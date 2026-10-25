import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import unittest.mock

import sonarch as pf

HAVE_GCC = shutil.which("gcc") is not None


def write(path, text=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


def desc(name, version, provides=()):
    s = f"%NAME%\n{name}\n\n%VERSION%\n{version}\n\n"
    if provides:
        s += "%PROVIDES%\n" + "\n".join(provides) + "\n\n"
    return s


class World:
    """A fake root + local db + sync db, built in a temp dir."""

    def __init__(self):
        self.tmp = tempfile.mkdtemp()
        self.root = os.path.join(self.tmp, "root")
        self.local = os.path.join(self.tmp, "local")
        self.sync_dir = os.path.join(self.tmp, "sync")
        os.makedirs(self.root)
        os.makedirs(self.local)
        os.makedirs(self.sync_dir)
        self._sync = []

    def local_pkg(self, name, ver, provides=(), files=()):
        d = os.path.join(self.local, f"{name}-{ver}")
        write(os.path.join(d, "desc"), desc(name, ver, provides))
        write(os.path.join(d, "files"), "%FILES%\n" + "\n".join(files) + "\n")

    def sync_pkg(self, name, ver, provides=()):
        self._sync.append((name, ver, provides))

    def finish_sync(self):
        with tarfile.open(os.path.join(self.sync_dir, "extra.db"), "w:gz") as tar:
            for name, ver, provides in self._sync:
                data = desc(name, ver, provides).encode()
                ti = tarfile.TarInfo(f"{name}-{ver}/desc")
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))

    def compile(self, rel, args, src="int f(void){return 1;}\n"):
        out = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        c = os.path.join(self.tmp, "x.c")
        write(c, src)
        subprocess.run(["gcc", "-fPIC", c, "-o", out, *args], check=True)
        return out

    def run(self, pending, **kw):
        self.finish_sync()
        return pf.analyze(
            pf.parse_local_db(self.local),
            pf.parse_sync_db(self.sync_dir),
            pf.parse_pending(pending),
            root=self.root,
            **kw,
        )


@unittest.skipUnless(HAVE_GCC, "gcc required")
class SonameTests(unittest.TestCase):
    def build(self, extra_local=None, new_provides=("libfoo.so=2-64",), old_provides=("libfoo.so=1-64",)):
        w = World()
        # libfoo v1 installed (soname libfoo.so.1)
        lib = w.compile("usr/lib/libfoo.so.1", ["-shared", "-Wl,-soname,libfoo.so.1"])
        libdir = os.path.dirname(lib)
        os.symlink("libfoo.so.1", os.path.join(libdir, "libfoo.so"))
        w.local_pkg("foo", "1.0-1", list(old_provides), ["usr/lib/libfoo.so.1"])
        w.sync_pkg("foo", "2.0-1", new_provides)
        # AUR plugin linked against libfoo.so.1, NO declared soname dependency
        w.compile("usr/lib/plugins/plug.so", ["-shared", f"-L{libdir}", "-Wl,--no-as-needed", "-lfoo"])
        w.local_pkg("plug-aur", "1.0-1", [], ["usr/lib/plugins/plug.so"])
        if extra_local:
            extra_local(w, libdir)
        return w

    PENDING = "foo 1.0-1 -> 2.0-1\n"

    def test_detects_breakage_for_foreign_package(self):
        rep = self.build().run(self.PENDING)
        self.assertEqual(len(rep.findings), 1)
        f = rep.findings[0]
        self.assertEqual((f.package, f.needed, f.bits), ("plug-aur", "libfoo.so.1", 64))
        self.assertEqual(f.lost_from, ["foo"])
        self.assertEqual(f.now_provided, ["libfoo.so.2"])

    def test_details_report_lost_and_unmatched(self):
        rep = self.build().run(self.PENDING)
        self.assertEqual(rep.lost, ["libfoo.so.1 [64-bit]"])
        self.assertEqual(rep.pending_count, 1)
        self.assertIn("libc.so.6", rep.unmatched)  # nothing in the fake world provides libc
        self.assertEqual(rep.unmatched["libc.so.6"]["packages"], {"plug-aur"})
        out = pf.render(rep, color=False, details=True)
        self.assertIn("libfoo.so.1 [64-bit]", out)
        self.assertIn("could NOT check", out)

    def test_detects_breakage_with_new_provide_format(self):
        rep = self.build(old_provides=("lib:libfoo.so.1",), new_provides=("lib:libfoo.so.2",)).run(self.PENDING)
        self.assertEqual(len(rep.findings), 1)
        self.assertEqual(rep.findings[0].needed, "libfoo.so.1")
        self.assertEqual(rep.findings[0].now_provided, ["libfoo.so.2"])

    def test_mixed_formats_old_to_new_is_not_a_break(self):
        rep = self.build(old_provides=("libfoo.so=1-64",), new_provides=("lib:libfoo.so.1",)).run(self.PENDING)
        self.assertEqual(rep.findings, [])

    # ---- file-based mode: works even when NOBODY declares any provides (the real-world case)
    def test_files_mode_detects_undeclared_library_break(self):
        w = self.build(old_provides=(), new_provides=())
        rep = w.run(self.PENDING, sync_files={"foo": ["usr/lib/libfoo.so.2", "usr/lib/libfoo.so"]})
        self.assertEqual(rep.source, "files")
        self.assertEqual([f.needed for f in rep.findings], ["libfoo.so.1"])
        self.assertEqual(rep.findings[0].now_provided, ["libfoo.so", "libfoo.so.2"])

    def test_provides_only_mode_is_blind_without_declarations(self):
        rep = self.build(old_provides=(), new_provides=()).run(self.PENDING)
        self.assertEqual(rep.findings, [])  # documents the limitation that files mode fixes
        self.assertEqual(rep.source, "provides")

    def test_files_mode_no_break_if_old_file_still_shipped(self):
        w = self.build(old_provides=(), new_provides=())
        rep = w.run(self.PENDING, sync_files={"foo": ["usr/lib/libfoo.so.1", "usr/lib/libfoo.so.2"]})
        self.assertEqual(rep.findings, [])

    def test_files_mode_other_package_may_ship_the_library(self):
        def add(w, libdir):
            w.local_pkg("foo-compat", "1.0-1", [], ["usr/lib/libfoo.so.1"])
        w = self.build(extra_local=add, old_provides=(), new_provides=())
        rep = w.run(self.PENDING, sync_files={"foo": ["usr/lib/libfoo.so.2"]})
        self.assertEqual(rep.findings, [])

    def test_files_mode_32bit_path_does_not_satisfy_64bit_need(self):
        w = self.build(old_provides=(), new_provides=())
        rep = w.run(self.PENDING, sync_files={"foo": ["usr/lib32/libfoo.so.1", "usr/lib/libfoo.so.2"]})
        self.assertEqual(len(rep.findings), 1)

    def test_files_mode_library_in_subdirectory_does_not_count(self):
        w = self.build(old_provides=(), new_provides=())
        rep = w.run(self.PENDING, sync_files={"foo": ["usr/lib/foo/libfoo.so.1", "usr/lib/libfoo.so.2"]})
        self.assertEqual(len(rep.findings), 1)

    def test_files_mode_missing_file_list_warns_and_does_not_guess(self):
        w = self.build(old_provides=(), new_provides=())
        rep = w.run(self.PENDING, sync_files={})
        self.assertEqual(rep.findings, [])
        self.assertTrue(any("no file list" in x for x in rep.warnings))

    def test_no_breakage_if_new_version_still_provides_old_soname(self):
        rep = self.build(new_provides=("libfoo.so=2-64", "libfoo.so=1-64")).run(self.PENDING)
        self.assertEqual(rep.findings, [])

    def test_no_breakage_if_compat_package_provides_old_soname(self):
        def add(w, libdir):
            w.local_pkg("foo1-compat", "1.0-1", ["libfoo.so=1-64"], [])
        rep = self.build(extra_local=add).run(self.PENDING)
        self.assertEqual(rep.findings, [])

    def test_32bit_provider_does_not_satisfy_64bit_need(self):
        rep = self.build(new_provides=("libfoo.so=2-64", "libfoo.so=1-32")).run(self.PENDING)
        self.assertEqual(len(rep.findings), 1)

    def test_library_shipped_by_same_package_is_ignored(self):
        def add(w, libdir):
            # package ships its own libfoo.so.1 alongside the plugin
            w.local_pkg("plug-aur", "1.0-1", [], ["usr/lib/plugins/plug.so", "usr/lib/libfoo.so.1"])
        rep = self.build(extra_local=add).run(self.PENDING)
        self.assertEqual(rep.findings, [])

    def test_official_packages_skipped_unless_all(self):
        def add(w, libdir):
            w.compile("usr/lib/official.so", ["-shared", f"-L{libdir}", "-Wl,--no-as-needed", "-lfoo"])
            w.local_pkg("official", "1.0-1", [], ["usr/lib/official.so"])
            w.sync_pkg("official", "1.0-1")
        w = self.build(extra_local=add)
        rep = w.run(self.PENDING)
        self.assertEqual([f.package for f in rep.findings], ["plug-aur"])
        w2 = self.build(extra_local=add)
        rep_all = w2.run(self.PENDING, scan_all=True)
        self.assertEqual(sorted(f.package for f in rep_all.findings), ["official", "plug-aur"])

    def test_stale_sync_db_warns(self):
        w = self.build()
        rep = w.run("foo 1.0-1 -> 3.0-1\n")
        self.assertTrue(any("stale" in x for x in rep.warnings))


class ParsingTests(unittest.TestCase):
    def test_parse_pending(self):
        text = "linux 6.1.1-1 -> 6.1.2-1\nffmpeg 1:7.0-1 -> 1:7.1-2\ngarbage\n"
        self.assertEqual(
            pf.parse_pending(text),
            {"linux": ("6.1.1-1", "6.1.2-1"), "ffmpeg": ("1:7.0-1", "1:7.1-2")},
        )

    def test_soname_files_filter(self):
        paths = ["usr/lib/libfoo.so.1", "usr/lib/libfoo.so", "usr/lib/libfoo.a", "usr/lib/foo/libx.so.1",
                 "usr/lib32/libfoo.so.2", "usr/bin/foo", "opt/app/libz.so.1", "usr/lib/ld-linux-x86-64.so.2"]
        self.assertEqual(
            sorted(pf.soname_files(paths)),
            sorted([("libfoo.so.1", 64), ("libfoo.so", 64), ("libfoo.so.2", 32), ("ld-linux-x86-64.so.2", 64)]),
        )

    def test_parse_files_db_reads_only_wanted_packages(self):
        d = tempfile.mkdtemp()
        with tarfile.open(os.path.join(d, "extra.files"), "w:gz") as tar:
            for name, body in {"foo-2.0-1/files": "%FILES%\nusr/\nusr/lib/libfoo.so.2\n",
                               "bar-1.0-3/files": "%FILES%\nusr/lib/libbar.so.1\n",
                               "my-dash-pkg-1.2-1/files": "%FILES%\nusr/lib/libd.so.1\n"}.items():
                data = body.encode()
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))
        got = pf.parse_files_db(d, {"foo", "my-dash-pkg"})
        self.assertEqual(sorted(got), ["foo", "my-dash-pkg"])
        self.assertIn("usr/lib/libfoo.so.2", got["foo"])

    def test_parse_pending_skips_ignored(self):
        text = "linux 6.1-1 -> 6.2-1\nnvidia 550-1 -> 555-1 [ignored]\n"
        self.assertEqual(pf.parse_pending(text), {"linux": ("6.1-1", "6.2-1")})

    def test_keys_old_and_new_formats(self):
        self.assertEqual(pf.provide_key("libavcodec.so=61-64"), ("libavcodec.so.61", 64))
        self.assertEqual(pf.provide_key("lib:libavcodec.so.61"), ("libavcodec.so.61", 64))
        self.assertEqual(pf.provide_key("lib32:libfoo.so.1"), ("libfoo.so.1", 32))
        self.assertEqual(pf.provide_key("lib:libnspr4.so"), ("libnspr4.so", 64))  # unversioned soname
        self.assertEqual(pf.provide_key("ld-linux-x86-64.so=2-64"), ("ld-linux-x86-64.so.2", 64))
        self.assertEqual(pf.provide_key("lib:ld-linux-x86-64.so.2"), ("ld-linux-x86-64.so.2", 64))
        self.assertIsNone(pf.provide_key("python=3.12"))
        self.assertIsNone(pf.provide_key("cmd:pacman"))
        self.assertIsNone(pf.provide_key("pc:libalpm"))
        self.assertEqual(pf.needed_key("libfoo.so.1", 64), ("libfoo.so.1", 64))
        self.assertEqual(pf.soname_stem("libfoo.so.1.2"), "libfoo.so")
        self.assertEqual(pf.soname_stem("libnspr4.so"), "libnspr4.so")

    @unittest.skipUnless(os.path.exists("/bin/ls"), "needs /bin/ls")
    def test_elf_reader_on_real_binary(self):
        res = pf.read_elf_needed(os.path.realpath("/bin/ls"))
        self.assertIsNotNone(res)
        bits, needed = res
        self.assertEqual(bits, 64)
        self.assertTrue(any(n.startswith("libc.so") for n in needed))

    def test_elf_reader_rejects_non_elf(self):
        with tempfile.NamedTemporaryFile() as t:
            t.write(b"hello world, definitely not an ELF file............................")
            t.flush()
            self.assertIsNone(pf.read_elf_needed(t.name))


class LiveRefreshTests(unittest.TestCase):
    """Test the glue code with stub `fakeroot` and `pacman` executables."""

    def test_live_refresh_with_stubs(self):
        tmp = tempfile.mkdtemp()
        bin_dir = os.path.join(tmp, "bin")
        os.makedirs(bin_dir)
        sysdb = os.path.join(tmp, "sysdb")
        os.makedirs(os.path.join(sysdb, "local"))
        os.makedirs(os.path.join(sysdb, "sync"))
        write(os.path.join(sysdb, "sync", "core.db"), "old")
        log = os.path.join(tmp, "calls.log")
        for name, body in {
            "fakeroot": 'shift\nexec "$@"\n',
            "pacman": f'echo "$@" >> {log}\n'
                      'case "$*" in *-Qu*) echo "foo 1.0-1 -> 2.0-1"; exit 0;; esac\nexit 0\n',
        }.items():
            path = os.path.join(bin_dir, name)
            write(path, "#!/bin/sh\n" + body)
            os.chmod(path, 0o755)
        old_path = os.environ["PATH"]
        os.environ["PATH"] = bin_dir + os.pathsep + old_path
        try:
            work = tempfile.mkdtemp()
            text, sync_dir = pf.live_refresh(work, pacman_dbpath=sysdb)
        finally:
            os.environ["PATH"] = old_path
        self.assertEqual(pf.parse_pending(text), {"foo": ("1.0-1", "2.0-1")})
        self.assertTrue(os.path.isfile(os.path.join(sync_dir, "core.db")))
        self.assertTrue(os.path.islink(os.path.join(work, "local")))
        with open(log) as fh:
            calls = fh.read()
        self.assertIn("-Sy --disable-sandbox-filesystem --dbpath " + work, calls)
        self.assertIn("-Fy --disable-sandbox-filesystem --dbpath " + work, calls)
        self.assertNotIn(sysdb, calls)  # never touches the real db path
        self.assertNotIn(sysdb, calls)

    def _stubs(self, pacman_body):
        tmp = tempfile.mkdtemp()
        bin_dir = os.path.join(tmp, "bin")
        sysdb = os.path.join(tmp, "sysdb")
        os.makedirs(bin_dir)
        os.makedirs(os.path.join(sysdb, "local"))
        os.makedirs(os.path.join(sysdb, "sync"))
        for name, body in {"fakeroot": 'shift\nexec "$@"\n', "pacman": pacman_body}.items():
            path = os.path.join(bin_dir, name)
            write(path, "#!/bin/sh\n" + body)
            os.chmod(path, 0o755)
        return bin_dir, sysdb

    def test_old_pacman_without_sandbox_option_falls_back(self):
        body = ('case "$*" in *--disable-sandbox-filesystem*) '
                'echo "error: invalid option \'--disable-sandbox-filesystem\'" >&2; exit 1;; esac\n'
                'case "$*" in *-Qu*) echo "foo 1.0-1 -> 2.0-1";; esac\nexit 0\n')
        bin_dir, sysdb = self._stubs(body)
        old_path = os.environ["PATH"]
        os.environ["PATH"] = bin_dir + os.pathsep + old_path
        try:
            text, _ = pf.live_refresh(tempfile.mkdtemp(), pacman_dbpath=sysdb)
        finally:
            os.environ["PATH"] = old_path
        self.assertEqual(pf.parse_pending(text), {"foo": ("1.0-1", "2.0-1")})

    def test_real_sync_failure_is_reported(self):
        bin_dir, sysdb = self._stubs('echo "error: failed to synchronize all databases" >&2\nexit 1\n')
        old_path = os.environ["PATH"]
        os.environ["PATH"] = bin_dir + os.pathsep + old_path
        try:
            with self.assertRaises(RuntimeError) as cm:
                pf.live_refresh(tempfile.mkdtemp(), pacman_dbpath=sysdb)
        finally:
            os.environ["PATH"] = old_path
        self.assertIn("failed to synchronize", str(cm.exception))

    def test_no_files_option_skips_files_db_and_cache_is_reused(self):
        body = ('echo "$@" >> ' + "{LOG}" + '\ncase "$*" in *-Qu*) echo "foo 1.0-1 -> 2.0-1";; esac\nexit 0\n')
        bin_dir, sysdb = self._stubs("true\n")
        log = os.path.join(os.path.dirname(bin_dir), "calls.log")
        write(os.path.join(bin_dir, "pacman"), "#!/bin/sh\n" + body.replace("{LOG}", log))
        os.chmod(os.path.join(bin_dir, "pacman"), 0o755)
        write(os.path.join(sysdb, "sync", "core.db"), "systemcopy")
        cache = tempfile.mkdtemp()
        old_path = os.environ["PATH"]
        os.environ["PATH"] = bin_dir + os.pathsep + old_path
        try:
            pf.live_refresh(cache, pacman_dbpath=sysdb, with_files=False)
            with open(os.path.join(cache, "sync", "core.db"), "w") as fh:
                fh.write("newer")                      # simulate a downloaded, newer db
            pf.live_refresh(cache, pacman_dbpath=sysdb, with_files=False)  # second run
        finally:
            os.environ["PATH"] = old_path
        with open(log) as fh:
            calls = fh.read()
        self.assertNotIn("-Fy", calls)
        with open(os.path.join(cache, "sync", "core.db")) as fh:
            self.assertEqual(fh.read(), "newer")       # not overwritten from the system copy

    def test_missing_tools_gives_clear_error(self):
        old_path = os.environ["PATH"]
        os.environ["PATH"] = tempfile.mkdtemp()
        try:
            with self.assertRaises(RuntimeError) as cm:
                pf.live_refresh(tempfile.mkdtemp())
        finally:
            os.environ["PATH"] = old_path
        self.assertIn("not found", str(cm.exception))


class CliTests(unittest.TestCase):
    def test_no_operation_is_an_error(self):
        with unittest.mock.patch("sys.stderr", new=io.StringIO()) as err:
            self.assertEqual(pf.main([]), 3)
        self.assertIn("-S", err.getvalue())

    def test_dash_S_runs_the_live_scan(self):
        with tempfile.TemporaryDirectory() as d, \
             unittest.mock.patch.object(pf, "live_refresh", return_value=("", d)) as live, \
             unittest.mock.patch("sys.stdout", new=io.StringIO()) as out, \
             unittest.mock.patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(pf.main(["-S"]), 0)
        live.assert_called_once()
        self.assertIn("No pending updates", out.getvalue())

    def test_long_option_is_equivalent(self):
        with tempfile.TemporaryDirectory() as d, \
             unittest.mock.patch.object(pf, "live_refresh", return_value=("", d)), \
             unittest.mock.patch("sys.stdout", new=io.StringIO()), \
             unittest.mock.patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(pf.main(["--scan"]), 0)


if __name__ == "__main__":
    unittest.main()
