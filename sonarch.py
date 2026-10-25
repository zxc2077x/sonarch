#!/usr/bin/env python3
"""sonarch: predict shared-library breakage BEFORE `pacman -Syu`.

Idea: pacman only protects packages that *declare* their library
dependencies. Anything else (older AUR builds, plugins, locally built
binaries) can silently break when a library's soname changes.

This tool reads the pending upgrades, works out which sonames will stop
being provided, and scans the ELF files of your installed packages
(AUR/foreign by default) for programs that still need those sonames.

Read-only: it never modifies the system.

Usage: `sonarch -S` scans the pending upgrades (add --details for more).

Exit codes: 0 = no breakage predicted, 1 = warnings only,
            2 = breakage predicted,    3 = error.
"""
import argparse
import glob
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

__version__ = "0.1.0"

# ---------------------------------------------------------------- db parsing


def parse_desc(text: str) -> Dict[str, List[str]]:
    """Parse a pacman `desc` file into {SECTION: [lines]}."""
    out: Dict[str, List[str]] = {}
    key = None
    for line in text.splitlines():
        line = line.rstrip()
        if len(line) > 2 and line.startswith("%") and line.endswith("%"):
            key = line[1:-1]
            out[key] = []
        elif line and key:
            out[key].append(line)
    return out


@dataclass
class Pkg:
    name: str
    version: str
    provides: List[str]
    dbdir: Optional[str] = None  # local-db entry dir (lets us read `files` lazily)

    def files(self) -> List[str]:
        if not self.dbdir:
            return []
        path = os.path.join(self.dbdir, "files")
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                sections = parse_desc(fh.read())
        except OSError:
            return []
        return [f for f in sections.get("FILES", []) if not f.endswith("/")]


def _pkg_from_desc(desc: Dict[str, List[str]], dbdir: Optional[str]) -> Optional[Pkg]:
    if not desc.get("NAME") or not desc.get("VERSION"):
        return None
    return Pkg(desc["NAME"][0], desc["VERSION"][0], desc.get("PROVIDES", []), dbdir)


def parse_local_db(path: str) -> Dict[str, Pkg]:
    pkgs: Dict[str, Pkg] = {}
    for entry in os.scandir(path):
        desc_path = os.path.join(entry.path, "desc")
        if not entry.is_dir() or not os.path.isfile(desc_path):
            continue
        with open(desc_path, encoding="utf-8", errors="replace") as fh:
            pkg = _pkg_from_desc(parse_desc(fh.read()), entry.path)
        if pkg:
            pkgs[pkg.name] = pkg
    return pkgs


def _open_db_tar(path: str) -> tarfile.TarFile:
    try:
        return tarfile.open(path)
    except tarfile.ReadError:
        # newer repos may use zstd, which older Python tarfile cannot read
        data = subprocess.run(["zstd", "-dc", path], capture_output=True, check=True).stdout
        return tarfile.open(fileobj=io.BytesIO(data), mode="r:")


def parse_sync_db(path: str) -> Dict[str, Pkg]:
    pkgs: Dict[str, Pkg] = {}
    dbs = [os.path.join(path, f) for f in sorted(os.listdir(path)) if f.endswith(".db")]
    if not dbs:
        raise FileNotFoundError(f"no *.db files in {path}")
    for db in dbs:
        with _open_db_tar(db) as tar:
            for member in tar.getmembers():
                if not member.name.endswith("/desc"):
                    continue
                fh = tar.extractfile(member)
                if fh is None:
                    continue
                pkg = _pkg_from_desc(parse_desc(fh.read().decode("utf-8", "replace")), None)
                if pkg:
                    pkgs.setdefault(pkg.name, pkg)  # first repo wins, like pacman
    return pkgs


def parse_files_db(path: str, wanted: Set[str]) -> Dict[str, List[str]]:
    """Read file lists of the `wanted` packages from the *.files databases (pacman -F)."""
    result: Dict[str, List[str]] = {}
    for db in sorted(glob.glob(os.path.join(path, "*.files"))):
        with _open_db_tar(db) as tar:
            for member in tar:
                if not member.name.endswith("/files"):
                    continue
                name = member.name.rsplit("/", 1)[0].rsplit("-", 2)[0]
                if name not in wanted or name in result:
                    continue
                fh = tar.extractfile(member)
                if fh is not None:
                    result[name] = parse_desc(fh.read().decode("utf-8", "replace")).get("FILES", [])
    return result


# ------------------------------------------------------------------ sonames

# Two provide formats exist in the wild (see `man alpm-soname`):
#   v1 (older makepkg):  libfoo.so=1-64        -> soname libfoo.so.1, 64-bit
#   v2 (newer makepkg):  lib:libfoo.so.1       -> prefix "lib" = 64-bit, "lib32" = 32-bit
_V1_RE = re.compile(r"^(?P<lib>.+\.so)=(?P<ver>.+)-(?P<bits>32|64)$")
_V2_RE = re.compile(r"^(?P<prefix>[A-Za-z0-9_+.-]+):(?P<soname>[^\s:]+\.so(?:\..*)?)$")
_STEM_RE = re.compile(r"^(?P<stem>.+?\.so)(?:\..*)?$")

SonameKey = Tuple[str, int]  # ("libfoo.so.1", 64)


def provide_key(provide: str) -> Optional[SonameKey]:
    m = _V1_RE.match(provide)
    if m:
        return (f"{m['lib']}.{m['ver']}", int(m["bits"]))
    m = _V2_RE.match(provide)
    if m:
        return (m["soname"], 32 if m["prefix"] == "lib32" else 64)
    return None


def needed_key(needed: str, bits: int) -> SonameKey:
    return (needed, bits)


def soname_stem(soname: str) -> str:
    m = _STEM_RE.match(soname)
    return m["stem"] if m else soname


def soname_index(pkgs: Iterable[Pkg]) -> Dict[SonameKey, Set[str]]:
    index: Dict[SonameKey, Set[str]] = {}
    for pkg in pkgs:
        for prov in pkg.provides:
            key = provide_key(prov)
            if key:
                index.setdefault(key, set()).add(pkg.name)
    return index


_SOFILE_RE = re.compile(r"^[^/]+\.so(?:\..*)?$")


def soname_files(paths: Iterable[str]) -> Iterable[SonameKey]:
    """Library files that the dynamic linker finds by default (directly in usr/lib or usr/lib32)."""
    for path in paths:
        if path.startswith("usr/lib/"):
            bits, rest = 64, path[8:]
        elif path.startswith("usr/lib32/"):
            bits, rest = 32, path[10:]
        else:
            continue
        if "/" not in rest and _SOFILE_RE.match(rest):
            yield (rest, bits)


# ---------------------------------------------------------------------- ELF


def read_elf_needed(path: str) -> Optional[Tuple[int, List[str]]]:
    """Return (bits, [DT_NEEDED sonames]) for a little-endian ELF file, else None."""
    try:
        with open(path, "rb") as f:
            head = f.read(64)
            if len(head) < 52 or head[:4] != b"\x7fELF" or head[5] != 1:
                return None
            bits = {1: 32, 2: 64}.get(head[4])
            if bits is None:
                return None
            if bits == 64:
                (phoff,) = struct.unpack_from("<Q", head, 32)
                phentsize, phnum = struct.unpack_from("<HH", head, 54)
            else:
                (phoff,) = struct.unpack_from("<I", head, 28)
                phentsize, phnum = struct.unpack_from("<HH", head, 42)
            f.seek(phoff)
            ph = f.read(phentsize * phnum)
            loads, dyn = [], None
            for i in range(phnum):
                o = i * phentsize
                if bits == 64:
                    p_type, _fl, p_off, p_vaddr, _pa, p_filesz, _ms, _al = struct.unpack_from("<IIQQQQQQ", ph, o)
                else:
                    p_type, p_off, p_vaddr, _pa, p_filesz, _ms, _fl, _al = struct.unpack_from("<IIIIIIII", ph, o)
                if p_type == 1:
                    loads.append((p_vaddr, p_off, p_filesz))
                elif p_type == 2:
                    dyn = (p_off, p_filesz)
            if dyn is None:
                return bits, []
            f.seek(dyn[0])
            dd = f.read(dyn[1])
            ent = 16 if bits == 64 else 8
            needed_offs, strtab, strsz = [], None, 0
            for i in range(0, len(dd) - ent + 1, ent):
                tag, val = struct.unpack_from("<qQ" if bits == 64 else "<iI", dd, i)
                if tag == 0:
                    break
                if tag == 1:
                    needed_offs.append(val)
                elif tag == 5:
                    strtab = val
                elif tag == 10:
                    strsz = val
            if strtab is None or not needed_offs:
                return bits, []
            file_off = next((o + strtab - v for v, o, sz in loads if v <= strtab < v + sz), None)
            if file_off is None:
                return bits, []
            f.seek(file_off)
            blob = f.read(strsz or 65536)
            names = []
            for off in needed_offs:
                end = blob.find(b"\0", off)
                names.append(blob[off:end if end != -1 else None].decode("utf-8", "replace"))
            return bits, names
    except (OSError, struct.error):
        return None


# ----------------------------------------------------------------- analysis


@dataclass
class Finding:
    package: str
    file: str
    needed: str
    bits: int
    lost_from: List[str]       # pending packages that provided it before
    now_provided: List[str]    # other versions of the same lib available after


@dataclass
class Report:
    findings: List[Finding]
    lost_sonames: int
    elf_files: int
    needed_total: int
    needed_known: int          # NEEDED entries we could map to a provide
    warnings: List[str]
    lost: List[str] = field(default_factory=list)          # sonames that will disappear
    pending_count: int = 0
    unmatched: Dict[str, Dict] = field(default_factory=dict)  # needed -> {reason, packages}
    source: str = "provides"  # "files" = full file lists, "provides" = declared provides only


def analyze(
    installed: Dict[str, Pkg],
    sync: Dict[str, Pkg],
    pending: Dict[str, Tuple[str, str]],
    root: str = "/",
    scan_all: bool = False,
    elf_reader: Callable[[str], Optional[Tuple[int, List[str]]]] = read_elf_needed,
    sync_files: Optional[Dict[str, List[str]]] = None,
) -> Report:
    warnings: List[str] = []
    for name, (_old, new) in pending.items():
        if name not in sync:
            warnings.append(f"{name}: pending update not found in sync db")
        elif sync[name].version != new:
            warnings.append(f"{name}: sync db has {sync[name].version} but update list says {new} (stale sync db?)")

    before = soname_index(installed.values())
    after_pkgs = [p for n, p in installed.items() if n not in pending]
    after_pkgs += [sync[n] for n in pending if n in sync]
    after = soname_index(after_pkgs)

    if sync_files is not None:
        # Compare the real library FILES before/after (not only what maintainers declared).
        no_list = [n for n in pending if n not in sync_files]
        if no_list:
            warnings.append(f"{len(no_list)} updated package(s) have no file list in the files "
                            f"database ({', '.join(sorted(no_list)[:3])}...); their libraries may be missed")
        for name, pkg in installed.items():
            if name in pending and name not in sync_files:
                continue  # unknown new contents: do not guess
            for key in soname_files(pkg.files()):
                before.setdefault(key, set()).add(name)
                if name not in pending:
                    after.setdefault(key, set()).add(name)
        for name, files in sync_files.items():
            if name in pending:
                for key in soname_files(files):
                    after.setdefault(key, set()).add(name)

    lost = {k: v for k, v in before.items() if k not in after}

    targets = [
        n for n in installed
        if n not in pending and (scan_all or n not in sync)
    ]

    findings: List[Finding] = []
    elf_files = needed_total = needed_known = 0
    seen: Set[Tuple[str, str, int]] = set()
    unmatched: Dict[str, Dict] = {}

    def note_unmatched(needed: str, reason: str, pkg_name: str) -> None:
        entry = unmatched.setdefault(needed, {"reason": reason, "packages": set()})
        entry["packages"].add(pkg_name)

    for name in targets:
        pkg = installed[name]
        files = pkg.files()
        own = {os.path.basename(f) for f in files}
        for rel in files:
            full = os.path.join(root, rel)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            elf = elf_reader(full)
            if elf is None:
                continue
            bits, needed_list = elf
            elf_files += 1
            for needed in needed_list:
                needed_total += 1
                if needed in own:
                    needed_known += 1  # shipped by the package itself
                    continue
                key = needed_key(needed, bits)
                if key in before or key in after:
                    needed_known += 1
                else:
                    note_unmatched(needed, "no installed package declares it", name)
                if key in lost and (name, needed, bits) not in seen:
                    seen.add((name, needed, bits))
                    stem = soname_stem(needed)
                    alternatives = sorted(
                        s_ for (s_, b) in after if b == bits and soname_stem(s_) == stem
                    )
                    findings.append(Finding(name, rel, needed, bits, sorted(lost[key]), alternatives))

    findings.sort(key=lambda f: (f.package, f.needed))
    lost_names = sorted(f"{soname} [{b}-bit]" for (soname, b) in lost)
    return Report(findings, len(lost), elf_files, needed_total, needed_known, warnings,
                  lost=lost_names, pending_count=len(pending), unmatched=unmatched,
                  source="files" if sync_files is not None else "provides")


# -------------------------------------------------------------- system glue

_PENDING_RE = re.compile(r"^(\S+)\s+(\S+)\s+->\s+(\S+)(\s+\[.*\])?\s*$")


def parse_pending(text: str) -> Dict[str, Tuple[str, str]]:
    out = {}
    for line in text.splitlines():
        m = _PENDING_RE.match(line.strip())
        if m and not (m[4] and "ignored" in m[4]):
            out[m[1]] = (m[2], m[3])
    return out


def _run_pacman(op: str, base: List[str]) -> Tuple[bool, str]:
    """Run `fakeroot pacman <op>`. pacman >= 7.1 needs --disable-sandbox-filesystem under
    fakeroot (checkupdates does the same); older pacman does not know it, so retry without."""
    msg = ""
    for extra in (["--disable-sandbox-filesystem"], []):
        res = subprocess.run(["fakeroot", "--", "pacman", op, *extra, *base],
                             capture_output=True, text=True)
        if res.returncode == 0:
            return True, ""
        msg = (res.stderr + res.stdout).strip()
        if extra and ("invalid option" in msg or "unrecognized option" in msg):
            continue
        break
    return False, msg


def live_refresh(cache_dir: str, pacman_dbpath: str = "/var/lib/pacman",
                 with_files: bool = True) -> Tuple[str, str]:
    """Refresh a private COPY of the sync databases in `cache_dir`; list pending upgrades.

    The real system database is never touched. The cache is kept between runs, so only
    changed databases are downloaded. Returns (pending_upgrades_text, sync_db_dir).
    """
    for tool in ("fakeroot", "pacman"):
        if not shutil.which(tool):
            raise RuntimeError(f"`{tool}` not found (install it: sudo pacman -S --needed base-devel)")
    sync_dir = os.path.join(cache_dir, "sync")
    os.makedirs(sync_dir, exist_ok=True)
    link = os.path.join(cache_dir, "local")
    if not os.path.lexists(link):
        os.symlink(os.path.join(pacman_dbpath, "local"), link)
    if not glob.glob(os.path.join(sync_dir, "*.db")):  # first run: start from the system copies
        for db in glob.glob(os.path.join(pacman_dbpath, "sync", "*.db")) + \
                glob.glob(os.path.join(pacman_dbpath, "sync", "*.files")):
            shutil.copy2(db, sync_dir)
    base = ["--dbpath", cache_dir, "--logfile", "/dev/null"]
    ok, msg = _run_pacman("-Sy", base)
    if not ok:
        raise RuntimeError(f"could not refresh temporary database: {msg}")
    if with_files:
        ok, msg = _run_pacman("-Fy", base)
        if not ok:
            print(f"warning: could not refresh the files database ({msg})", file=sys.stderr)
    qu = subprocess.run(["pacman", "-Qu", *base], capture_output=True, text=True)
    if qu.returncode not in (0, 1):  # 1 = nothing to upgrade
        raise RuntimeError(f"pacman -Qu failed: {qu.stderr.strip()}")
    return qu.stdout, sync_dir


# ------------------------------------------------------------------- output


def render(report: Report, color: bool, details: bool = False) -> str:
    def c(code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if color else s

    lines = []
    if not report.findings:
        lines.append(c("32", "OK: no soname breakage predicted for the scanned packages."))
    else:
        lines.append(c("31;1", f"BREAKAGE PREDICTED in {len({f.package for f in report.findings})} package(s):"))
        by_pkg: Dict[str, List[Finding]] = {}
        for f in report.findings:
            by_pkg.setdefault(f.package, []).append(f)
        for pkg, items in by_pkg.items():
            lines.append(f"  {c('1', pkg)}")
            for f in items:
                alt = f" (after update only: {', '.join(f.now_provided)})" if f.now_provided else " (no replacement provided)"
                lines.append(f"    needs {f.needed} [{f.bits}-bit] -> dropped by {', '.join(f.lost_from)}{alt}")
                lines.append(f"      in {f.file}")
        lines.append("")
        lines.append("Suggestion: rebuild/update these packages (or wait) before upgrading.")
    cov = (100 * report.needed_known / report.needed_total) if report.needed_total else 100.0
    lines.append(
        c("2", f"scanned {report.elf_files} ELF files; "
               f"{cov:.0f}% of library references could be matched to a known provider.")
    )
    lines.append(c("2", "library data: full file lists" if report.source == "files"
                   else "library data: declared provides only (LIMITED coverage)"))
    lines.append(
        c("2", f"{report.pending_count} package(s) will be updated; "
               f"{report.lost_sonames} library version(s) will disappear.")
    )
    if details:
        if report.lost:
            lines.append("\nLibrary versions that will disappear:")
            lines.extend(f"  - {x}" for x in report.lost[:40])
            if len(report.lost) > 40:
                lines.append(f"  ... and {len(report.lost) - 40} more")
        if report.unmatched:
            lines.append("\nLibraries we could NOT check (most used first):")
            ranked = sorted(report.unmatched.items(), key=lambda kv: (-len(kv[1]["packages"]), kv[0]))
            for needed, info in ranked[:25]:
                pk = sorted(info["packages"])
                shown = ", ".join(pk[:3]) + (f" +{len(pk) - 3} more" if len(pk) > 3 else "")
                lines.append(f"  {needed}  [{info['reason']}]  used by: {shown}")
    for w in report.warnings:
        lines.append(c("33", f"warning: {w}"))
    return "\n".join(lines)


def to_json(report: Report) -> str:
    return json.dumps(
        {
            "findings": [f.__dict__ for f in report.findings],
            "lost_sonames": report.lost_sonames,
            "elf_files": report.elf_files,
            "needed_total": report.needed_total,
            "needed_known": report.needed_known,
            "warnings": report.warnings,
            "pending_count": report.pending_count,
            "lost": report.lost,
            "unmatched": {k: {"reason": v["reason"], "packages": sorted(v["packages"])}
                          for k, v in report.unmatched.items()},
        },
        indent=2,
    )


# --------------------------------------------------------------------- main


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="sonarch", description=__doc__.split("\n\n")[0])
    ap.add_argument("-S", "--scan", action="store_true",
                    help="scan pending upgrades for predicted soname breakage")
    ap.add_argument("--pending", help="offline mode: file with `pacman -Qu` output (needs --sync-db)")
    ap.add_argument("--local-db", default="/var/lib/pacman/local")
    ap.add_argument("--sync-db", default=None, help="offline mode: dir with the sync *.db / *.files files")
    ap.add_argument("--root", default="/", help="filesystem root for installed files")
    ap.add_argument("--all", action="store_true", help="scan official packages too, not only foreign/AUR")
    ap.add_argument("--no-files", action="store_true",
                    help="skip the files database (faster, much weaker: declared provides only)")
    ap.add_argument("--details", action="store_true",
                    help="also list vanishing library versions and libraries we could not check")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    if not (args.scan or args.pending):  # like pacman: an operation is required
        print("error: no operation specified (use -S to scan, -h for help)", file=sys.stderr)
        return 3

    try:
        if args.pending:
            if not args.sync_db:
                raise RuntimeError("--pending needs --sync-db (offline mode)")
            with open(args.pending, encoding="utf-8") as fh:
                text = fh.read()
            sync_dir = args.sync_db
        else:
            cache = os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"),
                                 "sonarch", "db")
            print(f"Refreshing package databases (cached in {cache})...", file=sys.stderr)
            text, sync_dir = live_refresh(cache, with_files=not args.no_files)
        pending = parse_pending(text)
        if not pending:
            print("No pending updates.")
            return 0
        installed = parse_local_db(args.local_db)
        sync = parse_sync_db(sync_dir)
        sync_files = None
        notes: List[str] = []
        if not args.no_files:
            if glob.glob(os.path.join(sync_dir, "*.files")):
                sync_files = parse_files_db(sync_dir, set(pending))
            else:
                notes.append("files databases not found: only declared library provides were "
                             "checked (limited coverage)")
        report = analyze(installed, sync, pending, root=args.root, scan_all=args.all,
                         sync_files=sync_files)
        report.warnings.extend(notes)
    except (RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    if args.json:
        print(to_json(report))
    else:
        print(render(report, color=sys.stdout.isatty() and not args.no_color, details=args.details))
    if report.findings:
        return 2
    return 1 if report.warnings else 0


if __name__ == "__main__":
    sys.exit(main())
