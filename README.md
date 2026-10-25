# sonarch

Predict shared-library (soname) breakage **before** `pacman -Syu`.

pacman only protects packages that declare their library dependencies. AUR
builds, plugins and locally built binaries can silently break when a library's
soname changes. sonarch reads the pending upgrades, works out which sonames
will disappear, and scans the ELF files of your foreign (AUR) packages for
programs that still need them. It is read-only and never touches your system
database (it refreshes a private copy in `~/.cache/sonarch/db`).

## Usage

    sonarch -S              # scan pending upgrades
    sonarch -S --details    # also list vanishing libraries and unchecked ones
    sonarch -S --all        # scan official packages too
    sonarch -S --json       # machine-readable output

Exit codes: 0 = no breakage predicted, 1 = warnings only,
2 = breakage predicted, 3 = error.

## Install

    yay -S sonarch

Requires `python`, `pacman`, `fakeroot`.
