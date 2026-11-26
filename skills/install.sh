#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Install the sahinit skill from a checkout: copies skills/sahinit/SKILL.md
# to ${1:-$HOME/.claude/skills}/sahinit/SKILL.md and prints the file it
# wrote. It overwrites only that file and leaves any other file there alone.
# Without a checkout, use the copy inside the binary:
# sahinit --skill > ~/.claude/skills/sahinit/SKILL.md
#
# Threats: writing through a symlink or a hard link planted at the target
# (the skills directory, sahinit/, or the file) into some other place, and a
# relative target resolved against the wrong directory. The target is made
# absolute before anything else and the script never changes directory; a
# symlink anywhere at the target, a file with more than one hard link, or a
# directory where the file goes is refused before anything is written. It
# does not guard against another process changing the target while it runs.
# It copies only this file and runs nothing else.
set -euo pipefail

usage() {
    echo "usage: skills/install.sh [skills-dir]" >&2
    exit 2
}
[[ $# -le 1 ]] || usage
src="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/sahinit/SKILL.md"
dest="${1-$HOME/.claude/skills}"
[[ -n "$dest" && "$dest" != -* ]] || usage
if [[ "$dest" != /* ]]; then
    dest="$PWD/$dest"
fi

refuse() {
    echo "install: $1" >&2
    exit 1
}

for d in "$dest" "$dest/sahinit"; do
    if [[ -L "$d" ]]; then refuse "$d is a symlink; refusing to follow it"; fi
    if [[ -e "$d" && ! -d "$d" ]]; then refuse "$d is not a directory"; fi
done
out="$dest/sahinit/SKILL.md"
if [[ -L "$out" ]]; then refuse "$out is a symlink; refusing to follow it"; fi
if [[ -d "$out" ]]; then refuse "$out is a directory"; fi
if [[ -e "$out" && -n "$(find "$out" -prune -links +1)" ]]; then
    refuse "$out has more than one hard link; refusing to write through it"
fi
mkdir -p -- "$dest/sahinit"
cp -- "$src" "$out"
echo "wrote $out"
