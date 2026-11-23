#!/bin/sh
# The package tool and the signatures are hassmic's (its sdk/plugcheck.py and scripts/otatool.py), and so are the
# sandbox's table of system calls and its reader (sdk/filter.def, tools/mkfilter.py: the harness judges a community
# plugin's calls by them), copied in so that this repository checks packages by itself: sync.sh [HASSMIC] takes them
# from a hassmic tree, sync.sh --check [HASSMIC] says where they differ.  (hassmic's release key is not among them: what makes a package listed, and
# official, is this index's own key, keys/index.pub, a copy of which every hassmic build carries as keys/plugins.pub)
set -e
cd "$(dirname "$0")/.."
check=; [ "$1" = --check ] && { check=1; shift; }
H=${1:-../echo-dot-assist}
[ -f "$H/sdk/plugcheck.py" ] || { echo "sync: no hassmic tree at $H (give its path)" >&2; exit 1; }
bad=0
for pair in sdk/plugcheck.py:tools/plugcheck.py scripts/otatool.py:tools/otatool.py sdk/filter.def:tools/filter.def tools/mkfilter.py:tools/mkfilter.py; do
    from=${pair%%:*}; to=${pair#*:}
    if [ -n "$check" ]; then
        cmp -s "$H/$from" "$to" || { echo "differs: $to (hassmic: $from)"; bad=1; }
    else
        cp "$H/$from" "$to"
    fi
done
[ -n "$check" ] && { [ $bad = 0 ] && echo "sync: as hassmic's tree at $H"; exit $bad; }
commit=$(git -C "$H" rev-parse HEAD 2>/dev/null || echo unknown)
[ -z "$(git -C "$H" status --porcelain -- sdk/plugcheck.py scripts/otatool.py sdk/filter.def tools/mkfilter.py 2>/dev/null)" ] || commit="$commit with changes not committed there"
echo "hassmic $commit" > tools/VERSION
cat tools/VERSION
