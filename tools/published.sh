#!/bin/sh
# The site as it is published (the branch gh-pages of this repository's origin) into DIR, for --previous / PREVIOUS:
# every job of the index's CI reads it (only versions the site does not have are built; serials only grow against
# it).  Read anonymously: no token is needed, none is used.  No such branch (ls-remote's 2): nothing published yet,
# an empty folder.  Anything else that fails is an error: with an empty folder the serials would be checked against
# nothing.  What is read is checked by index.py (published(): the index key's signatures), never run.
# DIR.ref: the published branch's commit that was read ("none": no branch), which tools/publish.sh pushes against
# (--force-with-lease): a site built on this one never replaces another published meanwhile.
#   published.sh DIR
set -e
[ $# = 1 ] || { echo "usage: published.sh DIR" >&2; exit 2; }
dir=$1
mkdir -p "$dir"
r=0; git ls-remote --exit-code --heads origin gh-pages >/dev/null || r=$?
if [ $r = 0 ]; then
    git fetch --quiet --depth 1 origin gh-pages
    git rev-parse FETCH_HEAD > "$dir.ref"
    git archive -o "$dir.tar" FETCH_HEAD
    tar -xf "$dir.tar" -C "$dir"
    rm -f "$dir.tar"
    echo "published.sh: the published site in $dir (gh-pages at $(cat "$dir.ref"))"
elif [ $r = 2 ]; then
    echo none > "$dir.ref"
    echo "published.sh: nothing published yet"
else
    echo "::error::could not ask for the published branch" >&2
    exit 1
fi
