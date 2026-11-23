#!/bin/sh
# GitHub's CLI for index.yml's jobs: the one gh that verifies the attestations (tools/attest.py), its release
# downloaded and checked by its SHA-256 here, never the runner image's gh, which GitHub raises when it likes.  What
# attest.py takes as gh's verdicts (VERDICTS) are the words of this version, and the tests' recorded answer
# (tests/gh-verify-cli.json) is its: a new gh is a new VERSION and SHA256 here, its words read again first
# (tests/test_workflow.py holds VERSION to the one attest.py names).  The hash is of cli/cli's own release asset
# gh_<VERSION>_linux_amd64.tar.gz (the same as its gh_<VERSION>_checksums.txt; its attestation by cli/cli's
# workflow verified when it was entered).
#
#   sh tools/gh.sh DIR     unpacks into DIR and prints the path of its gh (for INDEX_GH)
#
# GH_URL: where to download it from instead (the tests, a file:// address): the SHA-256 holds all the same.
set -eu
VERSION=2.105.0
SHA256=79e7ab5db738c48777b696e374f8b428f0647debfb424f44d2f426370407fe2f
[ $# = 1 ] || { echo "usage: sh tools/gh.sh DIR" >&2; exit 2; }
dir=$1
name=gh_${VERSION}_linux_amd64
url=${GH_URL:-https://github.com/cli/cli/releases/download/v$VERSION/$name.tar.gz}
mkdir -p "$dir"
curl -sSfL --proto '=https,file' -o "$dir/$name.tar.gz" "$url"
# (sha256sum -c: a file that is not that one ends the job here, before anything of it is unpacked)
echo "$SHA256  $dir/$name.tar.gz" | sha256sum -c --quiet - >&2 ||
    { echo "::error::$url is not gh $VERSION's release (its SHA-256 is not $SHA256)" >&2; rm -f "$dir/$name.tar.gz"; exit 1; }
tar -xzf "$dir/$name.tar.gz" -C "$dir"
"$dir/$name/bin/gh" --version | head -1 | grep -q "^gh version $VERSION " ||
    { echo "::error::$dir/$name/bin/gh does not say it is gh $VERSION" >&2; exit 1; }
echo "$dir/$name/bin/gh"
