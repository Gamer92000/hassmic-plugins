#!/bin/sh
# SITE (built and signed) published as the branch gh-pages of REMOTE, unless it is what PREVIOUS (the site as it is
# published, tools/published.sh) has already: a publish of a commit run again with nothing new pushes nothing.  The branch is one commit, forced: its history is not the record,
# the serials are.
# Only the newest commit publishes, and only over the site it was built on (a review of 01e80b8: a late run of an
# older commit put its older tree over a newer one's site):
#   - BRANCH (refs/heads/main) of REMOTE has to be COMMIT, this run's, when it pushes; else nothing is pushed, and
#     it says so (a newer commit's run publishes its own site);
#   - the push replaces gh-pages only where it is still the commit PREVIOUS was read from (PREVIOUS.ref,
#     --force-with-lease; "none": only where there is no gh-pages yet): a publish that came in between, of another
#     run or job, is never overwritten; this one fails, and a run again builds on what is there.
#   publish.sh SITE PREVIOUS REMOTE BRANCH COMMIT
set -e
[ $# = 5 ] || { echo "usage: publish.sh SITE PREVIOUS REMOTE BRANCH COMMIT" >&2; exit 2; }
site=$1 previous=$2 remote=$3 branch=$4 commit=$5
read -r read_from < "$previous.ref" || { echo "::error::$previous.ref: which published commit the site was built on is not known" >&2; exit 1; }
case $read_from in none|[0-9a-f]*) ;; *) echo "::error::$previous.ref: no commit" >&2; exit 1;; esac
if cmp -s "$site/index.json" "$previous/index.json" && cmp -s "$site/revoked.json" "$previous/revoked.json" \
        && cmp -s "$site/index.html" "$previous/index.html"; then
    echo "publish.sh: the published site is this one already: nothing pushed"
    exit 0
fi
cd "$site"
touch .nojekyll
git init -q -b gh-pages
git add -A
git -c user.name=index -c user.email=index@users.noreply.github.com commit -q -m "index of $commit"
# (asked as late as can be: the lease covers what comes between this and the push)
head=$(git ls-remote "$remote" "$branch") || { echo "::error::could not ask for $branch" >&2; exit 1; }
head=${head%%[[:space:]]*}
if [ "$head" != "$commit" ]; then
    echo "publish.sh: $branch is at ${head:-nothing} now, not at this run's commit $commit: a newer commit's run publishes; nothing pushed"
    exit 0
fi
[ "$read_from" = none ] && lease=refs/heads/gh-pages: || lease=refs/heads/gh-pages:$read_from
git push -q --force-with-lease="$lease" "$remote" gh-pages:refs/heads/gh-pages || {
    echo "::error::gh-pages is no longer the site this one was built on ($read_from): published meanwhile; nothing pushed (run it again)" >&2
    exit 1
}
echo "publish.sh: published"
