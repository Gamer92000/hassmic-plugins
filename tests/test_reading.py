#!/usr/bin/env python3
"""The maintainer's reading list for a plugin's release workflow (README.md "Where a package comes from": what may
not go into a package from outside the commit the entry names) is written in eight places, in the same words: here
README.md and tools/attest.py; hassmic's docs/plugins.md 5.3 and docs/SECURITY.md (HASSMIC, else ../echo-dot-assist);
the template's README.md and .github/workflows/release.yml (TEMPLATE, else ../hassmic-plugin-template); and
microWakeWord's (MWW, else ../hassmic-plugin-microwakeword).  Each copy, read without its line breaks and comment
marks, is this README's sentence, word for word: an item added in one place and not the others is what a plugin's
author reads one way and the maintainer another (a review of 17c2e8c, whose list gained four items in all eight by
hand).  The README's own copy names those items, so that the list never shrinks unseen either.  A sibling tree not
there is said, and skipped; with --require it fails (index.yml's siblings job checks the three repositories out
beside this one, those files alone, and runs it so: a skip there was a check that never ran, a review of dc75e14; a
job no other needs, a review of 810b9e9: a sibling's branch never holds back a publish)."""
import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
UP = os.path.dirname(ROOT)
REQUIRE = "--require" in sys.argv[1:]
START, END = "Nothing of what goes into the package may come from outside that commit:", "has to make the same bytes."
failed = False


def check(cond, what):
    global failed
    print(("ok   " if cond else "FAIL ") + what)
    failed |= not cond


def sentence(path):
    """the reading list in PATH, its lines joined (leading blanks and "#" comment marks off, blanks as one), or None"""
    text = " ".join(re.sub(r"^\s*(#+\s?)?", "", l) for l in open(path, encoding="utf-8").read().splitlines())
    text = re.sub(r"\s+", " ", text)
    a = text.find(START)
    b = text.find(END, a)
    if a < 0 or b < 0:
        return None
    if text.find(START, a + 1) >= 0:
        return "(twice)"
    return text[a:b + len(END)]


canon = sentence(os.path.join(ROOT, "README.md"))
check(canon is not None and canon != "(twice)", "README.md has the reading list, once")
for item in ("no action (`uses:`) not pinned by a commit of the action's own repository", "impostor commit",
             "all the way down (a composite action's own steps", "Dockerfile's `FROM`",
             "no other job names an environment", "no artifact of another job or run", "`needs.*.outputs`", "`github.event.*`", "a ref that moves",
             "`docker://`", "no cache", "no `vars`", "no release asset", "`rust-toolchain.toml`", "not pinned by its hash",
             "a re-run of an old run"):
    check(canon is not None and item in canon, f"the list names {item}")
places = [(ROOT, "this tree", ["tools/attest.py"])]
for env, name, files in (("HASSMIC", "echo-dot-assist", ["docs/plugins.md", "docs/SECURITY.md"]),
                         ("TEMPLATE", "hassmic-plugin-template", ["README.md", ".github/workflows/release.yml"]),
                         ("MWW", "hassmic-plugin-microwakeword", ["README.md", ".github/workflows/release.yml"])):
    places.append((os.environ.get(env) or os.path.join(UP, name), f"{name} ({env})", files))
for tree, name, files in places:
    if not all(os.path.isfile(os.path.join(tree, f)) for f in files) and (not os.path.isdir(tree) or not REQUIRE):
        if REQUIRE:
            check(False, f"{name}: not at {tree} (--require: its copies of the reading list have to be checked)")
        else:
            print(f"skip {name}: not at {tree} (its copies of the reading list are not checked here)")
        continue
    for f in files:
        # (--require, the tree there without the file: the branch checked out does not have it, which index.yml's
        # sparse checkout lets pass; said as that, never as a tree not there, and the tree's other copies checked:
        # echo-dot-assist's main before the plugin work was pushed had docs/SECURITY.md and no docs/plugins.md)
        if not os.path.isfile(os.path.join(tree, f)):
            check(False, f"{name} {f}: not in {tree}, which is there: the branch checked out does not have this file "
                         "(not pushed there yet, or moved; --require: its copy of the reading list has to be checked)")
            continue
        got = sentence(os.path.join(tree, f))
        if got is not None and canon is not None and got != canon:
            i = next((i for i, (x, y) in enumerate(zip(got, canon)) if x != y), min(len(got), len(canon)))
            said = f": from \"...{got[max(0, i - 30):i + 50]}\" against \"...{canon[max(0, i - 30):i + 50]}\""
        else:
            said = "" if got == canon else ": not there" if got is None else ": twice"
        check(got == canon, f"{name} {f}: the reading list in README.md's words{said}")
print("reading: " + ("FAILED" if failed else "all passed"))
sys.exit(1 if failed else 0)
