#!/usr/bin/env python3
"""tools/workflow.py's skim() and metadata() against PyYAML: random action.yml files made of the pieces real actions
are written with and of the ones that could make a line belong to another key than it seems to (a quoted text, a
block text or a flow collection over lines with a `runs:` inside, a document marker, an item in a flow collection
that opens with ?, &, ! or * before a quote: a review of 5a3035d), each read by both.  Where both read a file, the
same top-level keys, the same runs.using and the same steps' uses; where skim reads one PyYAML must too.  A refusal
by skim is never a failure (it is stricter than YAML, and says so).  PyYAML is not Python's own: without it, said and
skipped.  SEED and COUNT: python3 tests/test_skim_fuzz.py [seed] [count] (make check: seed 1, 3000 files)."""
import os, random, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tools"))
import workflow
try:
    import yaml
except ImportError:
    print("skip skim fuzz: no PyYAML (pip install pyyaml)")
    sys.exit(0)

R = random.Random(int(sys.argv[1]) if len(sys.argv) > 1 else 1)
N = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
EVIL = "runs:\n  using: composite\n  steps:\n    - uses: evil/x@" + "e" * 40
GOOD = "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@" + "a" * 40 + "\n    - run: echo hi"
NODE = "runs:\n  using: node20\n  main: x.js"


def ind(t, k):
    return "\n".join((" " * k + x) if x else x for x in t.split("\n"))


def piece():
    k = R.choice([0, 1, 2, 4])
    c = R.randrange(32)
    q = R.choice(["'", '"'])
    if c == 0: return f"name: {R.choice(['x', 'a b', 'it' + chr(39) + 's', chr(34) + 'q' + chr(34), '[a, b]', 'x # c'])}"
    if c == 1: return f"description: {q}foo\n{ind(EVIL, k)}\n{' ' * k}x{q}"
    if c == 2: return f"description: |\n{ind(EVIL, k)}"
    if c == 3: return f"description: >-\n  a\n{ind(EVIL, k)}"
    if c == 4: return f"inputs:\n  x:\n    description: {q}foo\n{ind(EVIL, k)}{q}\n    required: false"
    if c == 5: return f"description:\n  {q}multi\n{' ' * k}line{q}"
    if c == 6: return "inputs:\n  x:\n    default: [a, 'b, c', \"d]\"]"
    if c == 7: return f"description: plain\n{ind('continued', k)}"
    if c == 8: return "branding:\n  icon: x\n  color: y"
    if c == 9: return f"# comment\n{ind('# runs:', k)}"
    if c == 10: return f"description: {q}a{q * 2}b{q}"
    if c == 11: return f"description: \"a\\\"\n{ind('runs: x', k)}\""
    if c == 12: return "outputs:\n  o:\n    value: ${{ steps.x.outputs.y }}"
    if c == 13: return f"description: {q}x{q} # c"
    if c == 14: return "inputs:\n  - |\n" + ind(EVIL, k)
    if c == 15: return f"author: a\n{ind('- b', k)}"
    if c == 16: return "description: >\n" + ind("x\n\n#y", k)
    if c == 17: return f"runs:\n  using: docker\n  image: {R.choice(['Dockerfile', 'docker://a@sha256:' + 'b' * 64])}"
    if c == 18: return "inputs:\n  x:\n    description: 'a\n\n      b'"
    if c == 19: return "description: [a,\n" + ind("b]", k)
    if c == 20: return "description: x:y"
    # (a review of 5a3035d: an item of a flow collection that opens with ?, an anchor, a tag or an alias, a quote after
    # it, a `runs:` on the lines the quote would take in)
    if c in (21, 22, 23, 24):
        lead = {21: "? ", 22: "&a ", 23: "!!str ", 24: R.choice(["*a ", "? &a "])}[c]
        return f"description: [{lead}{q}a]#\n{ind(EVIL, k)}\n{q}]"
    if c in (29, 30, 31):
        # (the quote closed on a line under a later key, which YAML reads as inside it: no `runs:` at the top)
        lead = {29: "? ", 30: "&a ", 31: "!!str "}[c]
        return f"description: [{lead}{q}a]#\n{NODE}\ninputs:\n  a:\n    {q}] #{q}"
    if c == 25: return f"description: {{{q}k{q}:{q}v, ]}}{q}}}"
    if c == 26: return f"description: [x, ? {q}y{q}]"
    if c == 27: return "---"
    if c == 28: return "--- # a marker"
    return f"description: {q}{q}"


agree = refused = 0
bad = []
for i in range(N):
    parts = [piece() for _ in range(R.randrange(1, 5))]
    parts.insert(R.randrange(len(parts) + 1), R.choice([GOOD, NODE, EVIL]))
    if R.random() < 0.15:
        parts.insert(0, R.choice(["---", "--- # x", "# c\n---"]))
    text = "\n".join(parts) + "\n"
    try:
        docs = list(yaml.safe_load_all(text))
        y = docs[0] if len(docs) == 1 else "ERR"         # (a second document: GitHub's runner reads the first alone)
    except Exception:
        y = "ERR"
    try:
        keys = workflow.skim(text)
        runs, found = workflow.metadata(text)
        ours = (sorted(keys), runs.get("using"), [u for _, _, u in found])
    except ValueError:
        refused += 1
        continue
    if not isinstance(y, dict):
        bad.append(("skim reads it, PyYAML does not (or reads more than one document)", text))
        continue
    yr = y.get("runs") if isinstance(y.get("runs"), dict) else {}
    theirs = (sorted(str(k) for k in y), yr.get("using"), [s.get("uses") for s in (yr.get("steps") or []) if isinstance(s, dict) and "uses" in s])
    if ours != theirs:
        bad.append((f"differ: {ours} against {theirs}", text))
    else:
        agree += 1
for why, t in bad[:4]:
    print("----", why)
    print(t)
print(("ok   " if not bad else "FAIL ") + f"skim fuzz: {N} files, {agree} read alike by both, {refused} refused by skim, {len(bad)} read otherwise")
sys.exit(1 if bad else 0)
