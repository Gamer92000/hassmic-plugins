#!/usr/bin/env python3
"""tools/workflow.py: every `uses:` of a version's release workflow at its commit, of the workflows it calls and of
the actions they use, all the way down (a composite action's steps, a docker action's image and Dockerfile, another
repository's reusable workflow; a review of 810b9e9), pinned by a commit of the action's own repository, an image by
its digest; the reader it reads them with,
strict where a YAML parser could read otherwise (a review of dc75e14: impostor commits of a fork run under the
original's name; Python's splitlines breaks lines where YAML does not).  No network: gh is tests/fake_gh.py, whose
`api` stand-in answers GitHub's REST API from made-up repositories (its DEFAULT_FILES: an honest release.yml calling
build.yml, actions/checkout by v7's commit, a node action).  The plugin template's and microWakeWord's own workflows
are read as the index reads them, and their copies of the reader held to this one's text, where those trees are
beside this one (TEMPLATE, MWW; --require: a tree not there fails, as in index.yml's siblings job).  index.py build's side (when this is asked, and what a Refused or an
Unavailable does to a version) is tests/test_index.py's."""
import json, os, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import attest, workflow

failed = False
def check(cond, what):
    global failed
    print(("ok   " if cond else "FAIL ") + what)
    failed |= not cond


top = tempfile.mkdtemp(prefix="references-test-")
os.environ["INDEX_GH"] = os.path.join(HERE, "fake_gh.py")
CFG, APILOG = os.path.join(top, "gh.json"), os.path.join(top, "api.log")
SOURCE, C, WF = "https://github.com/someone/plugin", "c" * 40, ".github/workflows/release.yml"
V7, MAIN, OLD, REL, FORK = "3d3c42e5aac5ba805825da76410c181273ba90b1", "9" * 40, "8" * 40, "7" * 40, "6" * 40


def gh(files=None, repos=None, **more):
    """the stand-in's API, a fresh build's caches"""
    open(CFG, "w").write(json.dumps({"api": dict(files=files or {}, repos=repos or {}, log=APILOG, **more)}))
    os.environ["INDEX_FAKE_GH"] = CFG
    if os.path.exists(APILOG):
        os.unlink(APILOG)
    workflow.Owner._repos.clear()
    attest._stalled.clear()


def asked():
    return open(APILOG).read().splitlines() if os.path.exists(APILOG) else []


def verdict(**over):
    """None, or "refused: ..." / "unavailable: ..." """
    a = dict(source=SOURCE, commit=C, workflow=WF, **over)
    try:
        workflow.check(a["source"], a["commit"], a["workflow"])
        return None
    except attest.Refused as x:
        return "refused: " + str(x)
    except attest.Unavailable as x:
        return "unavailable: " + str(x)


RELEASE = """name: release
on:
  push:
    tags: ['v*']
jobs:
  checks:
    uses: ./.github/workflows/build.yml
  release:
    needs: checks
    runs-on: ubuntu-24.04
    steps:
      - uses: {co}  # v7
        with:
          persist-credentials: false
      - name: Package
        run: |
          make
          echo done   # the shell's comment, with a uses: in it
"""
BUILD = "name: build\non:\n  workflow_call:\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: {co}\n      - run: make test\n"
CO = f"actions/checkout@{V7}"
REPOS = {"actions/checkout": {"default": "main", "branches": {"main": MAIN, "releases/v6": REL},
                              "tags": {"v7": V7, "v7.0.1": V7}, "history": {MAIN: [V7, OLD], REL: ["5" * 40]}}}


def files(release=None, build=None, **more):
    return dict({WF: release if release is not None else RELEASE.format(co=CO), ".github/workflows/build.yml": build if build is not None else BUILD.format(co=CO)}, **more)


# ---- the honest workflow: its actions by a tag's commit
gh(files(), REPOS)
check(verdict() is None, "release.yml and the build.yml it calls, actions/checkout by v7's commit (a tag's head): held")
paths = asked()
check(f"repos/someone/plugin/contents/{WF}?ref={C}" in paths and f"repos/someone/plugin/contents/.github/workflows/build.yml?ref={C}" in paths,
      f"both files read at the entry's commit, the called one too ({paths[:2]})")
check(not any("/compare/" in p for p in paths) and sum("repos/actions/checkout/tags" in p for p in paths) == 1,
      "the fast path: a tag's head needs no compare, and the action's refs are listed once for both references")
check(not any(p.startswith("repos/actions/checkout/commits") for p in paths),
      "never the commit's own page (GitHub serves a fork's commit there too, under the original's name)")
for what, sha, ok in (("on the default branch (behind its head)", OLD, True), ("on another branch's history", "5" * 40, True),
                      ("a branch's head", REL, True), ("in a fork only (an impostor commit)", FORK, False)):
    gh(files(release=RELEASE.format(co=f"actions/checkout@{sha}")), REPOS)
    got = verdict()
    check((got is None) == ok and (ok or ("a commit of a fork" in got and "jobs.release.steps.0" in got)),
          f"actions/checkout by a commit {what}: {'held' if ok else 'refused, named where'} ({got})")
gh(files(release=RELEASE.format(co=f"actions/checkout@{OLD}")), REPOS)
verdict()
cmp = [p for p in asked() if "/compare/" in p]
check(cmp and cmp[0] == f"repos/actions/checkout/compare/{MAIN}...{OLD}?per_page=1", f"the default branch's history asked first, from its head ({cmp[:1]})")
# the impostor in the called workflow: every local workflow read too
gh(files(build=BUILD.format(co=f"actions/checkout@{FORK}")), REPOS)
got = verdict()
check(got and got.startswith("refused") and ".github/workflows/build.yml jobs.build.steps.0" in got, f"an impostor commit in the called build.yml: refused ({got})")
# bounded: a repository of many refs, the commit in none of them
many = {"actions/checkout": {"default": "main", "branches": {f"b{i}": f"{i:040x}" for i in range(1, 240)}, "tags": {}, "history": {}}}
gh(files(release=RELEASE.format(co=f"actions/checkout@{FORK}"), build=BUILD.format(co=f"actions/checkout@{FORK}")), many)
got = verdict()
n = len([p for p in asked() if "/compare/" in p])
check(got and got.startswith("refused") and n == workflow.COMPARES and sum("/branches?" in p for p in asked()) == 3,
      f"a repository of 239 branches: its listings paged, {workflow.COMPARES} compares at most per commit, asked once for both references ({n}, {got and got[:80]})")
# the forms of a reference
for what, u, said in (("a tag", "actions/checkout@v7", "not pinned by a commit"), ("a branch", "actions/checkout@main", "not pinned by a commit"),
                      ("a short commit", "actions/checkout@3d3c42e", "not pinned by a commit"), ("capitals", "actions/checkout@" + V7.upper(), "not pinned by a commit"),
                      ("a local action", "./.github/actions/x", "local action"), ("a docker image by its tag", "docker://alpine:3.19", "not pinned"),
                      ("an expression", "${{ vars.ACTION }}", "not pinned by a commit")):
    gh(files(release=RELEASE.format(co=u)), REPOS)
    got = verdict()
    check(got and got.startswith("refused") and said in got, f"uses: {what}: refused ({got and got[:140]})")
gh(files(release=RELEASE.format(co="docker://alpine@sha256:" + "a" * 64)), REPOS)
check(verdict() is None, "uses: a docker image by its digest: held")
gh(files(release=RELEASE.format(co="nobody/gone@" + "1" * 40)), REPOS)
got = verdict()
check(got and got.startswith("refused") and "no repository nobody/gone" in got, f"an action of a repository GitHub does not have: refused ({got})")
for what, job, said in (("a container by its tag", "    container: node:20\n", "jobs.release.container"),
                        ("a container's image by its tag", "    container:\n      image: node:20\n", "jobs.release.container"),
                        ("a service by its tag", "    services:\n      db:\n        image: postgres\n", "jobs.release.services.db"),
                        # (a review of 9b02fdb, 3: services as an expression, and a service's value as one, went by unread)
                        ("services as an expression", "    services: ${{ fromJSON('{\"db\":{\"image\":\"evil/server:latest\"}}') }}\n", "jobs.release.services"),
                        ("a service as an expression", "    services:\n      db: ${{ fromJSON('{\"image\":\"evil/server:latest\"}') }}\n", "jobs.release.services.db"),
                        ("a container as an expression", "    container: ${{ fromJSON('{\"image\":\"evil/server:latest\"}') }}\n", "jobs.release.container")):
    gh(files(release=RELEASE.format(co=CO).replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n" + job, 1)), REPOS)
    got = verdict()
    check(got and got.startswith("refused") and said in got and "digest" in got, f"{what}: refused ({got and got[:140]})")
# a job that is no mapping (GitHub would read it otherwise, or not at all): refused, never passed over
gh(files(release=RELEASE.format(co=CO).replace("jobs:\n", "jobs:\n  other: ${{ fromJSON('{\"runs-on\":\"x\",\"container\":\"evil/server\"}') }}\n", 1)), REPOS)
got = verdict()
check(got and got.startswith("refused") and "jobs.other" in got, f"a job as an expression: refused ({got and got[:160]})")
gh(files(release=RELEASE.format(co=CO).replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    container: node@sha256:" + "b" * 64 + "\n", 1)), REPOS)
check(verdict() is None, "a container by its digest: held")
gh(files(release=RELEASE.format(co=CO).replace("  checks:\n    uses: ./.github/workflows/build.yml\n", f"  checks:\n    uses: someone/ci/.github/workflows/b.yml@{FORK}\n")),
   dict(REPOS, **{"someone/ci": {"branches": {"main": MAIN}, "tags": {}, "history": {}}}))
got = verdict()
check(got and got.startswith("refused") and "jobs.checks" in got and "someone/ci" in got, f"another repository's reusable workflow by an impostor commit: refused ({got})")
gh(files(release=RELEASE.format(co=CO).replace("        with:\n          persist-credentials: false\n", f"        with:\n          uses: actions/checkout@{FORK}\n")), REPOS)
got = verdict()
check(got and got.startswith("refused") and "where none is read" in got, f"a `uses` where GitHub reads none (an action's input): refused, never skipped ({got})")
gh(files(build=None, **{".github/workflows/build.yml": None}), REPOS)
got = verdict()
check(got and got.startswith("refused") and "build.yml is not in someone/plugin" in got, f"a called workflow not at the commit: refused ({got})")
loop = "on:\n  workflow_call:\njobs:\n  a:\n    uses: ./.github/workflows/release.yml\n"
gh(files(build=loop), REPOS)
check(verdict() is None, "workflows that call each other: each read once")

# ---- all the way down (a review of 810b9e9: the check stopped one level deep): an action's own metadata at its
# commit, a composite action's steps, a docker action's image or Dockerfile, another repository's reusable workflow
HELPER, HV1, HMAIN = "someone/helper", "1" * 40, "2" * 40
HREPO = {HELPER: {"default": "main", "branches": {"main": HMAIN}, "tags": {"v1": HV1}, "history": {HMAIN: [HV1]}}}
def composite(*steps):
    return ("name: 'Helper'\ndescription: >\n  A helper,\n  folded.\ninputs:\n  x:\n    description: 'over\n      two lines'\n"
            "runs:\n  using: composite\n  steps:\n" + "".join(f"    - {x}\n" for x in steps))
def with_helper(meta, uses=f"{HELPER}@{HV1}", repos=None, **more):
    gh(files(release=RELEASE.format(co=uses), **{f"{HELPER}:action.yml": meta}, **more), dict(REPOS, **HREPO, **(repos or {})))
    return verdict()
with_helper(composite(f"uses: {CO}  # v7", "run: make", "shell: bash"))
got = verdict()
check(got is None and f"repos/{HELPER}/contents/action.yml?ref={HV1}" in asked(),
      f"a composite action of the author's own by its tag's commit, its step actions/checkout by v7's: read at that commit, held ({got})")
got = with_helper(composite(f"uses: actions/checkout@{FORK}"))
check(got and got.startswith("refused") and "someone/helper/action.yml" in got and "runs.steps.0" in got and "a commit of a fork" in got,
      f"a composite action whose step is the impostor checkout: refused, named where ({got and got[:200]})")
for what, step, said in (("a tag", "uses: actions/checkout@v7", "not pinned by a commit"), ("a local action", "uses: ./x", "local action"),
                         ("an expression", "uses: ${{ inputs.a }}", "not pinned"), ("an image by its tag", "uses: docker://alpine:3", "not pinned")):
    got = with_helper(composite(step))
    check(got and got.startswith("refused") and said in got, f"a composite action's step by {what}: refused ({got and got[:160]})")
# composite in composite, three deep, the last one's step the impostor
gh(files(release=RELEASE.format(co=f"{HELPER}@{HV1}"),
         **{f"{HELPER}@{HV1}:action.yml": composite(f"uses: {HELPER}/inner@{HMAIN}"),
            f"{HELPER}@{HMAIN}:inner/action.yml": composite(f"uses: {HELPER}/deeper@{HV1}"),
            f"{HELPER}@{HV1}:deeper/action.yml": composite(f"uses: actions/checkout@{FORK}")}), dict(REPOS, **HREPO))
got = verdict()
check(got and got.startswith("refused") and "deeper/action.yml" in got and "a commit of a fork" in got,
      f"three composite actions deep, the third's step the impostor: refused ({got and got[:200]})")
# an action that uses itself: read once
gh(files(release=RELEASE.format(co=f"{HELPER}@{HV1}"), **{f"{HELPER}:action.yml": composite(f"uses: {HELPER}@{HV1}", f"uses: {CO}")}), dict(REPOS, **HREPO))
got = verdict()
check(got is None and asked().count(f"repos/{HELPER}/contents/action.yml?ref={HV1}") == 1, f"a composite action that uses itself: read once, held ({got})")
# where GitHub's runner looks: action.yml, action.yaml, Dockerfile, dockerfile, the first there
gh(files(release=RELEASE.format(co=f"{HELPER}@{HV1}"), **{f"{HELPER}:action.yml": None, f"{HELPER}:action.yaml": composite(f"uses: actions/checkout@{FORK}")}),
   dict(REPOS, **HREPO))
got = verdict()
check(got and "someone/helper/action.yaml" in got and "a commit of a fork" in got, f"no action.yml: action.yaml read ({got and got[:160]})")
gh(files(release=RELEASE.format(co=f"{HELPER}@{HV1}"), **{f"{HELPER}:action.yml": None}), dict(REPOS, **HREPO))
got = verdict()
check(got and got.startswith("refused") and "no action.yml, action.yaml, Dockerfile, dockerfile" in got, f"an action with no metadata at its commit: refused ({got and got[:160]})")
# docker actions: the image by its digest, or a Dockerfile whose FROM lines are
DOCKER = "name: d\nruns:\n  using: docker\n  image: {}\n"
D = "a" * 64
for what, image, dfile, ok in (
        ("an image by its digest", f"docker://alpine@sha256:{D}", None, True),
        ("an image by its tag", "docker://alpine:3", None, False),
        ("a Dockerfile FROM an image by its digest", "Dockerfile", f"FROM alpine:3@sha256:{D}\nRUN apk add x\n", True),
        ("a Dockerfile FROM an image by its tag", "Dockerfile", "FROM alpine:3\n", False),
        ("a Dockerfile of two stages, the second FROM the first", "Dockerfile", f"FROM --platform=linux/amd64 golang@sha256:{D} AS build\nRUN go build\nFROM scratch\nCOPY --from=build /x /x\n", True),
        ("a Dockerfile FROM a build argument", "Dockerfile", f"ARG I=alpine@sha256:{D}\nFROM ${{I}}\n", False),
        ("a Dockerfile COPY --from an image by its tag", "Dockerfile", f"FROM alpine@sha256:{D}\nCOPY --from=busybox:1 /bin/sh /sh\n", False),
        ("a Dockerfile RUN --mount from an image by its tag", "Dockerfile", f"FROM alpine@sha256:{D}\nRUN --mount=type=bind,from=busybox,target=/b true\n", False),
        ("a Dockerfile FROM continued on the next line", "Dockerfile", "FROM \\\n  alpine:3\n", False),
        ("a Dockerfile's second FROM after a tab", "Dockerfile", f"FROM alpine@sha256:{D}\nFROM\tevil:1\n", False),
        ("a Dockerfile's builder by its tag (# syntax=)", "Dockerfile", f"# syntax=docker/dockerfile:1\nFROM alpine@sha256:{D}\n", False),
        ("a Dockerfile in a folder of the action", "./docker/Dockerfile", f"FROM alpine@sha256:{D}\n", True),
        ("a Dockerfile outside the action (..)", "../Dockerfile", None, False)):
    more = {f"{HELPER}:action.yml": DOCKER.format(image)}
    if dfile is not None:
        more[f"{HELPER}:" + image.removeprefix("./")] = dfile
    gh(files(release=RELEASE.format(co=f"{HELPER}@{HV1}"), **more), dict(REPOS, **HREPO))
    got = verdict()
    check((got is None) == ok and (ok or got.startswith("refused")), f"a docker action, {what}: {'held' if ok else 'refused'} ({got and got[:180]})")
gh(files(release=RELEASE.format(co=f"{HELPER}@{HV1}"), **{f"{HELPER}:action.yml": None, f"{HELPER}:action.yaml": None, f"{HELPER}:Dockerfile": "FROM alpine:3\n"}),
   dict(REPOS, **HREPO))
got = verdict()
check(got and got.startswith("refused") and "someone/helper/Dockerfile" in got and "FROM alpine:3" in got,
      f"an action that is a Dockerfile alone (no action.yml): its FROM held too ({got and got[:160]})")
# a Dockerfile is read only where BuildKit cannot read it otherwise, the rest refused (a review of 5a3035d: BuildKit
# continues a line by its own rule and joins it with no blank, reads `// syntax=` and a JSON file as directives, takes
# quotes and backslashes out of flags, reads a mount's value as CSV with its keys in any case)
H = "a" * 64
for what, text, said in (
        ("a line ending in two backslashes (no continuation to BuildKit), a second FROM after it", f"FROM alpine@sha256:{H}\nRUN echo \\\\\nFROM attacker/img:latest\n", "a line continued"),
        ("a continued line (a backslash at its end)", f"FROM alpine@sha256:{H}\nRUN apk add x && \\\n    true\n", "a line continued"),
        ("a backslash and blanks at a line's end", f"FROM alpine@sha256:{H}\nRUN true \\  \t\nRUN x\n", "a line continued"),
        ("a line of a backslash alone", f"FROM alpine@sha256:{H}\n\\\nRUN x\n", "a line continued"),
        ("a comment ending in a backslash", f"# a \\\nFROM alpine@sha256:{H}\n", "a line continued"),
        ("COPY --from= continued, joined with no blank", f"FROM alpine@sha256:{H} AS ghcr.io\nCOPY --from=ghcr.io\\\n/attacker/img:latest /x /x\n", "a line continued"),
        ("RUN --mount from= continued", f"FROM alpine@sha256:{H} AS ghcr.io\nRUN --mount=type=bind,from=ghcr.io\\\n/attacker/img:latest,target=/x true\n", "a line continued"),
        ("// syntax=", f"// syntax=docker.io/attacker/frontend:latest\nFROM alpine@sha256:{H}\n", "starts with //"),
        ("a line starting with #!", f"#!/attacker/frontend\nFROM alpine@sha256:{H}\n", "starts with #!"),
        ("# syntax= after blanks", f"  #  syntax  =  docker/dockerfile:1\nFROM alpine@sha256:{H}\n", "a parser directive"),
        ("# SYNTAX= in capitals", f"# SYNTAX=docker/dockerfile:1\nFROM alpine@sha256:{H}\n", "a parser directive"),
        ("# escape=", f"# escape=`\nFROM alpine@sha256:{H}\n", "a parser directive"),
        ("# check=", f"#check=skip=all\nFROM alpine@sha256:{H}\n", "a parser directive"),
        ("a directive's form after the first instruction", f"FROM alpine@sha256:{H}\n# syntax=x\n", "a parser directive"),
        ("a file that reads as JSON", '{"syntax": "attacker/frontend:latest"}\n', "reads as JSON"),
        ("a file that opens as JSON does", '[\n"syntax"\nFROM alpine@sha256:' + H + '\n', "reads as JSON"),
        ("RUN --mount FROM= (BuildKit lowercases the key)", f"FROM alpine@sha256:{H}\nRUN --mount=type=bind,FROM=attacker/img:latest,target=/x true\n", "not an earlier stage"),
        ("RUN --mount From= after another key", f"FROM alpine@sha256:{H}\nRUN --mount=target=/x,From=attacker/img:latest true\n", "not an earlier stage"),
        ("RUN --mount, a quoted CSV field", f'FROM alpine@sha256:{H}\nRUN --mount=type=bind,"from=attacker/img:latest",target=/x true\n', "a quote or a backslash"),
        ("RUN --mount from= an image by its digest (a mount's only of an earlier stage)", f"FROM alpine@sha256:{H}\nRUN --mount=type=bind,from=busybox@sha256:{H},target=/b true\n", "not an earlier stage"),
        ("RUN --mount from= scratch", f"FROM alpine@sha256:{H}\nRUN --mount=type=bind,from=scratch,target=/b true\n", "not an earlier stage"),
        ("RUN --mount from= the stage it is in", f"FROM alpine@sha256:{H} AS b\nRUN --mount=type=bind,from=b,target=/b true\n", "not an earlier stage"),
        ("COPY --fr\\om= (BuildKit takes the backslash out)", f"FROM alpine@sha256:{H}\nCOPY --fr\\om=attacker/img:latest /x /x\n", "a quote or a backslash"),
        ("COPY --from= quoted", f'FROM alpine@sha256:{H}\nCOPY --from="attacker/img:latest" /x /x\n', "a quote or a backslash"),
        ("COPY --FROM= in capitals", f"FROM alpine@sha256:{H}\nCOPY --FROM=attacker/img:latest /x /x\n", "not an image by its digest"),
        ("COPY --from= a stage's number no earlier stage has", f"FROM alpine@sha256:{H}\nCOPY --from=0 /x /x\n", "no earlier stage of that number"),
        ("a character outside printable ASCII in an instruction (Go takes the byte 0xa0 of U+0160 for a blank)",
         f"FROM alpine@sha256:{H}\nCOPY --chown=x\u0160--from=attacker/img:latest /x /x\n", "outside tab and printable ASCII"),
        ("a stage's name BuildKit does not take", f"FROM alpine@sha256:{H} AS 'x'\n", "a FROM with a flag, a quote"),
        ("a FROM with a flag other than --platform", f"FROM --reset alpine@sha256:{H}\n", "a FROM with a flag"),
        ("a FROM of two words", f"FROM alpine@sha256:{H} evil:1\n", "a FROM of 2 words")):
    try:
        got = "; ".join(workflow.dockerfile(text)) or "nothing said"
    except ValueError as x:
        got = "ValueError " + str(x)
    check(said in got, f"a Dockerfile, {what}: {'not read' if got.startswith('ValueError') else 'refused'} ({got[:150]})")
for what, text in (("two stages, COPY --from= the first by its name and by its number", f"FROM golang@sha256:{H} AS build\nRUN go build\nFROM scratch\nCOPY --from=build /x /x\nCOPY --from=0 /y /y\n"),
                   ("RUN --mount from= an earlier stage, keys in capitals", f"FROM golang@sha256:{H} AS Build\nFROM alpine@sha256:{H}\nRUN --mount=TYPE=bind,FROM=build,target=/b true\n"),
                   ("comments, blank lines, a backslash inside a line", f"# a comment\n\nFROM --platform=$BUILDPLATFORM alpine@sha256:{H}\nRUN printf 'a\\nb' > /x\n")):
    try:
        got = workflow.dockerfile(text)
    except ValueError as x:
        got = "ValueError " + str(x)
    check(got == [], f"a Dockerfile, {what}: held ({got})")

# what the metadata says, read as GitHub reads it: a runs hidden from a reader by lines refused, never read past
for what, meta in (("a runs: inside a quoted text over lines", f"name: x\ndescription: 'a\nruns:\n  using: node20\n  main: x'\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@{FORK}\n"),
                   ("a runs: twice", f"runs:\n  using: node20\nruns:\n  using: composite\n"),
                   ("a quoted key", 'name: x\n"runs":\n  using: node20\n'),
                   ("an anchor", "name: &a x\nruns:\n  using: node20\n"),
                   ("a folded runs", "runs: >\n  using: node20\n"),
                   ("a line separator", "name: x\u2028runs:\nruns:\n  using: node20\n"),
                   ("a uses in a node action's runs", f"runs:\n  using: node20\n  steps:\n    - uses: actions/checkout@{FORK}\n"),
                   ("no runs", "name: x\n")):
    got = with_helper(meta)
    check(got and got.startswith("refused") and "is not read as the index reads an action's metadata" in got, f"action.yml with {what}: no reading, refused ({got and got[:180]})")
# skim as real actions are written (2026-11-23: actions/checkout's descriptions folded blocks, download-artifact's a
# quoted text over three lines, setup-uv's a value on the line below its key): read, the runs found where YAML has it
REAL = ("name: 'Checkout'\ndescription: \"Check\\\" it\"\ninputs:\n  ref:\n    description: >\n      The branch.\n\n\n      runs: not this\n"
        "  merge:\n    description: 'When\n      runs: neither\n      this.'\n    default: 'false'\n  token:\n    description:\n      \"Set up\"\n"
        "    default: ${{ github.token }}\noutputs:\n  x:\n    value: [a, 'b, c']\nruns:\n  using: node24\n  main: dist/index.js\n  post: dist/index.js\n"
        "branding:\n  icon: x\n")
try:
    got = (sorted(workflow.skim(REAL)), workflow.metadata(REAL)[0])
except ValueError as x:
    got = str(x)
check(got == (["branding", "description", "inputs", "name", "outputs", "runs"], {"using": "node24", "main": "dist/index.js", "post": "dist/index.js"}),
      f"skim: folded blocks, a quoted text over lines and one on the line below its key, an escaped quote: read past, runs where YAML has it ({got})")
for what, meta in (("a block line less deep than its first", "description: >\n    a\n  b\nruns:\n  using: node24\n"),
                   ("an indentation between two levels", "inputs:\n  a:\n    x: 1\n   y: 2\nruns:\n  using: node24\n"),
                   ("a flow list over lines", "outputs: [a,\n  b]\nruns:\n  using: node24\n"),
                   ("a document marker after a key (a second document)", "name: x\n---\nruns:\n  using: node24\n"),
                   ("two document markers", "---\n---\nruns:\n  using: node24\n"),
                   ("a document marker that ends a block text", "description: |\n  a\n---\nruns:\n  using: node24\n"),
                   ("a document marker with a value after it", "--- x\nruns:\n  using: node24\n"),
                   ("a flow list whose item opens with ? before a quote (a review of 5a3035d)",
                    f'name: x\ndescription: [? "a]#\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@{FORK}\n"]\nruns:\n  using: node24\n'),
                   ("a flow list whose item opens with ? before a quote closed under a later key (PyYAML: no runs at the top)",
                    'name: x\ndescription: [? "a]#\nruns:\n  using: node20\n  main: x.js\ninputs:\n  a:\n    "] #"\n'),
                   ("the same after an anchor", 'description: [&a "a]#\nruns:\n  using: node20\ninputs:\n  a:\n    "] #"\n'),
                   ("the same after a tag", "description: [!t 'a]#\nruns:\n  using: node20\ninputs:\n  a:\n    '] #'\n"),
                   ("a flow list whose item opens with an anchor before a quote", 'description: [&a "a]#\nruns:\n  using: node24\n"]\n'),
                   ("a flow list whose item opens with a tag before a quote", 'description: [!t "a]#\nruns:\n  using: node24\n"]\n'),
                   ("a flow list whose item is an alias", "description: [*a]\nruns:\n  using: node24\n"),
                   ("a flow mapping whose key opens with ?", "description: {? a: b}\nruns:\n  using: node24\n"),
                   ("a top line that is no key", "runs:\n  using: node24\nx\n"),
                   ("a plain text whose next line reads as a key", "description: a\n  b: c\nruns:\n  using: node24\n")):
    try:
        workflow.skim(meta)
        got = "read"
    except ValueError as x:
        got = str(x)
    check(got != "read", f"skim: {what}: no reading ({got[:100]})")
# one document marker as the first line that is not a comment (actions/setup-python's and pypa/gh-action-pypi-publish's
# open so; a review of 5a3035d: refused as a verdict): read, its keys and runs where YAML has them
for what, meta in (("---", "---\nname: x\nruns:\n  using: node24\n  main: x.js\n"), ("a comment, then ---", "# c\n\n--- # the one document\nname: x\nruns:\n  using: node24\n  main: x.js\n")):
    try:
        got = (sorted(workflow.skim(meta)), workflow.metadata(meta)[0])
    except ValueError as x:
        got = str(x)
    check(got == (["name", "runs"], {"using": "node24", "main": "x.js"}), f"skim: a leading document marker ({what}): read, runs where YAML has it ({got})")
# a quote in a flow collection after a `:` with no blank (a quoted key's value, as JSON writes it): taken as opening a
# quoted text, so a `]` or `#` inside it ends nothing
for meta in ('description: {"k":"v, ]}"}\nruns:\n  using: node24\n', 'description: {"k":" #"}\nruns:\n  using: node24\n'):
    try:
        got = sorted(workflow.skim(meta))
    except ValueError as x:
        got = "refused"
    check(got in (["description", "runs"], "refused"), f"skim: {meta.splitlines()[0]}: its keys as YAML's, or refused ({got})")

# another repository's reusable workflow: read with the strict reader, at its commit, all it uses held
REMOTE = "on:\n  workflow_call:\njobs:\n  b:\n    uses: ./.github/workflows/inner.yml\n  a:\n    runs-on: x\n    steps:\n      - uses: {}\n"
INNER = "on:\n  workflow_call:\njobs:\n  i:\n    runs-on: x\n    steps:\n      - uses: {}\n"
def with_remote(outer, inner, job=f"{HELPER}/.github/workflows/r.yml@{HV1}"):
    gh(files(release=RELEASE.format(co=CO).replace("  checks:\n    uses: ./.github/workflows/build.yml\n", f"  checks:\n    uses: {job}\n"),
             **{f"{HELPER}@{HV1}:.github/workflows/r.yml": outer, f"{HELPER}@{HV1}:.github/workflows/inner.yml": inner}), dict(REPOS, **HREPO))
    return verdict()
got = with_remote(REMOTE.format(CO), INNER.format(CO))
check(got is None and f"repos/{HELPER}/contents/.github/workflows/inner.yml?ref={HV1}" in asked(),
      f"another repository's reusable workflow by its own commit, and the local one it calls, at that repository's commit: read, held ({got})")
for what, outer, inner, said in (("a tag in it", REMOTE.format("actions/checkout@v7"), INNER.format(CO), "not pinned by a commit"),
                                 ("an impostor in the workflow it calls", REMOTE.format(CO), INNER.format(f"actions/checkout@{FORK}"), "a commit of a fork"),
                                 ("a local action in it", REMOTE.format("./x"), INNER.format(CO), "local action"),
                                 ("a folded block in it", REMOTE.format(CO).replace("on:\n", "name: >\n  x\non:\n"), INNER.format(CO), "not read as the plain YAML"),
                                 ("a job's container by its tag", REMOTE.format(CO).replace("    runs-on: x\n", "    runs-on: x\n    container: node:20\n"), INNER.format(CO), "an image not pinned")):
    got = with_remote(outer, inner)
    check(got and got.startswith("refused") and said in got, f"another repository's reusable workflow with {what}: refused ({got and got[:180]})")
got = with_remote(REMOTE.format(CO), INNER.format(CO), job=f"{HELPER}/.github/workflows/r.yml@{FORK}")
check(got and "a commit of a fork" in got, f"another repository's reusable workflow by an impostor commit: refused, nothing of it read ({got and got[:120]})")
# GitHub's self-repository reference, `$/<path>` (a review of 5a3035d: refused as "not pinned by a commit", which it
# is: the file's own repository at the commit the file is read at): at a step an action, at a job a workflow, of that
# repository and commit, held as such
OWN = "someone/plugin"
def with_self(release, **more):
    gh(files(release=release, **more), dict(REPOS, **HREPO))
    return verdict()
got = with_self(RELEASE.format(co="$/.github/actions/x"), **{f"{OWN}:.github/actions/x/action.yml": composite(f"uses: {CO}")})
check(got is None and f"repos/{OWN}/contents/.github/actions/x/action.yml?ref={C}" in asked(),
      f"uses: $/.github/actions/x at a step: the action read at the workflow's own repository and commit, held ({got})")
got = with_self(RELEASE.format(co="$/.github/actions/x"), **{f"{OWN}:.github/actions/x/action.yml": composite(f"uses: actions/checkout@{FORK}")})
check(got and got.startswith("refused") and ".github/actions/x/action.yml" in got and "a commit of a fork" in got,
      f"uses: $/.github/actions/x whose step is the impostor checkout: refused ({got and got[:160]})")
got = with_self(RELEASE.format(co=CO).replace("    uses: ./.github/workflows/build.yml\n", "    uses: $/.github/workflows/build.yml\n"),
                build=BUILD.format(co=f"actions/checkout@{FORK}"))
check(got and got.startswith("refused") and "build.yml jobs.build.steps.0" in got and "a commit of a fork" in got,
      f"uses: $/.github/workflows/build.yml at a job: that workflow read at the same commit, the impostor in it refused ({got and got[:160]})")
got = with_self(RELEASE.format(co=CO).replace("    uses: ./.github/workflows/build.yml\n", "    uses: $/.github/workflows/build.yml\n"))
check(got is None, f"uses: $/.github/workflows/build.yml at a job, an honest build.yml: held ({got})")
# in a composite action of another repository: that repository at the action's commit, not the workflow's
gh(files(release=RELEASE.format(co=f"{HELPER}@{HV1}"), **{f"{HELPER}@{HV1}:action.yml": composite("uses: $/inner"),
                                                          f"{HELPER}@{HV1}:inner/action.yml": composite(f"uses: actions/checkout@{FORK}")}), dict(REPOS, **HREPO))
got = verdict()
check(got and got.startswith("refused") and "someone/helper/inner/action.yml" in got and f"repos/{HELPER}/contents/inner/action.yml?ref={HV1}" in asked(),
      f"$/inner in another repository's composite action: read at that repository and the action's commit ({got and got[:160]})")
for u, said in (("$/../x", "self-repository reference"), ("$/./x", "self-repository reference"), ("$/x/../../y", "self-repository reference"),
                ("$/x@v1", "self-repository reference"), ("$/${{ inputs.a }}", "self-repository reference"), ("$/", "self-repository reference"),
                ("$//x", "self-repository reference"), ("$/x/", "self-repository reference")):
    got = with_self(RELEASE.format(co=u))
    check(got and got.startswith("refused") and said in got and not any("/contents/" in p and p.split("?")[0].endswith("x/action.yml") for p in asked()),
          f"uses: {u} at a step: refused, nothing read there ({got and got[:140]})")
got = with_self(RELEASE.format(co=CO).replace("    uses: ./.github/workflows/build.yml\n", "    uses: $/.github/actions/x\n"))
check(got and got.startswith("refused") and "not a workflow" in got, f"uses: $/<an action's path> at a job: refused ({got and got[:140]})")

# a path or a name that is `.` or `..`: refused (GitHub's runner joins the path without normalising it)
for u in (f"actions/checkout/../../evil@{V7}", f"actions/checkout/./x@{V7}", f"actions/..@{V7}", f"actions/.@{V7}", f"actions/checkout.git@{V7}"):
    gh(files(release=RELEASE.format(co=u)), REPOS)
    got = verdict()
    check(got and got.startswith("refused") and "not pinned by a commit" in got and not any("/contents/" in p and "evil" in p for p in asked()),
          f"uses: {u[:40]}...: refused, nothing read there ({got and got[:120]})")
# the bound: more files than FILES_MAX for one version is no verdict, never a pass
chain = {f"{HELPER}@{HV1}:a{i}/action.yml": composite(f"uses: {HELPER}/a{i + 1}@{HV1}") for i in range(workflow.FILES_MAX + 2)}
gh(files(release=RELEASE.format(co=f"{HELPER}/a0@{HV1}"), **chain), dict(REPOS, **HREPO))
got = verdict()
check(got and got.startswith("unavailable") and f"more than {workflow.FILES_MAX} files" in got,
      f"a chain of actions longer than the bound: no verdict, said why ({got and got[:160]})")
# a repository of more refs than the index reads: a commit found on none of those read is no verdict (it may be on
# one not read), never a refusal; one found is held
big = {"actions/checkout": {"default": "main", "branches": {"main": MAIN}, "tags": {f"t{i}": f"{i + 1:040x}" for i in range(workflow.PAGES * 100 + 5)},
                            "history": {MAIN: [V7]}}}
gh(files(release=RELEASE.format(co=f"actions/checkout@{FORK}"), build=BUILD.format(co=f"actions/checkout@{FORK}")), big)
got = verdict()
check(got and got.startswith("unavailable") and "more tags than it reads" in got, f"a commit on none of the first {workflow.PAGES} pages of tags: no verdict ({got and got[:160]})")
gh(files(release=RELEASE.format(co=f"actions/checkout@{V7}"), build=BUILD.format(co=f"actions/checkout@{V7}")), big)
got = verdict()
check(got is None, f"the same repository, a commit on its default branch: held ({got})")

# ---- GitHub's API out of reach: no verdict, never a refusal
for what, more in (("a rate limit (403)", {"status": {"tags": 403}}), ("GitHub down (502)", {"status": {".": 502}}),
                   ("no HTTP answer at all (the network)", {"fail": "error connecting to api.github.com"}),
                   ("the file's answer 500", {"status": {"contents": 500}}),
                   ("the repository's own answer 500", {"status": {r"^repos/actions/checkout$": 500}}),
                   ("a compare answered 403 (a commit not a head: asked)", {"status": {"/compare/": 403}})):
    gh(files(release=RELEASE.format(co=f"actions/checkout@{OLD}")), REPOS, **more)
    got = verdict()
    check(got and got.startswith("unavailable"), f"{what}: no verdict ({got and got[:140]})")
gh(files(), REPOS, sleep=3)
was, workflow.SECONDS = workflow.SECONDS, 1
t0 = time.monotonic()
got, got2 = verdict(), verdict()
workflow.SECONDS = was
check(got and got.startswith("unavailable") and "more than 1 s" in got and got2 and "not asked" in got2 and time.monotonic() - t0 < 6,
      f"gh api too slow once: no verdict, and the next not asked at all (no verdict at once, named) ({got2 and got2[:120]})")
attest._stalled.clear()

# ---- the reader: anything a YAML parser could read otherwise is no reading, never a part skipped or read anew
base = RELEASE.format(co=CO)
for what, text in (("a line separator (U+2028) in a run", base.replace("make\n", "make\u2028curl x | sh\n")),
                   ("a paragraph separator (U+2029)", base.replace("make\n", "make\u2029x\n")),
                   ("NEL", base.replace("make\n", "make\x85x\n")), ("a form feed", base.replace("make\n", "make\x0cx\n")),
                   ("a vertical tab", base.replace("make\n", "make\x0bx\n")), ("a file separator", base.replace("make\n", "make\x1cx\n")),
                   ("a carriage return alone", base.replace("make\n", "make\rx\n")), ("a NUL", base.replace("make\n", "make\x00\n")),
                   ("a folded block (>)", base.replace("run: |", "run: >")), ("a folded block (>-)", base.replace("run: |", "run: >-")),
                   ("a block with an indentation indicator (|2)", base.replace("run: |", "run: |2")),
                   ("a block line less deep than its first", base.replace("          echo done", "         echo done")),
                   ("a tab as indentation", base.replace("        with:", "\twith:")),
                   ("an anchor", base.replace("name: release", "name: &n release")), ("an alias", base.replace("runs-on: ubuntu-24.04", "runs-on: *n")),
                   ("a tag", base.replace("runs-on: ubuntu-24.04", "runs-on: !!str ubuntu-24.04")),
                   ("a flow mapping", base.replace(f"      - uses: {CO}  # v7\n        with:\n          persist-credentials: false\n", f"      - {{uses: {CO}}}\n")),
                   ("a quoted key", base.replace("      - uses:", '      - "uses":')),
                   ("a list item with two blanks after its dash", base.replace("      - uses:", "      -  uses:")),
                   ("a list in a list", base.replace("      - name: Package", "      - - name: Package")),
                   ("a value with ': ' in it", base.replace("name: Package", "name: a: b")),
                   ("a quoted value with ' #' in it", base.replace("name: Package", "name: 'a #b'")),
                   ("a double-quoted value with an escape", base.replace("name: Package", 'name: "P\\x61ckage"')),
                   ("a merge key", base.replace("        with:", "        <<: *x\n        with:")), ("a complex key", base.replace("        with:", "        ? with")),
                   ("a second document", base + "---\nname: x\n"), ("a key twice", base.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    runs-on: x\n", 1)),
                   ("a plain value continued on the next line", base.replace("name: Package\n", "name: Package\n          more\n"))):
    try:
        workflow.read(text)
        got = "read"
    except ValueError as x:
        got = str(x)
    check(got != "read", f"the reader: {what}: no reading ({got[:100]})")
t = workflow.read(base.replace("\n", "\r\n"))
check(t["jobs"]["release"]["steps"][1]["run"] == "make\necho done   # the shell's comment, with a uses: in it",
      "CRLF read as LF, a block text kept as written (its comment and its ` #` are the shell's)")
t = workflow.read("a: [main, 'v*', \"x\"]\nb: 'it''s'\nc: |-\n  x\n\n  y\nd:\ne: ${{ x == 'y' }}\n")
check(t == {"a": ["main", "v*", "x"], "b": "it's", "c": "x\n\ny", "d": None, "e": "${{ x == 'y' }}"}, f"flow lists, quotes, |-, a null, an expression: read ({t})")
for name in ("index.yml",):
    try:
        workflow.read(open(os.path.join(ROOT, ".github", "workflows", name)).read())
        ok = True
    except ValueError as x:
        ok = str(x)
    check(ok is True, f"this repository's own {name} reads ({ok})")
# the sibling trees' workflows, where they are beside this one: what an author starts from reads as the index reads it
for env, name in (("TEMPLATE", "hassmic-plugin-template"), ("MWW", "hassmic-plugin-microwakeword")):
    tree = os.environ.get(env) or os.path.join(os.path.dirname(ROOT), name)
    for f in ("release.yml", "build.yml"):
        p = os.path.join(tree, ".github", "workflows", f)
        if not os.path.isfile(p):
            if "--require" in sys.argv[1:]:
                check(False, f"{name} {f}: not at {tree} (--require: index.yml's siblings job checks it out)")
            else:
                print(f"skip {name} {f}: not at {tree}")
            continue
        text = open(p).read()
        try:
            tree_, blocks = workflow.parse(text)
            n = len(workflow.uses(tree_, blocks, text.split("\n")))
            ok = n > 0
        except ValueError as x:
            ok = str(x)
        check(ok is True, f"{name}'s {f} reads, every uses: read ({ok})")
# and their copies of the reader (tools/workflow_test.py: _INDICATOR, scalar, parse, read), the same text as
# tools/workflow.py's: an author's own test that reads a workflow otherwise than the index does passes what the index
# refuses, or the other way (a review of 810b9e9: both docstrings said "the same text", nothing held them to it)
import ast
def reader(path):
    """the reader's parts in the Python file PATH, as written: {name: source}"""
    text = open(path, encoding="utf-8").read()
    out = {}
    for node in ast.parse(text).body:
        if isinstance(node, ast.FunctionDef) and node.name in ("scalar", "parse", "read"):
            out[node.name] = ast.get_source_segment(text, node)
        elif isinstance(node, ast.Assign) and [getattr(t, "id", None) for t in node.targets] == ["_INDICATOR"]:
            out["_INDICATOR"] = ast.get_source_segment(text, node)
    return out
ours = reader(os.path.join(ROOT, "tools", "workflow.py"))
check(sorted(ours) == ["_INDICATOR", "parse", "read", "scalar"], f"tools/workflow.py has the reader's four parts: {sorted(ours)}")
for env, name in (("TEMPLATE", "hassmic-plugin-template"), ("MWW", "hassmic-plugin-microwakeword")):
    p = os.path.join(os.environ.get(env) or os.path.join(os.path.dirname(ROOT), name), "tools", "workflow_test.py")
    if not os.path.isfile(p):
        if "--require" in sys.argv[1:]:
            check(False, f"{name} tools/workflow_test.py: not at {p} (--require: index.yml's siblings job checks it out)")
        else:
            print(f"skip {name} tools/workflow_test.py: not at {p}")
        continue
    theirs = reader(p)
    differ = [k for k in ours if theirs.get(k) != ours[k]]
    check(not differ, f"{name}'s tools/workflow_test.py carries tools/workflow.py's reader, the same text{': not so in ' + ', '.join(differ) if differ else ''}")
# the count of `uses:` lines against the uses read: a line the reader would skip is caught
text = RELEASE.format(co=CO)
tree_, blocks = workflow.parse(text)
try:
    workflow.uses(tree_, blocks - {max(blocks)}, text.split("\n") + [f"      - uses: actions/checkout@{FORK}"])
    got = "taken"
except ValueError as x:
    got = str(x)
check("lines say uses:" in got, f"a `uses:` line the tree does not have: refused ({got})")

import shutil
shutil.rmtree(top)
print("references: " + ("FAILED" if failed else "all passed"))
sys.exit(1 if failed else 0)
