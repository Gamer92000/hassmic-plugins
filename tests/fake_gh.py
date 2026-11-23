#!/usr/bin/env python3
"""A stand-in for GitHub's CLI as tools/attest.py runs it (`gh attestation verify FILE --repo ... --format json`), for
the tests: no network, no Sigstore.  It answers from INDEX_FAKE_GH, a JSON file:

  {"<sha256 of a file>" | "*": facts or [facts, ...],   the attestations GitHub's API would have for that file ("*":
                                                        any file; none: "no attestations found", as gh says)
   "mode": "honest" | "lie",                            honest (the default): holds each attestation to the flags as gh
                                                        does and prints only those that pass, failing where none does;
                                                        lie: prints every one as verified, status 0, whatever the flags
                                                        (what attest.judge must not take on gh's word)
   "fail": "<text>",                                    gh fails: the text on stderr, status 1
   "raw": "<text>",                                     printed as it is, status 0 (an answer that is no JSON)
   "log": "<file>"}                                     each command line appended to it, one JSON line each

facts: {"repo": "<owner/repo>", "commit": "<40 hex>", "runner": "github-hosted" | "self-hosted", "signer_repo",
"signer_commit", "issuer", "predicate", "subject": "<sha256>", "workflow": "<the signing workflow's path>", "caller": "<the
workflow the run was started for, buildConfigURI's>", "ref": "<refs/tags/... or refs/heads/...>", "trigger": "push" |
"workflow_dispatch" | ..., "config_commit"}; what is left out is what the flags ask for (repo: --repo, commit:
--source-digest, signer_*: repo's and commit's, subject: the file's own SHA-256, workflow: the one --cert-identity-regex
names, caller: the workflow, ref: --source-ref, trigger: push, config_commit: the commit), so {} attests any file as
the honest build of what is asked.  With --bundle the attestations are the file's lines instead: bundles this stand-in
made (their verificationMaterial carries the facts), as attest.verify keeps them and the site publishes them.  The
JSON printed is shaped as gh 2.105.0's (tests/gh-verify-cli.json is a real one), and so are its errors (the words
attest.VERDICTS reads as gh's verdicts: no attestations, a field not what a flag asks, an identity not the one asked).
gh has no flag for the trigger, buildConfigURI or its digest: an honest gh passes an attestation whatever they are,
and attest.judge has to refuse it.  "sleep": <seconds> before it answers (a gh that takes too long); "sleep_api": the
same, for a verification that asks GitHub's API alone (no --bundle), and for `gh api` (GitHub's API stalls, Sigstore
does not); "sleep_for": {"<sha256 of a file>": <seconds>}, the same for that file's verification alone.  `gh --version`
says it is attest.GH_VERSION, as tools/gh.sh's gh does, or "version": what it prints instead."""
import base64, hashlib, json, os, re, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
from attest import GH_VERSION                   # (what it says it is: the one attest.py reads)
PREDICATE = "https://slsa.dev/provenance/v1"
ISSUER = "https://token.actions.githubusercontent.com"


def die(text):
    sys.stderr.write(text + "\n")
    sys.exit(1)


# ---- `gh api --include ... PATH` as tools/workflow.py asks it: GitHub's REST API for the files of the entry's
# commit and the refs of the actions' repositories.  cfg["api"]:
#   {"files": {"<path>": "<text>" | null},          the files at any commit of any repository (null: 404; a path not
#                                                   named: DEFAULT_FILES, an honest release.yml and build.yml, and
#                                                   actions/checkout's action.yml, a node action); "<owner>/<repo>:<path>"
#                                                   that repository's alone, "<owner>/<repo>@<commit>:<path>" at that
#                                                   commit alone (looked up first)
#    "repos": {"<owner>/<repo>": {"default": "<branch>", "branches": {name: sha}, "tags": {name: sha},
#                                 "history": {"<sha>": ["<sha it reaches>", ...]}}} | null (404),
#                                                   the actions' repositories (not named: DEFAULT_REPOS)
#    "status": {"<regex on the path>": <HTTP status>},   that answer instead (a rate limit, GitHub down)
#    "fail": "<text>",                              no HTTP answer at all: the text on stderr, status 1
#    "sleep": <seconds>,                            before it answers
#    "log": "<file>"}                               each path asked appended, one line each
# Printed as gh 2.105.0 prints with --include: the status line, headers ending in CRLF, a blank line, the body;
# status 1 and "gh: <message> (HTTP <n>)" on stderr for an answer of 4xx or 5xx
CHECKOUT = "3d3c42e5aac5ba805825da76410c181273ba90b1"          # actions/checkout v7's commit, the template's pin
DEFAULT_FILES = {
    ".github/workflows/release.yml": "name: release\non:\n  push:\n    tags: ['v*']\njobs:\n  checks:\n    uses: ./.github/workflows/build.yml\n"
                                     "  release:\n    needs: checks\n    runs-on: ubuntu-24.04\n    steps:\n"
                                     f"      - uses: actions/checkout@{CHECKOUT}  # v7\n      - run: make\n",
    ".github/workflows/build.yml": "name: build\non:\n  workflow_call:\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n"
                                  f"      - uses: actions/checkout@{CHECKOUT}  # v7\n      - run: make test\n",
    "actions/checkout:action.yml": "name: 'Checkout'\ndescription: >\n  Checks out.\nruns:\n  using: node24\n  main: dist/index.js\n"}
DEFAULT_REPOS = {"actions/checkout": {"default": "main", "branches": {"main": "9" * 40}, "tags": {"v7": CHECKOUT},
                                      "history": {"9" * 40: [CHECKOUT]}}}


def api(args, conf):
    import urllib.parse
    path = args[-1] if args else ""
    if conf.get("log"):
        with open(conf["log"], "a") as f:
            f.write(path + "\n")
    if conf.get("sleep"):
        time.sleep(conf["sleep"])
    if cfg.get("sleep_api"):
        time.sleep(cfg["sleep_api"])
    if "fail" in conf:
        die(conf["fail"])
    url = urllib.parse.urlsplit(path)
    q = dict(urllib.parse.parse_qsl(url.query))
    parts = url.path.split("/")

    def answer(code, body):
        sys.stdout.write(f"HTTP/2.0 {code} {'OK' if code == 200 else 'Not Found' if code == 404 else 'Error'}\n"
                         "Content-Type: application/json; charset=utf-8\r\nX-Github-Api-Version-Selected: 2022-11-28\r\n\r\n")
        sys.stdout.write(body if isinstance(body, str) else json.dumps(body))
        if code >= 400:
            sys.stdout.flush()
            die(f"gh: {'Not Found' if code == 404 else 'Error'} (HTTP {code})")
        sys.exit(0)
    for rx, code in (conf.get("status") or {}).items():
        if re.search(rx, path):
            answer(code, {"message": "stand-in", "status": str(code)})
    if parts[:1] != ["repos"] or len(parts) < 3:
        answer(404, {"message": "Not Found"})
    repo = "/".join(parts[1:3])
    if parts[3:4] == ["contents"]:
        files = dict(DEFAULT_FILES, **(conf.get("files") or {}))
        p = "/".join(parts[4:])
        k = next((k for k in (f"{repo}@{q.get('ref')}:{p}", f"{repo}:{p}", p) if k in files), p)
        text = files.get(k)
        answer(404, {"message": "Not Found"}) if text is None else answer(200, text)
    repos = dict(DEFAULT_REPOS, **(conf.get("repos") or {}))
    r = repos.get(repo)
    if r is None:
        answer(404, {"message": "Not Found"})
    if len(parts) == 3:
        answer(200, {"full_name": repo, "default_branch": r.get("default", "main")})
    if parts[3] in ("branches", "tags"):
        items = [{"name": n, "commit": {"sha": c}} for n, c in (r.get(parts[3]) or {}).items()]
        page, per = int(q.get("page", 1)), int(q.get("per_page", 30))
        answer(200, items[(page - 1) * per:page * per])
    if parts[3] == "compare":
        base, _, head = "/".join(parts[4:]).partition("...")
        status = "identical" if base == head else "behind" if head in (r.get("history") or {}).get(base, []) else "diverged"
        answer(200, {"status": status, "commits": []})
    answer(404, {"message": "Not Found"})


a = sys.argv[1:]
cfg = json.load(open(os.environ["INDEX_FAKE_GH"])) if os.environ.get("INDEX_FAKE_GH") else {"*": {}}
if a == ["--version"]:
    # as gh 2.105.0 says it (attest.gh_checked asks it once per process, before its first verify; not logged)
    sys.stdout.write(cfg.get("version", f"gh version {GH_VERSION} (2026-11-17)\nhttps://github.com/cli/cli/releases/tag/v{GH_VERSION}\n"))
    sys.exit(0)
if a[:1] == ["api"]:
    api(a[1:], cfg.get("api") or {})
if cfg.get("log"):
    with open(cfg["log"], "a") as f:
        f.write(json.dumps(a) + "\n")
if a[:2] != ["attestation", "verify"] or len(a) < 3:
    die(f"fake gh: not a command it knows: {a}")
path, flags, i = a[2], {}, 3
while i < len(a):
    if a[i] == "--deny-self-hosted-runners":
        flags[a[i]] = True
        i += 1
    else:
        flags[a[i]] = a[i + 1]
        i += 2
if cfg.get("sleep"):
    time.sleep(cfg["sleep"])
if cfg.get("sleep_api") and "--bundle" not in flags:
    time.sleep(cfg["sleep_api"])
if "--bundle" not in flags and hashlib.sha256(open(path, "rb").read()).hexdigest() in (cfg.get("sleep_for") or {}):
    time.sleep(cfg["sleep_for"][hashlib.sha256(open(path, "rb").read()).hexdigest()])
if "fail" in cfg:
    die(cfg["fail"])
if "raw" in cfg:
    sys.stdout.write(cfg["raw"])
    sys.exit(0)
data = open(path, "rb").read()
sha = hashlib.sha256(data).hexdigest()
repo = flags.get("--repo", "")


def statement(f):
    return {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": os.path.basename(path), "digest": {"sha256": f["subject"]}}],
            "predicateType": f["predicate"],
            "predicate": {"buildDefinition": {"buildType": "https://actions.github.io/buildtypes/workflow/v1",
                                              "externalParameters": {"workflow": {"path": f["caller"], "ref": f["ref"],
                                                                                  "repository": f"https://github.com/{f['repo']}"}},
                                              "internalParameters": {"github": {"event_name": f["trigger"], "runner_environment": f["runner"]}},
                                              "resolvedDependencies": [{"digest": {"gitCommit": f["commit"]}, "uri": f"git+https://github.com/{f['repo']}@{f['ref']}"}]}}}


# the workflow and the ref the flags ask for: attest.identity's regex, ^https://github\.com/(?i:<repo>)/<workflow>@<ref>$
asked = re.fullmatch(r"\^https://github\\\.com/\(\?i:[^)]*\)/(.*)@(refs/.*)\$", flags.get("--cert-identity-regex", ""))
ASKED_WORKFLOW = asked.group(1).replace("\\", "") if asked else ".github/workflows/release.yml"
ASKED_REF = flags.get("--source-ref") or (asked.group(2).replace("\\", "") if asked else "refs/tags/v1")


def resolved(f):
    f = dict(f)
    f.setdefault("repo", repo)
    f.setdefault("commit", flags.get("--source-digest", "0" * 40))
    f.setdefault("runner", "github-hosted")
    f.setdefault("signer_repo", f["repo"])
    f.setdefault("signer_commit", f["commit"])
    f.setdefault("issuer", ISSUER)
    f.setdefault("predicate", PREDICATE)
    f.setdefault("subject", sha)
    f.setdefault("workflow", ASKED_WORKFLOW)
    f.setdefault("caller", f["workflow"])
    f.setdefault("ref", ASKED_REF)
    f.setdefault("trigger", "push")
    f.setdefault("config_commit", f["commit"])
    return f


def bundle_of(f):
    payload = base64.b64encode(json.dumps(statement(f), separators=(",", ":")).encode()).decode()
    return {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"x-fake": f},
            "dsseEnvelope": {"payload": payload, "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "ZmFrZQ=="}]}}


def san(f):
    return f"https://github.com/{f['signer_repo']}/{f['workflow']}@{f['ref']}"


def result(f, bundle):
    wf, config = san(f), f"https://github.com/{f['repo']}/{f['caller']}@{f['ref']}"
    cert = {"certificateIssuer": "CN=sigstore-intermediate,O=sigstore.dev", "subjectAlternativeName": wf, "issuer": f["issuer"],
            "githubWorkflowTrigger": f["trigger"], "githubWorkflowSHA": f["config_commit"], "githubWorkflowName": "release",
            "githubWorkflowRepository": f["repo"], "githubWorkflowRef": f["ref"], "buildSignerURI": wf,
            "buildSignerDigest": f["signer_commit"], "runnerEnvironment": f["runner"], "sourceRepositoryURI": f"https://github.com/{f['repo']}",
            "sourceRepositoryDigest": f["commit"], "sourceRepositoryRef": f["ref"], "sourceRepositoryIdentifier": "1",
            "sourceRepositoryOwnerURI": f"https://github.com/{f['repo'].split('/')[0]}", "sourceRepositoryOwnerIdentifier": "2",
            "buildConfigURI": config, "buildConfigDigest": f["config_commit"], "buildTrigger": f["trigger"],
            "runInvocationURI": f"https://github.com/{f['repo']}/actions/runs/1/attempts/1", "sourceRepositoryVisibilityAtSigning": "public"}
    return {"attestation": {"bundle": bundle, "bundle_url": "", "initiator": ""},
            "verificationResult": {"mediaType": "application/vnd.dev.sigstore.verificationresult+json;version=0.1",
                                   "signature": {"certificate": cert},
                                   "verifiedTimestamps": [{"type": "Tlog", "uri": "https://rekor.sigstore.dev", "timestamp": "2026-11-22T00:00:00Z"}],
                                   "verifiedIdentity": {"subjectAlternativeName": {"subjectAlternativeName": "", "regexp": flags.get("--cert-identity-regex", f"(?i)^https://github\\.com/{repo}/")},
                                                        "issuer": {"issuer": "", "regexp": ".*"}},
                                   "statement": statement(f)}}


if "--bundle" in flags:
    found = []
    for line in open(flags["--bundle"], "rb").read().splitlines():
        b = json.loads(line)
        f = b.get("verificationMaterial", {}).get("x-fake")
        if not isinstance(f, dict):
            die("Error: failed to verify the bundle's signature (not one of the stand-in's)")
        found.append((f, b))
else:
    got = cfg.get(sha, cfg.get("*"))
    if got is None:
        die("Error: no attestations found")
    found = [(resolved(f), None) for f in (got if isinstance(got, list) else [got])]
    found = [(f, bundle_of(f)) for f, _ in found]


def why_not(f):
    """what gh 2.105.0 says against the attestation F under the flags, None where it passes"""
    if f["subject"] != sha:
        # (the API is asked by the file's digest; a bundle on file of another file's does not verify)
        return "Error: verifying with issuer \"sigstore.dev\"" if "--bundle" in flags else "Error: no attestations found"
    if f["predicate"] != flags.get("--predicate-type", PREDICATE):
        return f"Error: no attestations found with predicate type: {flags.get('--predicate-type', PREDICATE)}"
    if f["issuer"] != flags.get("--cert-oidc-issuer", ISSUER):
        return f"Error: expected Issuer to be {flags.get('--cert-oidc-issuer', ISSUER)}, got {f['issuer']}"
    if f["repo"].casefold() != repo.casefold():
        return f"Error: expected SourceRepositoryURI to be https://github.com/{repo}, got https://github.com/{f['repo']}"
    if "--source-digest" in flags and f["commit"] != flags["--source-digest"]:
        return f"Error: expected SourceRepositoryDigest to be {flags['--source-digest']}, got {f['commit']}"
    if "--source-ref" in flags and f["ref"] != flags["--source-ref"]:
        return f"Error: expected SourceRepositoryRef to be {flags['--source-ref']}, got {f['ref']}"
    if "--signer-repo" in flags and f["signer_repo"].casefold() != flags["--signer-repo"].casefold():
        return "Error: verifying with issuer \"sigstore.dev\""
    if "--cert-identity-regex" in flags and not re.search(flags["--cert-identity-regex"], san(f)):
        return "Error: verifying with issuer \"sigstore.dev\""
    if "--signer-digest" in flags and f["signer_commit"] != flags["--signer-digest"]:
        return f"Error: expected BuildSignerDigest to be {flags['--signer-digest']}, got {f['signer_commit']}"
    if flags.get("--deny-self-hosted-runners") and f["runner"] != "github-hosted":
        return "Error: expected RunnerEnvironment to be github-hosted"
    return None


out = []
last = None
for f, b in found:
    w = None if cfg.get("mode") == "lie" else why_not(f)
    if w:
        last = w
    else:
        out.append(result(f, b))
if not out:
    die(last or "Error: no attestations found")
sys.stdout.write(json.dumps(out, indent=2) + "\n")
