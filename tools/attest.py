#!/usr/bin/env python3
"""Whether a package is what its plugin's own repository built in GitHub Actions at the commit the entry names, in
the workflow the entry names, for the push of the tag its release is under (hassmic's docs/plugins.md 5.3): a
GitHub artifact attestation (build provenance, Sigstore), made by actions/attest-build-provenance in the plugin's
release workflow, verified with GitHub's own CLI and then read again here, field by field.  index.py build asks this
before it lists a version, official or community: one path.

What has to hold, for an attestation of the package (each one that does not is said, and not kept):
  - the subject: one of the statement's subjects is the package, by its SHA-256 (the bytes as the release has them);
  - SLSA provenance v1 in an in-toto statement, signed by a certificate of GitHub Actions' OIDC issuer;
  - the source repository is the entry's `source` (https://github.com/<owner>/<repo>), and its commit the entry's
    `commit`: the run was of that commit;
  - the run was the push of the tag the release asset is under (the entry's `package`,
    https://github.com/<owner>/<repo>/releases/download/<tag>/<asset>): its trigger is "push" (buildTrigger, and
    githubWorkflowTrigger where it is there) and its ref refs/tags/<tag> (sourceRepositoryRef, githubWorkflowRef):
    not a run started by hand (workflow_dispatch: any workflow at any ref a writer of the repository names), not a
    branch, not another tag's release;
  - the signing workflow (the job that ran the attestation step, Fulcio's buildSignerURI, the certificate's SAN) and
    the workflow the run was started for (buildConfigURI) are both exactly the entry's `workflow` at that tag,
    https://github.com/<owner>/<repo>/<workflow>@refs/tags/<tag>, at that same commit (buildSignerDigest,
    buildConfigDigest): not another workflow of the repository (a second one that downloads a package and attests
    it), not the named one called by another (workflow_call: buildSignerURI is then the callee, buildConfigURI the
    caller, whose inputs steer it), not a reusable workflow of another repository.  A local reusable workflow the
    named one calls (release.yml's `uses: ./.github/workflows/build.yml`) is no signer: the attestation step runs in
    the named workflow's own job, so both URIs are the named one's;
  - the job ran on a runner GitHub hosts (runnerEnvironment "github-hosted"): a self-hosted one is the repository
    owner's machine, and what it says it built is that machine's word.
What it proves: GitHub's CI ran that workflow file of that commit, for that tag's push, on GitHub's machine, and that
run made these bytes.  What it does not: what the workflow does.  A workflow can download a program from anywhere and
attest it; the maintainer reads the workflow the entry names at that commit, and everything it runs (the local
workflows it calls, the scripts and make targets of its steps, the actions it uses), in the entry's pull request
(README.md "Where a package comes from").  Nothing of what goes into the package may come from outside that commit:
no action (`uses:`) not pinned by a commit of the action's own repository (one on its tags or branches: GitHub runs a
fork's commit under the original's name too, an impostor commit, which the index refuses), all the way down (a
composite action's own steps, a called workflow's, a docker action's image and its Dockerfile's `FROM`, by the same
rule), no artifact of another job or run (one only to compare a build of its own with), no other job's outputs
(`needs.*.outputs`) but a SHA-256 to compare with, nothing of the event's payload (`github.event.*`; a tag's
annotation is not in the commit) but the tag's name, no other repository checked out at a ref that moves (a branch or
a tag; a commit's id stays), no container image (`container:`, `docker://`) not pinned by its digest, no cache
(`actions/cache`, the caches `setup-*` actions keep, which other runs write), no `vars` and no secret as an input
(the signing key aside, which only the release job's environment holds: no other job names an environment, whose
secrets it would get), no release asset already there, no toolchain resolved online by a channel (rustup's `stable`,
`beta` or `nightly`, in a `rust-toolchain.toml` or on its command line), and no download not pinned by its hash; and
a re-run of an old run, which GitHub attests as that tag's push again, has to make the same bytes.  A package
uploaded by hand, or built anywhere else, has no such attestation, and is refused.

gh is asked with every rule it has a flag for (COMMAND: gh attestation verify --repo --source-digest --source-ref
--cert-identity-regex --signer-digest --deny-self-hosted-runners --predicate-type --cert-oidc-issuer --format json;
the identity's regex is the signing workflow's URI exactly, the repository's name in any case as GitHub takes it:
--signer-repo and --signer-workflow cannot go with it, and the latter is a prefix), and its answer is not taken on
its exit status alone: the JSON it prints is read here and every field held to the entry again (judge), the ones gh
has no flag for too (the trigger, buildConfigURI and its digest).  Without --bundle, gh asks GitHub's API for the
repository's attestations: that is the repository that has that name now (gh's own words: a bundle on disk cannot
tell a repository renamed, or a name taken by another since).  A version the published site lists already is
verified again with the bundle the site keeps (BUNDLE: gh --bundle), which needs no API (Sigstore's trust root it
still fetches): what was the repository's when it was first listed stays so.

Two kinds of no (index.py build treats them apart):
  Refused       a verdict: the attestation does not say what it must, or gh says so (no attestation for the file, a
                field that is not what the flags ask: the words gh 2.105.0 prints for them, VERDICTS), or something a
                plugin's own repository can make (more than gh may print, JSON nested past what Python reads).  The
                version is left out (an error in a pull request's check).
  Unavailable   no verdict: gh missing, not tools/gh.sh's version (gh --version, asked once: VERDICTS are that
                version's words, and another's no would be read as none or its none as a no), failing in another way
                (the network, Sigstore's trust root, GitHub's API answering anything but 404, a gh that words its
                errors otherwise), too slow, or printing what gh does not print.  index.py build fails where the
                published site lists the version (an outage never takes a version off the index), and in a pull
                request's check; a publish leaves a new version out, said as no verdict (a later publish lists it: one
                plugin's attestations, or GitHub's API, out of reach for a version not listed yet never holds back the
                rest, the revocation list least of all).
A Refused of a version the published site lists, verified again with the site's own BUNDLE (which held when it was
listed, for the same bytes), is no verdict either: index.py build (attested) takes it as Unavailable, since what
changed is gh, Sigstore's trust root or this reading, never the release; a listed version leaves the index only by a
person's step (the revocation list, the entry).  gh is the release tools/gh.sh downloads by its SHA-256 (index.yml),
the version whose words VERDICTS are, and any other is no verdict wherever this runs (gh_checked: a PC's gh, the
runner's own where INDEX_GH was lost; a review of 17c2e8c).

The bundle kept is that of the one attestation that held (the first in gh's answer, within BUNDLE_MAX), one JSON
line, as gh printed what it verified: the site publishes it beside the package (packages/<id>-<version>.hmp.sigstore
.jsonl), so that anyone can verify the release asset again with the same command and `--bundle <that file>`
(command(): what the site's page shows).  One that held but is larger than a site keeps is not kept; where none
fits, the version is refused (left out), never one that would fail the site's own check at signing.

The CLI is a seam: INDEX_GH names another program than `gh` (tools/gh.sh's in index.yml; the tests' stand-in,
tests/fake_gh.py, which answers from recorded and made-up JSON and says it is GH_VERSION; no network in the tests).
Python's standard library only."""
import base64, json, os, re, subprocess

ISSUER = "https://token.actions.githubusercontent.com"
PREDICATE = "https://slsa.dev/provenance/v1"
STATEMENT = re.compile(r"https://in-toto\.io/Statement/v[01](\.[0-9]+)?")
# a GitHub repository's address, as an entry's source has to be: owner (GitHub's rule: letters, digits, single
# hyphens, 39 at most) and repository name, nothing after
GITHUB = re.compile(r"https://github\.com/([A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38})/([A-Za-z0-9._-]{1,100})")
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
# a workflow file as GitHub runs one: directly in .github/workflows/ (GitHub reads no folder below it), .yml or .yaml
WORKFLOW = re.compile(r"\.github/workflows/[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}\.ya?ml")
TAG = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}")      # as index.py's: a release's tag in its asset's address
TRIGGER = "push"                                # the run of a tag's push; nothing started by hand or by another workflow
SECONDS = 180                                   # one gh run, all of it (the API and Sigstore's trust root)
OUT_MAX = 32 << 20                              # what gh may print: 30 attestations with their bundles fit
BUNDLE_MAX = 4 << 20                            # what the site keeps per package (and verify reads)
SUFFIX = ".sigstore.jsonl"                      # the bundle's file beside a package: <id>-<version>.hmp.sigstore.jsonl
# gh's words when it decided against the attestations (gh 2.105.0, each seen from the real gh: no attestation for
# the file, a certificate's field not what a flag asks, the identity (SAN) not the one asked or a signature that does
# not hold, GitHub's API saying the repository is not there): its last line, from its start.  Anything else it
# fails with is no verdict (Unavailable): a gh that words these otherwise fails the build, it never drops a version
VERDICTS = (re.compile(r"Error: no attestations found\b"), re.compile(r"Error: expected [A-Za-z]+ to be "),
            re.compile(r'Error: verifying with issuer "sigstore\.dev"$'), re.compile(r"Error: HTTP 404: "))


# the gh whose words VERDICTS are, tools/gh.sh's VERSION (tests/test_workflow.py holds the two together): gh_checked
# asks every other gh's --version once and takes none of its answers
GH_VERSION = "2.105.0"


class Refused(Exception):
    """a verdict: the attestation does not say what it must (the version is left out)"""


class Unavailable(Exception):
    """no verdict: gh could not be asked, or did not answer as gh answers (index.py build: an error where the site
    lists the version, and in a pull request's check)"""


def repo_of(source):
    """"owner/repo" of a source address https://github.com/<owner>/<repo>, None for anything else (another host, a
    path after the repository, a name GitHub does not give)"""
    m = GITHUB.fullmatch(source) if isinstance(source, str) else None
    if not m or m.group(2) in (".", "..") or m.group(2).endswith(".git"):
        return None
    return f"{m.group(1)}/{m.group(2)}"


def signer(repo, workflow, tag):
    """the URI the certificate names the workflow by (buildSignerURI, buildConfigURI, the SAN): the workflow file at
    the tag's ref"""
    return f"https://github.com/{repo}/{workflow}@refs/tags/{tag}"


def identity(repo, workflow, tag):
    """gh's --cert-identity-regex for signer(): that URI and nothing else, the repository's name in any case (GitHub
    takes one in any case, and its certificate spells it as the repository does)"""
    q = lambda t: re.sub(r"([.\\+*?()\[\]{}|^$])", r"\\\1", t)      # (RE2's metacharacters; only "." occurs in what passed the rules)
    return f"^https://github\\.com/(?i:{q(repo)})/{q(workflow)}@refs/tags/{q(tag)}$"


def gh_program():
    return os.environ.get("INDEX_GH") or "gh"


_checked = {}


def gh_checked(gh):
    """Unavailable unless GH says it is GH_VERSION (its --version's first line "gh version <it> (<date>)"); asked once
    per program and process.  index.yml names tools/gh.sh's by INDEX_GH; where that is lost (a later step, a PC) the
    gh found is the runner's or the PC's, whose words may be other ones: no verdict from it, never one read wrongly"""
    if gh not in _checked:
        try:
            r = subprocess.run([gh, "--version"], stdin=subprocess.DEVNULL, capture_output=True, timeout=30,
                               env=dict(os.environ, GH_NO_UPDATE_NOTIFIER="1", NO_COLOR="1"))
            line = (r.stdout.decode(errors="replace").splitlines() or [""])[0].strip()
            ok = r.returncode == 0 and re.fullmatch(r"gh version " + re.escape(GH_VERSION) + r"( \(.*\))?", line)
            _checked[gh] = "" if ok else "".join(c if " " <= c < "\x7f" else "?" for c in line)[:80] or f"status {r.returncode}"
        except FileNotFoundError:
            raise Unavailable(f"no {gh} here (GitHub's CLI: it verifies the attestation; INDEX_GH names another)")
        except (OSError, subprocess.SubprocessError) as x:
            _checked[gh] = str(x)[:80]
    if _checked[gh]:
        raise Unavailable(f"{gh} is not gh {GH_VERSION}, whose words this reads ({_checked[gh]}): tools/gh.sh's, named by INDEX_GH")


def argv(gh, package, repo, commit, workflow, tag, bundle=None):
    """gh's command line: every rule gh has a flag for (judge reads its answer again all the same, and holds it to
    the ones gh has none for).  --signer-repo and --signer-workflow cannot go with --cert-identity-regex"""
    a = [gh, "attestation", "verify", package, "--repo", repo, "--source-digest", commit, "--source-ref", f"refs/tags/{tag}",
         "--cert-identity-regex", identity(repo, workflow, tag), "--signer-digest", commit, "--deny-self-hosted-runners",
         "--predicate-type", PREDICATE, "--cert-oidc-issuer", ISSUER, "--format", "json"]
    return a + (["--bundle", bundle] if bundle else [])


def command(package, repo, commit, workflow, tag, bundle=None):
    """the command line as a reader runs it (the site's page, the README): the very flags the index gives gh, quoted
    for a shell"""
    def sh(t):
        return t if re.fullmatch(r"[A-Za-z0-9_./:=@-]+", t) else "'" + t.replace("'", "'\\''") + "'"
    return " ".join(sh(x) for x in ["gh"] + argv("gh", package, repo, commit, workflow, tag, bundle)[1:])


# one gh that took more than its time (SECONDS) is said once and every later call of the same kind in the same run is
# no verdict at once, each named: the network or GitHub that kept one waiting keeps the next waiting as long, and the
# publish job's timeout (index.yml, 10 minutes then, 30 now) would end the run with no version named after three or four (a review
# of dc75e14).  Two kinds, each its own (a review of 810b9e9: one stalled call of GitHub's API for a new version held
# back every listed one, and the revocation list with them): "api", what asks GitHub's API (gh attestation verify
# without --bundle, gh api), and "bundle", the verification of a bundle the published site keeps, which asks no API
# (only Sigstore's trust root)
_stalled = {}


def not_stalled(kind="api"):
    """Unavailable where a gh call of KIND of this run already took more than its time"""
    if _stalled.get(kind):
        raise Unavailable(f"not asked: {_stalled[kind]} earlier in this run (no verdict; run it again)")


def run_cli(a, seconds, what, kind="api"):
    """(exit status, stdout, stderr) of gh's command line A, within SECONDS; Unavailable where it could not be run or
    took too long (and every later call of its KIND then, not_stalled).  Its environment is the caller's (GH_TOKEN
    for the API), with nothing that would make it ask a person or print colour"""
    not_stalled(kind)
    env = dict(os.environ, GH_PROMPT_DISABLED="1", GH_NO_UPDATE_NOTIFIER="1", NO_COLOR="1", GH_SPINNER_DISABLED="1")
    try:
        r = subprocess.run(a, stdin=subprocess.DEVNULL, capture_output=True, timeout=seconds, env=env)
    except FileNotFoundError:
        raise Unavailable(f"no {a[0]} here (GitHub's CLI: it verifies the attestation; INDEX_GH names another)")
    except subprocess.TimeoutExpired:
        _stalled[kind] = f"{what} took more than {seconds} s"
        raise Unavailable(_stalled[kind])
    except (OSError, subprocess.SubprocessError) as x:
        raise Unavailable(f"{what}: {x}")
    return r.returncode, r.stdout, r.stderr


def run_gh(a):
    """gh's stdout; Refused where gh decided against it (VERDICTS) or printed more than it may, Unavailable where it
    could not be run, took too long (run_cli) or failed in any other way"""
    bundle = "--bundle" in a
    code, out, err = run_cli(a, SECONDS, f"{os.path.basename(a[0])} attestation verify" + (" --bundle" if bundle else ""),
                             "bundle" if bundle else "api")
    if code != 0:
        why = err.decode(errors="replace").strip().splitlines()
        # (its last line names what failed; control characters out of what goes into a CI log)
        line = next((x.strip() for x in reversed(why) if x.strip()), f"status {code}")
        said = "gh attestation verify failed: " + "".join(c if " " <= c < "\x7f" else "?" for c in line)[:300]
        if any(v.match(line) for v in VERDICTS):
            raise Refused(said)
        raise Unavailable(said + " (no verdict on the attestation: the network, Sigstore, GitHub's API, or gh itself)")
    if len(out) > OUT_MAX:
        # (as many attestations as the repository makes, each as large as it makes it: its own doing)
        raise Refused(f"gh attestation verify printed more than {OUT_MAX >> 20} MB")
    return out


def _s(d, *path):
    """the text at PATH in nested objects D, "" where it is not a text"""
    for k in path:
        d = d.get(k) if isinstance(d, dict) else None
    return d if isinstance(d, str) else ""


def judge(results, sha256, repo, commit, workflow, tag):
    """gh's JSON answer (RESULTS, parsed) held to the entry: the bundles of every result that keeps every rule, and
    for each one that does not, why.  -> (kept bundles, reasons).  Unavailable where the answer is not the list of
    verified attestations gh prints on success (it never prints an empty one)"""
    if not isinstance(results, list) or not results:
        raise Unavailable("gh's answer, status 0, is not the list of verified attestations gh prints: " + (type(results).__name__ if results != [] else "an empty one"))
    kept, why = [], []
    url = f"https://github.com/{repo}".casefold()
    want = signer(repo, workflow, tag)
    head, tail = len(f"https://github.com/{repo}/"), f"/{workflow}@refs/tags/{tag}"

    def named(uri):
        # this repository's (in any case, as GitHub's names are), then the workflow file and the tag exactly
        return uri.casefold().startswith(url + "/") and uri[head - 1:] == tail

    ref = f"refs/tags/{tag}"
    for i, r in enumerate(results):
        def no(reason):
            why.append(f"attestation {i + 1}: {reason}")
        if not isinstance(r, dict) or not isinstance(r.get("verificationResult"), dict) or not isinstance(r.get("attestation"), dict):
            no("not a verified attestation as gh prints one")
            continue
        vr = r["verificationResult"]
        cert = (vr.get("signature") or {}).get("certificate") if isinstance(vr.get("signature"), dict) else None
        st = vr.get("statement")
        bundle = r["attestation"].get("bundle")
        if not isinstance(cert, dict) or not isinstance(st, dict) or not isinstance(bundle, dict):
            no("no certificate, statement or bundle in it")
            continue
        subjects = st.get("subject") if isinstance(st.get("subject"), list) else []
        digests = [_s(x, "digest", "sha256") for x in subjects]
        if not STATEMENT.fullmatch(_s(st, "_type")) or _s(st, "predicateType") != PREDICATE:
            no(f"not SLSA provenance v1 in an in-toto statement ({_s(st, 'predicateType')[:80] or 'none'})")
        elif sha256 not in digests:
            no(f"its subjects are other files than this package (SHA-256 {sha256[:16]}...: not among {len(digests)})")
        elif _s(cert, "issuer") != ISSUER:
            no(f"not signed for GitHub Actions (issuer {_s(cert, 'issuer')[:80] or 'none'})")
        elif _s(cert, "sourceRepositoryURI").casefold() != url:
            no(f"built from another repository ({_s(cert, 'sourceRepositoryURI')[:120] or 'none'}), not {url}")
        elif _s(cert, "sourceRepositoryDigest") != commit:
            no(f"built from another commit ({_s(cert, 'sourceRepositoryDigest')[:40] or 'none'}), not {commit}")
        elif _s(cert, "runnerEnvironment") != "github-hosted":
            no(f"not built on a runner GitHub hosts ({_s(cert, 'runnerEnvironment')[:40] or 'none'}): a self-hosted runner is its owner's machine")
        elif _s(cert, "buildTrigger") != TRIGGER or _s(cert, "githubWorkflowTrigger") not in ("", TRIGGER):
            no(f"a run started by {_s(cert, 'buildTrigger')[:40] or _s(cert, 'githubWorkflowTrigger')[:40] or 'nothing it names'}, "
               f"not by the push of the tag {tag} (a run by hand names any workflow at any ref)")
        elif _s(cert, "sourceRepositoryRef") != ref or _s(cert, "githubWorkflowRef") not in ("", ref):
            no(f"a run of {_s(cert, 'sourceRepositoryRef')[:80] or 'no ref'}, not of the tag {tag} the release asset is under")
        elif not named(_s(cert, "buildSignerURI")) or _s(cert, "githubWorkflowRepository").casefold() != repo.casefold():
            no(f"signed by another workflow ({_s(cert, 'buildSignerURI')[:160] or 'none'}) than the entry's, {want}")
        elif _s(cert, "buildSignerDigest") != commit:
            no(f"signed by the workflow of another commit ({_s(cert, 'buildSignerDigest')[:40] or 'none'}), not {commit}")
        elif not named(_s(cert, "buildConfigURI")) or _s(cert, "buildConfigDigest") != commit:
            no(f"a run of another workflow ({_s(cert, 'buildConfigURI')[:160] or 'none'} at {_s(cert, 'buildConfigDigest')[:12] or 'none'}) "
               f"that calls the entry's: the run has to be {want}'s own")
        else:
            kept.append(bundle)
    return kept, why


def verify(package, source, commit, sha256, workflow, tag, bundle=None):
    """the bundle (one JSON line) of an attestation that says the file PACKAGE (whose SHA-256 is SHA256) was built by
    a GitHub-hosted run of SOURCE's WORKFLOW for the push of the tag TAG, at COMMIT; Refused with why where none
    does, Unavailable where gh gave no verdict.  BUNDLE: a file of bundles to verify against instead of the API (the
    published site's, for a version it lists already)"""
    repo = repo_of(source)
    if repo is None:
        raise Refused(f"the source {str(source)[:120]} is no GitHub repository: only GitHub's attestations are read")
    if (not isinstance(commit, str) or not COMMIT.fullmatch(commit) or not isinstance(sha256, str) or not SHA256.fullmatch(sha256)
            or not isinstance(workflow, str) or not WORKFLOW.fullmatch(workflow) or not isinstance(tag, str) or not TAG.fullmatch(tag)):
        raise Refused("the commit, the package's SHA-256, the workflow or the tag is not one")
    gh_checked(gh_program())
    out = run_gh(argv(gh_program(), package, repo, commit, workflow, tag, bundle))
    try:
        results = json.loads(out)
    except RecursionError:
        # (nested past Python's reading: what a repository's own predicate can be)
        raise Refused("gh's answer is nested deeper than it is read")
    except ValueError as x:
        raise Unavailable(f"gh's answer, status 0, is no JSON: {str(x)[:120]}")
    kept, why = judge(results, sha256, repo, commit, workflow, tag)
    # the one that held, as the site keeps it: the first whose line a site takes (a larger one is never one the
    # site's own check would refuse at signing, index.py verify)
    lines = [json.dumps(b, separators=(",", ":"), ensure_ascii=False).encode() + b"\n" for b in kept]
    fits = [x for x in lines if len(x) <= BUNDLE_MAX]
    if lines and not fits:
        why.append(f"the attestations that hold are larger than the {BUNDLE_MAX >> 20} MB a site keeps of one")
    if not fits:
        raise Refused("no attestation that " + repo + "'s " + workflow + " built it for the tag " + tag + " at " + commit[:12] + ": " + "; ".join(why[:3]))
    return fits[0]


def subjects(data):
    """the SHA-256 digests the bundle DATA (JSON lines, as verify keeps it: one) names as its subjects, read without
    checking a signature (index.py verify: the site's bundles are the ones of the packages it lists; their
    signatures are gh's to check, again, by anyone).  ValueError for what is not such a file"""
    if not data or len(data) > BUNDLE_MAX or not data.endswith(b"\n"):
        raise ValueError("no bundles, or more than a site keeps")
    found = set()
    for line in data.split(b"\n")[:-1]:
        b = json.loads(line)
        env = b.get("dsseEnvelope") if isinstance(b, dict) else None
        payload = env.get("payload") if isinstance(env, dict) else None
        if not isinstance(payload, str):
            raise ValueError("a line that is no attestation bundle (no DSSE envelope)")
        st = json.loads(base64.b64decode(payload, validate=True))
        if not isinstance(st, dict) or st.get("predicateType") != PREDICATE or not isinstance(st.get("subject"), list):
            raise ValueError("a bundle that is no SLSA provenance v1")
        found |= {_s(x, "digest", "sha256") for x in st["subject"]} - {""}
    return found
