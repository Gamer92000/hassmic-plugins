#!/usr/bin/env python3
"""tools/attest.py: a package's GitHub artifact attestation, as gh verifies it and as this index reads gh's answer
again (hassmic's docs/plugins.md 5.3).  No network: gh is tests/fake_gh.py (INDEX_GH), which answers from made-up
attestations, and the reading is also held to a real answer of gh 2.105.0 (tests/gh-verify-cli.json: GitHub's CLI's
own release asset gh_2.105.0_linux_arm64.tar.gz, attested by cli/cli's deployment workflow).

The real answer is a run started by hand (workflow_dispatch) from a branch (refs/heads/trunk): REFUSED now, whatever
workflow and tag it is held to (an attestation has to be the entry's workflow's own run for the push of the release's
tag); the same answer turned into a tag's push (its trigger, refs and URIs, nothing else) is the one taken, and every
mutation below starts from that.

Each rule refused one at a time, both ways: where gh itself refuses (the flags attest.py gives it), and where a gh
that lies (status 0, every attestation "verified", whatever the flags) is caught by attest.judge reading the JSON:
no attestation, another repository, another commit, another file, a self-hosted runner, a signing workflow of another
repository or of another commit, another workflow of the same repository, the named one called by another, a run by
hand, a branch, another tag, another issuer or predicate.  gh's own no's (a verdict: Refused) apart from its failures
(no verdict: Unavailable): gh missing, too slow, the network, Sigstore's trust root, GitHub's API failing, an answer
that is no JSON or not the list gh prints.  Then the bundle kept: one, within what a site keeps, verified again from
the file alone (--bundle), and read by subjects()."""
import copy, hashlib, json, os, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tools"))
import attest

failed = False
def check(cond, what):
    global failed
    print(("ok   " if cond else "FAIL ") + what)
    failed |= not cond


top = tempfile.mkdtemp(prefix="attest-test-")
FAKE = os.path.join(HERE, "fake_gh.py")
os.environ["INDEX_GH"] = FAKE
CFG, LOG = os.path.join(top, "gh.json"), os.path.join(top, "gh.log")
SOURCE, REPO, C = "https://github.com/someone/hassmic-plugin-example", "someone/hassmic-plugin-example", "a" * 40
pkg = os.path.join(top, "example-1.hmp")
open(pkg, "wb").write(b"a package's bytes")
SHA = hashlib.sha256(b"a package's bytes").hexdigest()


def gh(cfg):
    cfg = dict(cfg, log=LOG)
    open(CFG, "w").write(json.dumps(cfg))
    os.environ["INDEX_FAKE_GH"] = CFG
    if os.path.exists(LOG):
        os.unlink(LOG)


# ---- the real answer of gh 2.105.0, read
real = json.load(open(os.path.join(HERE, "gh-verify-cli.json")))
RSHA, RREPO, RC = "b1278c75107423d818f1937fd92cafc9e5e9b606631568f68d7fb816f5885a02", "cli/cli", "e1219499a578b69e3437adaa31cd60614e23c802"
RWF, RTAG = ".github/workflows/deployment.yml", "v2.105.0"
k, w = attest.judge(real, RSHA, RREPO, RC, RWF, RTAG)
check(not k and w and "workflow_dispatch" in w[0] and "not by the push of the tag" in w[0],
      f"gh 2.105.0's real answer (cli/cli's own release asset, a run by hand from refs/heads/trunk): REFUSED now ({w[0] if w else 'taken'})")
cert = lambda vr: vr["signature"]["certificate"]


def tagged(r):
    """the real answer as the push of the tag RTAG would have made it: trigger, refs and URIs, nothing else"""
    r = copy.deepcopy(r)
    c = cert(r[0]["verificationResult"])
    uri = f"https://github.com/cli/cli/{RWF}@refs/tags/{RTAG}"
    c.update(githubWorkflowTrigger="push", buildTrigger="push", githubWorkflowRef=f"refs/tags/{RTAG}", sourceRepositoryRef=f"refs/tags/{RTAG}",
             buildSignerURI=uri, buildConfigURI=uri, subjectAlternativeName=uri)
    return r


tag_real = tagged(real)
k, w = attest.judge(real, RSHA, RREPO, RC, RWF, "trunk")
check(not k and w and "workflow_dispatch" in w[0], "the real answer held to the branch's name as if it were a tag: refused all the same (a run by hand)")
kept, why = attest.judge(tag_real, RSHA, RREPO, RC, RWF, RTAG)
check(len(kept) == 1 and why == [], f"the real answer turned into the push of {RTAG} (trigger, refs, URIs): its attestation kept ({why})")
data = b"".join(json.dumps(b, separators=(",", ":")).encode() + b"\n" for b in kept)
check(RSHA in attest.subjects(data), "its bundle, as the site keeps it, names the asset's SHA-256 among its subjects")
for what, args, said in (("another repository", (RSHA, "cli/go-gh", RC, RWF, RTAG), "built from another repository"),
                         ("another commit", (RSHA, RREPO, "f" * 40, RWF, RTAG), "another commit"),
                         ("another file", ("0" * 64, RREPO, RC, RWF, RTAG), "other files"),
                         ("another workflow of the same repository", (RSHA, RREPO, RC, ".github/workflows/release.yml", RTAG), "signed by another workflow"),
                         ("another tag than the one the release asset is under", (RSHA, RREPO, RC, RWF, "v2.104.0"), "not of the tag v2.104.0"),
                         ("the repository's name in other letters (GitHub's names are one in any case)", (RSHA, "CLI/Cli", RC, RWF, RTAG), None)):
    k, w = attest.judge(tag_real, *args)
    check((not k and w and said in w[0]) if said else (len(k) == 1), f"the answer held to {what}: {('refused, ' + w[0] if w else 'taken') if said else 'taken'}")


def mutated(change):
    r = copy.deepcopy(tag_real)
    change(r[0]["verificationResult"])
    return attest.judge(r, RSHA, RREPO, RC, RWF, RTAG)


U = lambda p: f"https://github.com/cli/cli/{p}"
for what, change, said in (
        ("a self-hosted runner", lambda vr: cert(vr).update(runnerEnvironment="self-hosted"), "self-hosted"),
        ("another source repository alone (this repository's workflow, called by another's)",
         lambda vr: cert(vr).update(sourceRepositoryURI="https://github.com/evil/cli"), "built from another repository"),
        ("no runner said", lambda vr: cert(vr).pop("runnerEnvironment"), "runner GitHub hosts"),
        ("a run started by hand (workflow_dispatch), all else a tag's push", lambda vr: cert(vr).update(buildTrigger="workflow_dispatch"), "workflow_dispatch"),
        ("a run started by hand, said only by the older field (githubWorkflowTrigger)", lambda vr: cert(vr).update(githubWorkflowTrigger="workflow_dispatch"), "not by the push"),
        ("a run of a pull request", lambda vr: cert(vr).update(buildTrigger="pull_request_target", githubWorkflowTrigger="pull_request_target"), "pull_request_target"),
        ("no trigger said", lambda vr: [cert(vr).pop(x) for x in ("buildTrigger", "githubWorkflowTrigger")], "not by the push"),
        ("a branch's run (refs/heads/main), the URIs too", lambda vr: cert(vr).update(sourceRepositoryRef="refs/heads/main", githubWorkflowRef="refs/heads/main",
                                                                                       buildSignerURI=U(RWF + "@refs/heads/main"), buildConfigURI=U(RWF + "@refs/heads/main")),
         "refs/heads/main"),
        ("another tag's run", lambda vr: cert(vr).update(sourceRepositoryRef="refs/tags/v1", githubWorkflowRef="refs/tags/v1",
                                                         buildSignerURI=U(RWF + "@refs/tags/v1"), buildConfigURI=U(RWF + "@refs/tags/v1")), "not of the tag"),
        ("the URIs the tag's, the source's ref a branch (sourceRepositoryRef)", lambda vr: cert(vr).update(sourceRepositoryRef="refs/heads/main"), "refs/heads/main"),
        ("the tag's ref, the workflow at a branch (githubWorkflowRef)", lambda vr: cert(vr).update(githubWorkflowRef="refs/heads/main"), "not of the tag"),
        ("the tag's ref, the signing workflow's URI at a branch", lambda vr: cert(vr).update(buildSignerURI=U(RWF + "@refs/heads/main")), "signed by another workflow"),
        ("another workflow of the same repository (a second one that attests a download)",
         lambda vr: cert(vr).update(buildSignerURI=U(".github/workflows/x.yml@refs/tags/" + RTAG), buildConfigURI=U(".github/workflows/x.yml@refs/tags/" + RTAG)),
         "signed by another workflow"),
        ("a workflow whose name begins as the entry's", lambda vr: cert(vr).update(buildSignerURI=U(RWF + "x@refs/tags/" + RTAG)), "signed by another workflow"),
        ("the entry's workflow in other letters", lambda vr: cert(vr).update(buildSignerURI=U(RWF.replace("deployment", "Deployment") + "@refs/tags/" + RTAG)),
         "signed by another workflow"),
        ("the entry's workflow called by another (buildConfigURI: the caller, whose inputs steer it)",
         lambda vr: cert(vr).update(buildConfigURI=U(".github/workflows/caller.yml@refs/tags/" + RTAG)), "that calls the entry's"),
        ("the run's own workflow at another commit (buildConfigDigest)", lambda vr: cert(vr).update(buildConfigDigest="f" * 40), "that calls the entry's"),
        ("no buildConfigURI", lambda vr: cert(vr).pop("buildConfigURI"), "that calls the entry's"),
        ("a signing workflow of another repository (a reusable workflow)",
         lambda vr: cert(vr).update(buildSignerURI="https://github.com/evil/actions/.github/workflows/build.yml@refs/heads/main", githubWorkflowRepository="evil/actions"),
         "signed by another workflow"),
        ("a signing workflow whose URI names this repository but whose workflow repository is another",
         lambda vr: cert(vr).update(githubWorkflowRepository="evil/actions"), "signed by another workflow"),
        ("a signing workflow of a repository whose name begins as this one's",
         lambda vr: cert(vr).update(buildSignerURI=f"https://github.com/cli/cli-evil/{RWF}@refs/tags/{RTAG}"), "signed by another workflow"),
        ("the signing workflow of another commit", lambda vr: cert(vr).update(buildSignerDigest="f" * 40), "another commit"),
        ("another issuer", lambda vr: cert(vr).update(issuer="https://accounts.google.com"), "GitHub Actions"),
        ("another predicate", lambda vr: vr["statement"].update(predicateType="https://example.com/anything"), "SLSA"),
        ("no in-toto statement", lambda vr: vr["statement"].update(_type="https://example.com/Statement"), "SLSA"),
        ("no certificate", lambda vr: vr["signature"].pop("certificate"), "no certificate"),
        ("subjects that are no list", lambda vr: vr["statement"].update(subject={"digest": {"sha256": RSHA}}), "other files")):
    k, w = mutated(change)
    check(not k and w and said in w[0], f"refused: {what} ({w[0] if w else 'taken'})")
for what, results in (("an empty list", []), ("an object", {"verificationResult": {}})):
    try:
        attest.judge(results, RSHA, RREPO, RC, RWF, RTAG)
        got = "taken"
    except attest.Unavailable as x:
        got = "unavailable: " + str(x)
    check(got.startswith("unavailable"), f"gh's answer is {what} (gh never prints that on success): no verdict, Unavailable ({got[:120]})")
for what, results in (("a list of texts", ["x"]), ("a result without its bundle", [dict(tag_real[0], attestation={})])):
    k, w = attest.judge(results, RSHA, RREPO, RC, RWF, RTAG)
    check(not k and w, f"refused: gh's answer is {what} ({w[0] if w else 'taken'})")
two = [copy.deepcopy(tag_real[0]), copy.deepcopy(tag_real[0])]
cert(two[0]["verificationResult"]).update(sourceRepositoryDigest="f" * 40)
k, w = attest.judge(two, RSHA, RREPO, RC, RWF, RTAG)
check(len(k) == 1 and len(w) == 1 and "another commit" in w[0], "of two attestations, the one of another commit is said and left out, the one that holds is kept")
check(attest.identity("Gamer92000/hassmic-plugin-x", ".github/workflows/release.yml", "v1.2")
      == r"^https://github\.com/(?i:Gamer92000/hassmic-plugin-x)/\.github/workflows/release\.yml@refs/tags/v1\.2$",
      "gh's identity: the signing workflow's URI exactly, anchored, its dots escaped, the repository's name in any case")
for wf, ok in ((".github/workflows/release.yml", True), (".github/workflows/r.yaml", True), (".github/workflows/sub/release.yml", False),
               ("release.yml", False), (".github/workflows/../x.yml", False), (".github/workflows/release.json", False), (".github/workflows/.yml", False)):
    check(bool(attest.WORKFLOW.fullmatch(wf)) == ok, f"a workflow's path {wf!r}: {'taken' if ok else 'refused'}")

for src, want in (("https://github.com/Gamer92000/hassmic-plugin-microwakeword", "Gamer92000/hassmic-plugin-microwakeword"),
                  ("https://github.com/a/b", "a/b"), ("https://github.com/a/b/tree/main", None), ("https://gitlab.com/a/b", None),
                  ("https://github.com/-a/b", None), ("https://github.com/a--b/c", None), ("https://github.com/a/..", None),
                  ("https://github.com/a/b.git", None), ("http://github.com/a/b", None), (None, None)):
    check(attest.repo_of(src) == want, f"repo_of({src!r}): {want}")

# ---- verify through the stand-in gh: what gh refuses, and what a gh that lies says, both refused
WF, TAG = ".github/workflows/release.yml", "v1"


def verified(cfg, bundle=None, source=SOURCE, commit=C, sha=SHA, workflow=WF, tag=TAG):
    """attest.verify's bundle, or "refused: <why>", or "unavailable: <why>" """
    gh(cfg)
    try:
        return attest.verify(pkg, source, commit, sha, workflow, tag, bundle)
    except attest.Refused as x:
        return "refused: " + str(x)
    except attest.Unavailable as x:
        return "unavailable: " + str(x)


got = verified({"*": {}})
check(isinstance(got, bytes) and SHA in attest.subjects(got), "the stand-in gh, an honest build of what is asked: verified, its bundle kept")
argv = json.loads(open(LOG).read().splitlines()[0])
want = ["attestation", "verify", argv[2], "--repo", REPO, "--source-digest", C, "--source-ref", "refs/tags/v1",
        "--cert-identity-regex", r"^https://github\.com/(?i:someone/hassmic-plugin-example)/\.github/workflows/release\.yml@refs/tags/v1$",
        "--signer-digest", C, "--deny-self-hosted-runners", "--predicate-type", attest.PREDICATE, "--cert-oidc-issuer", attest.ISSUER, "--format", "json"]
check(argv == want, f"gh is asked with every rule it has a flag for, and no --bundle: GitHub's API, the repository that has the name now ({argv})")
check(attest.command("example-1.hmp", REPO, C, WF, TAG, "example-1.hmp" + attest.SUFFIX)
      == "gh attestation verify example-1.hmp " + " ".join(x if "^" not in x else "'" + x + "'" for x in want[3:]) + " --bundle example-1.hmp.sigstore.jsonl",
      "the command shown to readers is the one the index runs, the identity quoted for a shell, with the site's bundle")
for what, facts, said_gh, said_us in (
        ("another repository (its source; the signing workflow this one's, called by it)", {"repo": "evil/hassmic-plugin-example", "signer_repo": REPO},
         "SourceRepositoryURI", "built from another repository"),
        ("another commit", {"commit": "b" * 40}, "SourceRepositoryDigest", "another commit"),
        ("another file (the digest)", {"subject": "0" * 64}, "no attestations", "other files"),
        ("a self-hosted runner", {"runner": "self-hosted"}, "RunnerEnvironment", "self-hosted"),
        ("a workflow of another repository", {"signer_repo": "evil/actions"}, "verifying with issuer", "signed by another workflow"),
        ("another workflow of the same repository", {"workflow": ".github/workflows/x.yml"}, "verifying with issuer", "signed by another workflow"),
        ("a branch's run", {"ref": "refs/heads/main"}, "SourceRepositoryRef", "refs/heads/main"),
        ("another tag's run", {"ref": "refs/tags/v2"}, "SourceRepositoryRef", "not of the tag v1"),
        ("the workflow of another commit", {"signer_commit": "b" * 40}, "BuildSignerDigest", "another commit"),
        ("another issuer", {"issuer": "https://accounts.google.com"}, "Issuer", "GitHub Actions"),
        ("another predicate", {"predicate": "https://in-toto.io/attestation/release/v0.1"}, "with predicate type", "SLSA")):
    honest = verified({"*": facts})
    lied = verified({"*": facts, "mode": "lie"})
    check(honest.startswith("refused") and said_gh in honest, f"{what}: gh refuses it (its flags), and so is it refused: {honest[:160]}")
    check(isinstance(lied, str) and lied.startswith("refused") and said_us in lied,
          f"{what}: a gh that says status 0 and \"verified\" all the same is not taken at its word: {lied[:160]}")
# what gh has no flag for: an honest gh passes it, and judge refuses it
for what, facts, said in (("a run started by hand (gh workflow run release.yml --ref v1)", {"trigger": "workflow_dispatch"}, "workflow_dispatch"),
                          ("the entry's workflow called by another of the repository", {"caller": ".github/workflows/caller.yml"}, "that calls the entry's"),
                          ("its caller at another commit", {"config_commit": "b" * 40}, "that calls the entry's")):
    got = verified({"*": facts})
    check(got.startswith("refused") and said in got, f"{what}: gh has no flag for it and verifies it; refused here ({got[:160]})")
# gh's own no's are verdicts; anything else it fails with is none
for what, text, kind in (("no attestation at all (uploaded by hand, built elsewhere)", "Error: no attestations found", "refused"),
                         ("a field not what a flag asks", "Error: expected SourceRepositoryRef to be refs/tags/v1, got refs/heads/main", "refused"),
                         ("the identity not the one asked, or a signature that does not hold", 'Error: verifying with issuer "sigstore.dev"', "refused"),
                         ("GitHub's API: no such repository", "Error: HTTP 404: Not Found (https://api.github.com/repos/a/b/attestations/sha256:0)", "refused"),
                         ("Sigstore's trust root out of reach", "error creating Sigstore verifier: no valid Sigstore verifiers could be initialized", "unavailable"),
                         ("GitHub's API down", "Error: HTTP 503: Service Unavailable", "unavailable"),
                         ("GitHub's API refusing the token", "Error: HTTP 401: Bad credentials (https://api.github.com/repos/a/b/attestations)", "unavailable"),
                         ("GitHub's API's rate limit", "Error: HTTP 403: API rate limit exceeded", "unavailable"),
                         ("the network", "Error: Get \"https://api.github.com/\": dial tcp: lookup api.github.com: no such host", "unavailable"),
                         ("a gh that words a verdict otherwise", "Error: attestation does not match", "unavailable"),
                         ("nothing said", "", "unavailable")):
    got = verified({"fail": text})
    check(got.startswith(kind) and (text[:20] in got or not text), f"gh failing, {what}: {kind} ({got[:140]})")
got = verified({"fail": "Error: \x1b[31m::error::red\x07"})
check(got.startswith("unavailable") and "\x1b" not in got and "\x07" not in got, f"gh's words with control characters: said without them ({got[:120]!r})")
for what, raw, kind, said in (("no JSON", "Error: something\n", "unavailable", "is no JSON"), ("cut short", json.dumps([{"attestation": {}}])[:-3], "unavailable", "is no JSON"),
                              ("an object", "{}\n", "unavailable", "not the list"), ("an empty list", "[]\n", "unavailable", "an empty one"),
                              ("a list of numbers", "[1, 2]\n", "refused", "not a verified attestation"),
                              ("nested past what Python reads (a repository's own predicate can be)", "[" * 100000 + "]" * 100000, "refused", "nested deeper")):
    got = verified({"raw": raw})
    check(got.startswith(kind) and said in got, f"gh's answer {what}, status 0: {kind}, said so ({got[:120]})")
os.environ["INDEX_GH"] = os.path.join(top, "no-such-gh")
got = verified({"*": {}})
check(got.startswith("unavailable") and "no " in got, f"no gh here: no verdict, Unavailable ({got[:120]})")
os.environ["INDEX_GH"] = FAKE
# gh is tools/gh.sh's version or no verdict, wherever this runs (gh --version, asked once a process: a review of
# 17c2e8c, where a step after tools/gh.sh's could set INDEX_GH to the runner's own gh, whose words may be others)
for what, said in (("another version", "gh version 2.99.0 (2026-01-01)\n"), ("a later one", f"gh version {attest.GH_VERSION}1 (2026-12-01)\n"),
                   ("nothing", ""), ("its version on a second line", f"gh\ngh version {attest.GH_VERSION}\n"),
                   ("control characters", "gh version \x1b[31m::error::\n")):
    attest._checked.clear()
    got = verified({"*": {}, "version": said})
    check(isinstance(got, str) and got.startswith("unavailable") and f"not gh {attest.GH_VERSION}" in got and "\x1b" not in got and not os.path.exists(LOG),
          f"a gh that says {what} for --version: no verdict, nothing verified with it ({str(got)[:140]!r})")
attest._checked.clear()
got = verified({"*": {}})
check(isinstance(got, bytes) and attest._checked == {FAKE: ""}, "gh that says it is gh.sh's version: asked, then verified with")
check(isinstance(verified({"*": {}, "version": "gh version 0.0.0\n"}), bytes), "asked once a process: the answer taken first stands for that program")
attest._checked.clear()
was, attest.SECONDS = attest.SECONDS, 1
got = verified({"*": {}, "sleep": 3})
attest.SECONDS = was
check(got.startswith("unavailable") and "more than 1 s" in got, f"gh too slow: no verdict ({got[:120]})")
# and every later call of the same run no verdict at once, said so: one stalled gh would keep each next one waiting
# as long, past the publish job's timeout with nothing named (a review of dc75e14)
import time as _time
t0 = _time.monotonic()
got = verified({"*": {}, "sleep": 3})
check(isinstance(got, str) and got.startswith("unavailable") and "not asked" in got and "more than 1 s" in got and _time.monotonic() - t0 < 1 and not os.path.exists(LOG),
      f"after gh took its whole time once, the next one is not asked: no verdict at once, said why ({got[:140]})")
# but a stall of GitHub's API is not one of the bundles': the verification of a bundle the published site keeps asks
# no API and is still asked (a review of 810b9e9: one stalled new version held back every listed one and the
# revocation list with them); a stall of a bundle's makes the next bundle's no verdict at once, not the API's
attest._stalled.clear()
kept_file = os.path.join(os.path.dirname(pkg), "kept.sigstore.jsonl")
open(kept_file, "wb").write(verified({"*": {}}))
attest.SECONDS = 1
verified({"*": {}, "sleep_api": 3})
got = verified({"*": {}, "sleep_api": 3}, bundle=kept_file)
check(isinstance(got, bytes) and os.path.exists(LOG), f"after GitHub's API took its whole time once, a bundle on file is still verified ({str(got)[:120]})")
verified({"*": {}, "sleep": 3}, bundle=kept_file)
got_b = verified({"*": {}}, bundle=kept_file)
got_a = verified({"*": {}})
attest.SECONDS = was
check(isinstance(got_b, str) and "not asked" in got_b and "--bundle" in got_b and isinstance(got_a, str) and "not asked" in got_a and "--bundle" not in got_a,
      f"each kind its own: after a bundle's verification took its whole time, the next bundle's is not asked, and the API's still not ({got_b[:100]}; {got_a[:100]})")
attest._stalled.clear()
for what, src in (("another host", "https://gitlab.com/someone/plugin"), ("a path after the repository", SOURCE + "/tree/main")):
    got = verified({"*": {}}, source=src)
    check(got.startswith("refused") and "no GitHub repository" in got, f"a source on {what}: refused before gh is asked ({got[:120]})")
for what, over in (("a workflow outside .github/workflows/", {"workflow": "release.yml"}), ("a tag of another form", {"tag": "v1/x"})):
    got = verified({"*": {}}, **over)
    check(got.startswith("refused") and "the workflow or the tag" in got, f"{what}: refused before gh is asked ({got[:120]})")

# ---- the bundle kept: one, within what a site keeps
kept = verified({"*": [{}, {"commit": "b" * 40}], "mode": "lie"})
check(isinstance(kept, bytes) and kept.count(b"\n") == 1, "of two attestations, the one that holds is kept, the other is not published")
both = verified({"*": [{}, {}]})
check(isinstance(both, bytes) and both.count(b"\n") == 1, "of two that hold, one kept: the site keeps one attestation")
big = "x" * (attest.BUNDLE_MAX + 1)
got = verified({"*": [{"pad": big}, {}]})
check(isinstance(got, bytes) and got.count(b"\n") == 1 and len(got) < 1 << 16, "one that holds but is larger than a site keeps, and a small one: the small one kept")
got = verified({"*": {"pad": big}})
check(isinstance(got, str) and got.startswith("refused") and "larger than the 4 MB" in got,
      f"only one larger than a site keeps: refused (left out at the build), never one the signing would refuse ({got[:160]})")
bundle = os.path.join(top, "example-1.hmp" + attest.SUFFIX)
open(bundle, "wb").write(kept)
got = verified({}, bundle=bundle)
argv = json.loads(open(LOG).read().splitlines()[0])
check(isinstance(got, bytes) and argv[-2:] == ["--bundle", bundle] and got == kept,
      "verified again with the kept bundle (--bundle, no API: nothing in the config), the same bundle kept")
open(bundle, "wb").write(kept.replace(C.encode(), b"b" * 40))
got = verified({}, bundle=bundle)
check(got.startswith("refused"), f"a bundle of another commit on file: refused ({got[:120]})")
open(bundle, "wb").write(kept)
got = verified({}, bundle=bundle, workflow=".github/workflows/other.yml")
check(got.startswith("refused") and "verifying with issuer" in got, f"the kept bundle held to another workflow: refused ({got[:120]})")
got = verified({}, bundle=bundle, tag="v2")
check(got.startswith("refused") and "SourceRepositoryRef" in got, f"the kept bundle held to another tag: refused ({got[:120]})")
got = verified({"fail": "error creating Sigstore verifier: no valid Sigstore verifiers could be initialized"}, bundle=bundle)
check(got.startswith("unavailable"), f"the kept bundle with Sigstore's trust root out of reach: no verdict ({got[:120]})")
open(pkg, "wb").write(b"another package")
got = verified({}, bundle=os.path.join(top, "example-1.hmp" + attest.SUFFIX), sha=hashlib.sha256(b"another package").hexdigest())
check(got.startswith("refused"), f"another package beside that bundle: refused ({got[:120]})")
for what, d in (("nothing", b""), ("no JSON", b"x\n"), ("no envelope", b"{}\n"), ("another predicate", json.dumps({"dsseEnvelope": {"payload": "e30="}}).encode() + b"\n"),
                ("no final newline", kept[:-1])):
    try:
        attest.subjects(d)
        took = True
    except (ValueError, RecursionError):
        took = False
    check(not took, f"subjects(): {what} is no file of bundles")

import shutil
shutil.rmtree(top)
print("attest: " + ("FAILED" if failed else "all passed"))
sys.exit(1 if failed else 0)
