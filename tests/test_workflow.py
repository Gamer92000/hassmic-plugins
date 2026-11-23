#!/usr/bin/env python3
"""The index's CI (.github/workflows/index.yml, WORKFLOW for another file) read as data (a reader of the YAML this file
is written in: mappings, lists, block texts; no YAML library in Python's standard one).  The index lists: every
package is its plugin's own release asset, built and attested by that repository's GitHub Actions; nothing is built
here (hassmic's docs/plugins.md 5.3).  What the workflow keeps:
  - "check" fetches every package, checks it and verifies its attestation (gh, with the run's read-only token; a
    pull request: --strict), and runs nothing of a package; "publish" needs "check" alone and does the same with
    the index key, building and running nothing;
  - "smoke" (a pull request only) runs the community versions not published yet in the harness: no secret, no
    environment, no token, no credentials left in its checkout, and no job needs it (publishing never waits for a
    stranger's program);
  - every job's runner is named: ubuntu-24.04, never -latest.
And what the reviews of 01e80b8 and bccb6a9 asked: only the newest commit publishes (git ls-remote against
GITHUB_SHA before the job queues, again as its first step, and tools/publish.sh again before it pushes, only over the
site it was built on: both run here against a repository of the test's own, PUBLISH and PUBLISHED other scripts to
show a broken one fails); publish one at a time in a group of its own; a cancelled run publishes nothing more
(!cancelled(), never always()); the jobs that run the harness lift AppArmor's user namespace restriction, never
"|| true"; a job of its own, "siblings", which no job needs and which runs for every push and pull request, runs the
reading list's check and the readers' over the three sibling repositories, checked out read-only
(tests/test_reading.py, tests/test_references.py --require: a copy not there fails it), and "check" checks out no
other repository (a review of 810b9e9: a sibling's moving branch held back every publish)."""
import os, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))

failed = False
def check(cond, what):
    global failed
    print(("ok   " if cond else "FAIL ") + what)
    failed |= not cond


# the reader is tools/workflow.py's, the one index.py build reads a plugin's release workflow with: strict where a
# YAML parser could read otherwise (a character outside printable ASCII, a folded block, a tab, an anchor...: no
# reading, never a part skipped; a review of dc75e14)
from workflow import read


path = os.environ.get("WORKFLOW") or os.path.join(ROOT, ".github", "workflows", "index.yml")
text = open(path).read()
try:
    wf = read(text)
    jobs = wf["jobs"]
except (ValueError, KeyError, TypeError) as x:
    print(f"FAIL {path} does not read: {x}")
    sys.exit(1)


def runs(job):
    return "\n".join(str(s.get("run", "")) for s in (job or {}).get("steps", []) if isinstance(s, dict))


def needs(job):
    n = (job or {}).get("needs") or []
    return [n] if isinstance(n, str) else list(n)


def step_env(job, pattern):
    """the env of the job's steps whose run matches PATTERN"""
    return [x.get("env") or {} for x in (job or {}).get("steps", []) if isinstance(x, dict) and re.search(pattern, str(x.get("run", "")))]


check(all(j.get("runs-on") == "ubuntu-24.04" for j in jobs.values()),
      f"every job's runner is named, ubuntu-24.04: {[j.get('runs-on') for j in jobs.values()]}")
pub, chk, smk, sbl = jobs.get("publish"), jobs.get("check"), jobs.get("smoke"), jobs.get("siblings")
check(set(jobs) == {"check", "smoke", "publish", "siblings"},
      f"four jobs, no build of the index's own (no community build, no two runners to agree): {sorted(jobs)}")
check(pub is not None and needs(pub) == ["check"], f"publish needs check and nothing else: no stranger's program holds the revocation list back: {needs(pub)}")
check(pub is not None and re.search(r"^make site PREVIOUS=previous\s*$", runs(pub), re.M) and "download-artifact" not in str(pub) and "upload-artifact" not in text,
      "publish lists what it fetched and checked itself: no package handed on from another job")
check(chk is not None and "published.sh previous" in runs(chk)
      and re.search(r"^make site PREVIOUS=previous \$\{\{ github.event_name == 'pull_request' && 'STRICT=1' \|\| '' \}\}\s*$", runs(chk), re.M),
      "check builds the site as publish will, against the published one; a pull request's with --strict (a version left out is an error)")
for name, job in (("check", chk), ("publish", pub)):
    envs = step_env(job, r"make site")
    check(envs and all(e.get("GH_TOKEN") == "${{ github.token }}" for e in envs),
          f"{name}'s site is built with the run's own token for gh (the attestations from GitHub's API): {envs}")
check(chk is not None and not re.search(r"make\b[^\n]*\bsmoke\b|index\.py\b[^\n]*\bsmoke\b|harness\.py|community", runs(chk)) and not needs(chk),
      "check, which publish waits for, runs no stranger's program (no smoke, no harness on a package)")
check(pub is not None and not re.search(r"smoke|harness|community", runs(pub)), "publish runs nothing of a package either")
check(smk is not None and smk.get("if") == "github.event_name == 'pull_request'" and not any("smoke" in needs(j) for j in jobs.values()),
      "smoke runs for a pull request only, and no job waits for it")
check(smk is not None and "secrets." not in str(smk) and "environment" not in smk and "GH_TOKEN" not in str(smk) and "github.token" not in str(smk)
      and "permissions" not in smk and wf.get("permissions") == {"contents": "read"},
      "smoke has no secret, no environment, no token named, and the workflow's read-only permissions")
co = [x for x in (smk or {}).get("steps", []) if isinstance(x, dict) and "actions/checkout" in str(x.get("uses"))]
check(len(co) == 1 and str((co[0].get("with") or {}).get("persist-credentials")) == "false", "smoke's checkout leaves no credentials in .git/config")
check(smk is not None and "make smoke PREVIOUS=previous" in runs(smk) and runs(smk).index("published.sh") < runs(smk).index("make smoke"),
      "smoke runs only what the published site does not have (PREVIOUS, read first)")
check(all("always()" not in str(j.get("if")) and all("always()" not in str(st.get("if")) for st in j.get("steps", []) if isinstance(st, dict))
          for j in jobs.values()),
      f"no job or step runs always(): a cancelled run publishes nothing more (V2) {[n for n, j in jobs.items() if 'always()' in str(j)]}")
check(all("secrets." not in str(j) for n, j in jobs.items() if n != "publish"), "the key is named by the publishing job only")

# only the newest commit publishes (V1)
def gate(job):
    """the job's steps that ask whether GITHUB_SHA is the head of GITHUB_REF, and say so as the output head"""
    return [st for st in (job or {}).get("steps", []) if isinstance(st, dict) and re.search(r"git ls-remote\b.*\$GITHUB_REF", str(st.get("run", "")))
            and '"$GITHUB_SHA"' in str(st.get("run")) and "head=true" in str(st.get("run")) and "head=false" in str(st.get("run"))]
g = gate(chk)
check(len(g) == 1 and g[0].get("id") == "head" and (chk.get("outputs") or {}).get("head") == "${{ steps.head.outputs.head }}"
      and pub is not None and "needs.check.outputs.head == 'true'" in str(pub.get("if")),
      "publish runs only while this run's commit is the branch's head (check's last step, git ls-remote): an older run's publish never queues")
# (and again as the job's first step, once it has its turn in its queue, every step after it only while that said
# head: an older run's job that waited there while a newer run published skips the build, which would fail red
# for a serial that does not grow (a review of bccb6a9))
st = [x for x in (pub or {}).get("steps", []) if isinstance(x, dict)]
check(st and st[0] in gate(pub) and st[0].get("id") == "head" and len(st) > 1
      and all("steps.head.outputs.head == 'true'" in str(x.get("if")) for x in st[1:]),
      f"publish asks whether this run's commit is the head again as its first step, before the checkout and the build, and runs every later step only then: "
      f"{[x.get('name') or x.get('uses') for x in st[1:] if 'steps.head.outputs.head' not in str(x.get('if'))]}")
check(re.search(r'sh tools/publish\.sh site previous "[^"]+" "\$GITHUB_REF" "\$GITHUB_SHA"\s*$', runs(pub), re.M) is not None,
      "publish pushes through tools/publish.sh with the branch and this run's commit (asked again right before the push, and pushed only over the site it read)")

# one publish at a time, in a group of its own
def conc(job):
    c = (job or {}).get("concurrency") or {}
    return (c.get("group"), c.get("cancel-in-progress")) if isinstance(c, dict) else (c, None)
gp, cp = conc(pub)
others = {conc(j)[0] for n, j in jobs.items() if n != "publish"} | ({conc(wf)[0]} if wf.get("concurrency") else set())
check(gp and "${{ github.ref }}" in gp and cp == "false" and gp not in others,
      f"publish one at a time in a group of its own (cancel-in-progress false) ({gp!r})")


# publish.sh and published.sh, run: the head asked before the push, the push only over what was read
def sh(*a, cwd=None, env=None):
    return subprocess.run(list(a), cwd=cwd, capture_output=True, text=True, env=env)
def git(*a, cwd=None):
    r = sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", "-c", "protocol.file.allow=always", *a, cwd=cwd)
    if r.returncode:
        raise SystemExit(f"FAIL git {' '.join(a)}: {r.stderr}")
    return r.stdout.strip()
publish = os.environ.get("PUBLISH") or os.path.join(ROOT, "tools", "publish.sh")
published = os.environ.get("PUBLISHED") or os.path.join(ROOT, "tools", "published.sh")
with tempfile.TemporaryDirectory(prefix="publish-test-") as t:
    origin, work = os.path.join(t, "origin.git"), os.path.join(t, "work")
    git("init", "-q", "--bare", origin)
    git("init", "-q", work)
    git("remote", "add", "origin", origin, cwd=work)
    def push_main(text):
        with open(os.path.join(work, "f"), "w") as f:
            f.write(text)
        git("add", "f", cwd=work)
        git("commit", "-q", "-m", text, cwd=work)
        git("push", "-q", "origin", "HEAD:refs/heads/main", cwd=work)
        return git("rev-parse", "HEAD", cwd=work)
    def gh_pages():
        r = sh("git", "ls-remote", origin, "refs/heads/gh-pages")
        return r.stdout.split()[0] if r.stdout.strip() else None
    def site(name, text):
        d = os.path.join(t, name)
        os.makedirs(d)
        for n in ("index.json", "revoked.json", "index.html"):
            with open(os.path.join(d, n), "w") as f:
                f.write(text + n)
        return d
    def read(name):
        r = sh("sh", published, name, cwd=work)
        return r.returncode == 0, os.path.join(work, name)
    def pub_(s_, prev, commit):
        env = dict(os.environ, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="protocol.file.allow", GIT_CONFIG_VALUE_0="always")
        r = sh("sh", publish, s_, prev, origin, "refs/heads/main", commit, env=env)
        return r.returncode, (r.stdout + r.stderr).strip().replace("\n", " | ").replace("::", ": ")      # (no "::" command for a CI log)
    c1 = push_main("one")
    ok, prev1 = read("previous1")
    check(ok and open(prev1 + ".ref").read().strip() == "none", "published.sh: nothing published yet, previous.ref says none")
    code, said = pub_(site("s1", "one"), prev1, c1)
    first = gh_pages()
    check(code == 0 and first is not None, f"publish.sh: this run's commit is the head: published ({said})")
    ok, prev2 = read("previous2")
    check(ok and open(prev2 + ".ref").read().strip() == first, "published.sh: previous.ref names the published commit it read")
    c2 = push_main("two")
    code, said = pub_(site("s2", "late"), prev2, c1)
    check(code == 0 and gh_pages() == first and "nothing pushed" in said and c2 in said,
          f"publish.sh of a run whose commit is no longer the head: nothing pushed, said ({said})")
    code, said = pub_(site("s3", "two"), prev2, c2)
    second = gh_pages()
    check(code == 0 and second not in (None, first), f"the head's run publishes ({said})")
    code, said = pub_(site("s4", "two again"), prev2, c2)
    check(code != 0 and gh_pages() == second, f"publish.sh over a site that is no longer the one it read (published meanwhile): refused, the other kept ({said})")
    code, said = pub_(site("s5", "first"), prev1, c2)
    check(code != 0 and gh_pages() == second, f"publish.sh built on nothing published, while something is now: refused ({said})")

# every job that builds the site against the published one has the whole history: --bump over a site of a commit
# this one descends from asks git (merge-base --is-ancestor), which a shallow clone cannot answer
for name, job in jobs.items():
    if "make site PREVIOUS=previous" not in runs(job):
        continue
    co = [x for x in job.get("steps", []) if isinstance(x, dict) and "actions/checkout" in str(x.get("uses")) and "repository" not in (x.get("with") or {})]
    check(len(co) == 1 and str((co[0].get("with") or {}).get("fetch-depth")) == "0",
          f"{name} builds the site and checks this repository out with its whole history (fetch-depth 0: whether this commit descends from the published site's)")

# both jobs that run the harness (check: the tool's tests; smoke: strangers' programs) lift Ubuntu's restriction of
# unprivileged user namespaces before they run it, and a sysctl that fails fails the job: with "|| true" a missing
# user namespace was a run that did nothing (a review of bccb6a9)
SYSCTL = re.compile(r'^(\[ -n "\$ACT" \] \|\| )?sudo sysctl -w kernel\.apparmor_restrict_unprivileged_userns=0$', re.M)
for name, job, step in (("check", chk, "make check"), ("smoke", smk, "make smoke")):
    r = runs(job)
    m = SYSCTL.search(r)
    check(m is not None and step in r and m.start() < r.index(step),
          f"{name} sets kernel.apparmor_restrict_unprivileged_userns=0 before it runs the harness ({step}), its failure the job's (no \"|| true\")")
# gh is the release tools/gh.sh downloads and checks by its SHA-256, named to index.py as INDEX_GH, in both jobs
# that verify attestations, before they build the site: never the runner image's gh, which GitHub raises when it
# likes (a gh that words its no's otherwise is no verdict, and a listed version's bundle refused by another gh's
# reading would fail every publish; a review of c61a1a5)
GHSTEP = 'gh=$(sh tools/gh.sh "$RUNNER_TEMP/gh")\necho "INDEX_GH=$gh" >> "$GITHUB_ENV"'
for name, job in (("check", chk), ("publish", pub)):
    st = [x for x in (job or {}).get("steps", []) if isinstance(x, dict)]
    at = [i for i, x in enumerate(st) if str(x.get("run", "")).strip() == GHSTEP]
    site_at = [i for i, x in enumerate(st) if "make site" in str(x.get("run", ""))]
    check(len(at) == 1 and site_at and at[0] < site_at[0], f"{name} takes gh from tools/gh.sh (by its SHA-256) as INDEX_GH before it builds the site")
# and nothing else names INDEX_GH (a step's env, a job's, a later run line writing it into GITHUB_ENV, a make line),
# nothing lets the job go on past a gh.sh that failed (continue-on-error: index.py would find the runner's gh), and the
# gh.sh step runs whenever the site is built (check: always; publish: as every step after the head's gate).  attest.py
# holds the gh it runs to gh.sh's version all the same (gh_checked): this is the workflow's half (a review of 17c2e8c)
rest = [x for j in jobs.values() for x in j.get("steps", []) if isinstance(x, dict) and str(x.get("run", "")).strip() != GHSTEP]
check("INDEX_GH" not in str(rest) + str({n: {k: v for k, v in j.items() if k != "steps"} for n, j in jobs.items()}) + str({k: v for k, v in wf.items() if k != "jobs"}),
      "nothing but the gh.sh step names INDEX_GH (no env, no run line, no other step writing it into GITHUB_ENV)")
check("continue-on-error" not in str(wf), "no job or step goes on past a failure (continue-on-error): never past gh.sh's, nor past a check")
ghs = {n: [x for x in j.get("steps", []) if isinstance(x, dict) and str(x.get("run", "")).strip() == GHSTEP] for n, j in jobs.items()}
check([set(x) for x in ghs.get("check", [])] == [{"name", "run"}]
      and [(set(x), x.get("if")) for x in ghs.get("publish", [])] == [({"name", "if", "run"}, "steps.head.outputs.head == 'true'")],
      f"the gh.sh step: a name and its run, in publish the head's gate as every later step's `if` and nothing else: {ghs}")
ghsh = open(os.path.join(ROOT, "tools", "gh.sh")).read()
ver = re.search(r"^VERSION=(\S+)$", ghsh, re.M)
sha = re.search(r"^SHA256=([0-9a-f]{64})$", ghsh, re.M)
named = set(re.findall(r"gh (\d+\.\d+\.\d+)", open(os.path.join(ROOT, "tools", "attest.py")).read()))
import attest
check(ver is not None and sha is not None and named == {ver.group(1)} and attest.GH_VERSION == ver.group(1),
      f"tools/gh.sh names one gh by its version and SHA-256, the version whose words attest.py reads and whose --version it asks for "
      f"({ver and ver.group(1)} against {sorted(named)}, GH_VERSION {attest.GH_VERSION})")
with tempfile.TemporaryDirectory(prefix="gh-test-") as t:
    # a release of the right form that is not the one: a gh that says it is that version, packed as gh's release is
    import tarfile, io
    fake = os.path.join(t, "gh.tar.gz")
    with tarfile.open(fake, "w:gz") as tf:
        body = f"#!/bin/sh\necho 'gh version {ver.group(1) if ver else '0'} (2026-11-17)'\n".encode()
        ti = tarfile.TarInfo(f"gh_{ver.group(1) if ver else '0'}_linux_amd64/bin/gh")
        ti.size, ti.mode = len(body), 0o755
        tf.addfile(ti, io.BytesIO(body))
    r = sh("sh", os.environ.get("GHSH") or os.path.join(ROOT, "tools", "gh.sh"), os.path.join(t, "out"),
           env=dict(os.environ, GH_URL="file://" + fake))
    check(r.returncode != 0 and r.stdout.strip() == "" and not os.path.exists(os.path.join(t, "out", f"gh_{ver.group(1) if ver else '0'}_linux_amd64")),
          f"tools/gh.sh refuses a download that is not that release (its SHA-256), unpacks nothing and names no gh ({r.stderr.strip()[-120:]})")
# the reading list's eight copies, the workflows an author starts from and the authors' copies of the reader, checked
# where all of them are: a job of its own checks out hassmic's docs, the template and microWakeWord, those files
# alone, without credentials, and runs both checks with --require (make check skips a tree that is not there: in CI
# that was a check that never ran; a review of dc75e14).  No job needs it and it has no if: (every push and pull
# request runs it, its failure shown), and "check", which publish needs, checks out no other repository: a sibling's
# branch, which moves when it likes, never holds back a publish and the revocation list with it (a review of 810b9e9)
SIBLINGS = {"Gamer92000/echo-dot-assist": ("siblings/echo-dot-assist", {"docs/plugins.md", "docs/SECURITY.md"}),
            "Gamer92000/hassmic-plugin-template": ("siblings/hassmic-plugin-template", {"README.md", ".github/workflows/release.yml", ".github/workflows/build.yml",
                                                                                        "tools/workflow_test.py"}),
            "Gamer92000/hassmic-plugin-microwakeword": ("siblings/hassmic-plugin-microwakeword", {"README.md", ".github/workflows/release.yml", ".github/workflows/build.yml",
                                                                                                  "tools/workflow_test.py"})}
cst = [x for x in (sbl or {}).get("steps", []) if isinstance(x, dict)]
sib = {(x.get("with") or {}).get("repository"): x for x in cst if "actions/checkout" in str(x.get("uses")) and (x.get("with") or {}).get("repository")}
check(set(sib) == set(SIBLINGS) and all(set(x["with"]) == {"repository", "path", "sparse-checkout", "sparse-checkout-cone-mode", "persist-credentials"}
                                       and x["with"]["path"] == SIBLINGS[r][0] and set(x["with"]["sparse-checkout"].split()) == SIBLINGS[r][1]
                                       and x["with"]["sparse-checkout-cone-mode"] == "false" and x["with"]["persist-credentials"] == "false"
                                       for r, x in sib.items()),
      f"siblings checks out the three sibling repositories, the reading list's files, the workflows and the readers alone, no credentials left: {sorted(sib)}")
own = [x for x in cst if "actions/checkout" in str(x.get("uses")) and not (x.get("with") or {}).get("repository")]
check(len(own) == 1 and own[0].get("with") == {"persist-credentials": "false"}, "siblings checks this repository out too, no credentials left")
rd = [x for x in cst if "test_reading.py" in str(x.get("run"))]
check(len(rd) == 1 and rd[0].get("run", "").split("\n") == ["python3 tests/test_reading.py --require", "python3 tests/test_references.py --require"]
      and rd[0].get("env") == {"HASSMIC": SIBLINGS["Gamer92000/echo-dot-assist"][0], "TEMPLATE": SIBLINGS["Gamer92000/hassmic-plugin-template"][0],
                               "MWW": SIBLINGS["Gamer92000/hassmic-plugin-microwakeword"][0]}
      and set(rd[0]) == {"name", "env", "run"} and all(cst.index(x) < cst.index(rd[0]) for x in sib.values()),
      "siblings runs the reading list's check and the references' over those trees with --require, after their checkouts, no if:")
check(sbl is not None and "if" not in sbl and not any("siblings" in needs(j) for j in jobs.values()) and not needs(sbl)
      and "secrets." not in str(sbl) and "environment" not in sbl and "permissions" not in sbl and "token" not in str(sbl).lower(),
      "siblings runs for every push and pull request, no job needs it (publish never waits on a sibling's branch), no secret, no environment, no token")
check(chk is not None and not any((x.get("with") or {}).get("repository") for x in chk.get("steps", []) if isinstance(x, dict))
      and "test_reading.py" not in runs(chk) and "--require" not in runs(chk) and pub is not None and not any((x.get("with") or {}).get("repository")
      for x in pub.get("steps", []) if isinstance(x, dict)),
      "check and publish check out no other repository and run no sibling's check: nothing of a sibling holds back a publish")
# and --require is what CI relies on: a sibling tree not there fails both checks (make check, without it, skips one)
with tempfile.TemporaryDirectory(prefix="require-test-") as t:
    gone = dict(os.environ, HASSMIC=os.path.join(t, "none"), TEMPLATE=os.path.join(t, "none"), MWW=os.path.join(t, "none"))
    got = [subprocess.run([sys.executable, os.path.join(HERE, n), "--require"], env=gone, capture_output=True, text=True)
           for n in ("test_reading.py", "test_references.py")]
    check(all(r_.returncode != 0 and "--require" in r_.stdout for r_ in got),
          f"tests/test_reading.py and tests/test_references.py --require fail where a sibling tree is not there: {[r_.returncode for r_ in got]}")
check(all(str(s.get("uses", "")).split("@")[-1].split()[0].isalnum() and len(str(s.get("uses", "")).split("@")[-1].split()[0]) == 40
          for j in jobs.values() for s in j.get("steps", []) if isinstance(s, dict) and s.get("uses")),
      "every action pinned by its commit")
print("workflow: " + ("FAILED" if failed else "all passed"))
sys.exit(1 if failed else 0)
