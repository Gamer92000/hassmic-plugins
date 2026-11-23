#!/usr/bin/env python3
"""Community plugins in the index (hassmic's docs/plugins.md 5.3, 5.8): listed as every plugin is, from the package
its own repository's GitHub Actions built, attested and released (tools/attest.py: tests/test_attest.py has every
way an attestation is refused); never built here.  First what needs nothing beyond Python: the entry's rules for a
community plugin (its package the release asset, and what else names its bytes: signature, LICENSE, capabilities),
fetch and the page; the harness's reading of qemu's -strace output judged by the sandbox's table (tools/filter.def),
call by call; the sandbox's bounds (tools/sandbox.py); the serials of sites built again (--bump) and a new index key.

Then, where they are there (else a note and nothing more): hassmic's plugin template (TEMPLATE, else
../hassmic-plugin-template) built as its author's release would build it (its own make, zig, the author's key), its
package served as the release asset (no network: urlopen and gh are stand-ins), listed as community and verified;
each way it is refused at the build (a manifest, signature, capabilities or LICENSE other than the entry's); and the
smoke test (index.py smoke: the harness under qemu-arm in bubblewrap) on it and on programs that open a socket,
reach out of the sandbox, write into qemu's log, close it or flood their stderr."""
import hashlib, json, os, shutil, subprocess, sys, tempfile
import urllib.request as _ur

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(os.path.dirname(HERE), "tools")
sys.path.insert(0, TOOLS)
import harness, index, otatool, plugcheck, sandbox

failed = False
def check(cond, what):
    global failed
    print(("ok   " if cond else "FAIL ") + what)
    failed |= not cond


top = tempfile.mkdtemp(prefix="community-test-")
# gh: the stand-in (no network), which attests any package as its repository's honest build of what is asked;
# a release asset: what RELEASES has under its address, and nothing is fetched from anywhere else
os.environ["INDEX_GH"] = os.path.join(HERE, "fake_gh.py")
os.environ.pop("INDEX_FAKE_GH", None)
WF = ".github/workflows/release.yml"              # each version's release workflow, as the entries name it
RELEASES, asked = {}, []
class _Got:
    def __init__(self, data): self.data = data
    def read(self, n=-1): return self.data[:n] if n >= 0 else self.data
    def __enter__(self): return self
    def __exit__(self, *a): return False
def _fake(url, timeout=0):
    asked.append(url)
    if url in RELEASES:
        return _Got(RELEASES[url])
    raise OSError("no network in the test")
_ur.urlopen = _fake
# whether a process here gets a user namespace of its own (sandbox.bounded: every bounded run, the harness's too).
# Where it does not (unprivileged user namespaces off), the cases that run one are not tried, said once; what is tried
# is that each refuses plainly, leaving nothing behind (a review of bccb6a9: harness.run fell over with a traceback)
def _userns():
    try:
        subprocess.run(["true"], preexec_fn=lambda: sandbox.own_userns(os.getuid(), os.getgid()))
        return True
    except subprocess.SubprocessError:
        return False
USERNS = _userns()
if not USERNS:
    print("note: no user namespace to be had here (unprivileged user namespaces off?): the harness's runs and the bounded runs "
          "are not tried; only that each refuses plainly")
for k in ("author", "index", "other"):
    otatool.keygen(os.path.join(top, k + ".key"), os.path.join(top, k + ".pub"))
AUTHOR_PUB = open(os.path.join(top, "author.pub"), "rb").read().hex()
URL = "https://github.com/your-account/hassmic-plugin-example"      # the template manifest's source
REL = URL + "/releases/download/v1/example-1.hmp"


def make_root(e, revoked=None):
    """a stand-in of this repository with the one entry E"""
    root = tempfile.mkdtemp(prefix="root-", dir=top)
    for d in ("plugins", "keys"):
        os.makedirs(os.path.join(root, d))
    shutil.copy(os.path.join(top, "index.pub"), os.path.join(root, "keys", "index.pub"))
    with open(os.path.join(root, "plugins", e["id"] + ".json"), "w") as f:
        json.dump(e, f)
    with open(os.path.join(root, "revoked.json"), "w") as f:
        json.dump(revoked or {"serial": 0, "entries": []}, f)
    return root


def entry(versions, **over):
    e = {"id": "example", "name": "Example", "description": "The template's example.", "author": "tests", "author_key": AUTHOR_PUB,
         "tier": "community", "source": URL, "versions": versions}
    e.update(over)
    return e


def version(n=1, **over):
    v = {"version": n, "commit": "c" * 40, "workflow": WF, "manifest": "d" * 64, "package": f"{URL}/releases/download/v{n}/example-{n}.hmp", "signature": "e" * 128,
         "license_sha256": "f" * 64, "capabilities": {"storage": 1}}
    v.update(over)
    return v


def refused(e):
    try:
        index.load(make_root(e))
    except index.Bad as x:
        return str(x)
    return ""


# ---- the entry: a release asset, as an official plugin's, and what names the rest of its bytes
check(refused(entry([version()])) == "", "a community entry: its version with commit, manifest, the release asset, signature, LICENSE's SHA-256, capabilities")
for what, why, e in (
        ("an official version's fields alone (no signature, LICENSE, capabilities)", "fields", entry([{"version": 1, "commit": "c" * 40, "workflow": WF, "manifest": "d" * 64, "package": REL}])),
        ("a field more: how the index would build it (gone: the index builds nothing)", "fields", entry([dict(version(), build={"toolchain": "zig-0.13.0"})])),
        ("no package", "fields", entry([{k: x for k, x in version().items() if k != "package"}])),
        ("a package that is no release asset of its source", "release asset", entry([version(package="https://example.com/example-1.hmp")])),
        ("a release asset of another repository", "release asset", entry([version(package="https://github.com/someone/else/releases/download/v1/example-1.hmp")])),
        ("a release asset of another version's name", "release asset", entry([version(package=URL + "/releases/download/v1/example-2.hmp")])),
        ("a source elsewhere than GitHub (whose attestations the index reads)", "GitHub repository", entry([version()], source="https://codeberg.org/someone/plugin")),
        ("a source that is no https address", "source", entry([version()], source="git@github.com:someone/plugin")),
        ("a source with ..", "source", entry([version()], source="https://github.com/someone/../plugin")),
        ("a signature that is not 128 hex digits", "signature", entry([version(signature="E" * 128)])),
        ("no license_sha256", "fields", entry([{k: x for k, x in version().items() if k != "license_sha256"}])),
        ("a license_sha256 that is not 64 hex digits", "license_sha256", entry([version(license_sha256="F" * 64)])),
        ("capabilities that are no object", "capabilities", entry([version(capabilities=["storage"])])),
        ("a capability no Echo knows", "capabilities", entry([version(capabilities={"storage": 1, "root": True})])),
        ("log.read.full declared by a community plugin", "official plugins only", entry([version(capabilities={"log.read.full": True})])),
        ("request.audio with net.internet", "may not reach the internet", entry([version(capabilities={"request.audio": True, "net.internet": True})])),
        ("wake with a way out", "only files and storage", entry([version(capabilities={"wake": True, "net.server": []})]))):
    got = refused(e)
    check(why in got, f"refused at the entry: {what}" + ("" if why in got else f": {got or 'taken'}"))
check("fields" in refused(entry([version()], tier="official", source="https://github.com/Gamer92000/example")),
      "an official entry with a community version's fields: refused")
RELEASES[REL] = b"the release asset's bytes"
missing = index.fetch(make_root(entry([version()])), os.path.join(top, "fetched"))
check(missing == 0 and asked == [REL] and open(os.path.join(top, "fetched", "example-1.hmp"), "rb").read() == RELEASES[REL],
      "fetch: a community version is its release asset, fetched from there as an official one's (nothing built)")
del RELEASES[REL]
check(index.broad({"storage": 1, "net.server": [], "request.text": True, "call": True, "log.read": True}) == ["call", "request.text"],
      "broad capabilities, in the Echo's order: call, request.text (net.server, storage, log.read are not)")
import page
html = page.page({"serial": 1700000000, "plugins": [{"id": "example", "name": "Example", "description": "d", "author": "a", "author_key": AUTHOR_PUB, "tier": "community", "source": URL,
                               "versions": [{"version": 1, "version_name": "1", "requires": {"core": 1, "call": 1}, "models": ["*"], "capabilities": {"call": True}, "broad": ["call"],
                                             "commit": "c" * 40, "workflow": WF, "manifest": "d" * 64, "package": "packages/example-1.hmp", "size": 1, "sha256": "0" * 64,
                                             "release": REL, "release_sha256": "1" * 64, "attestation": "packages/example-1.hmp.sigstore.jsonl",
                                             "attestation_sha256": "2" * 64}]}]},
                 {"entries": []})
check("Broad: call" in html and "Not reviewed" in html and "author's own GitHub Actions" in html and "not what the workflow does" in html
      and "--repo your-account/hassmic-plugin-example" in html and "zig" not in html,
      "the page: a community plugin not reviewed, its broad capabilities flagged, built by its author's own CI (attested), what that does not say")


# ---- the harness's reading of qemu's -strace, judged by the table
def judged(text, pid=2):
    t = harness.Trace(qemu={4})
    return [(name, harness.verdict(name, nr, args, pid)[0]) for _, name, nr, args, _, _ in t.feed(text)]


for line, want, what in (
        ("2 mmap2(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x3fffd000\n", "allow", "private anonymous memory"),
        ("2 mmap2(NULL,12288,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|0x20000,-1,0) = 0x3f000000\n", "allow", "with MAP_STACK, which qemu writes as a number (Rust's threads)"),
        ("2 mmap2(NULL,4096,PROT_EXEC|PROT_READ,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x3fff9000\n", "refused", "executable memory"),
        ("2 mmap2(NULL,4096,PROT_READ,MAP_SHARED,3,0) = 0x3fff9000\n", "refused", "a descriptor mapped"),
        ("2 mmap2(NULL,4096,PROT_READ,MAP_PRIVATE|MAP_GROWSDOWN|MAP_ANONYMOUS,-1,0) = 0\n", "refused", "a flag the table does not take"),
        ("2 mprotect(0x3fffd000,4096,PROT_READ) = 0\n", "allow", "mprotect to read only"),
        ("2 mprotect(0x3fffd000,4096,PROT_READ|PROT_EXEC) = 0\n", "refused", "mprotect to executable"),
        ("2 fcntl64(0,F_GETFD) = 0\n", "allow", "F_GETFD"),
        ("2 fcntl64(0,F_SETFL,O_RDONLY|O_LARGEFILE|O_NONBLOCK) = 0\n", "refused", "F_SETFL (a socket handed over stays as it is)"),
        ("2 ioctl(0,FIONREAD,0x407ffab4) = 0 (0)\n", "allow", "FIONREAD"),
        ("2 ioctl(0,TCGETS,0x407ffab4) = -1 errno=25 (Inappropriate ioctl for device)\n", "refused", "TCGETS"),
        ("2 ioctl(3,FIONBIO,0x407ffab4) = 0\n", "refused", "FIONBIO"),
        ("2 prctl(15,65896,1082129076,34,-1,1082129076) = 0\n", "allow", "PR_SET_NAME"),
        ("2 prctl(4,0,1082129076,34,-1,1082129076) = 0\n", "refused", "PR_SET_DUMPABLE"),
        ("2 sendto(3,65908,1,64,0,0) = 1\n", "allow", "send with MSG_DONTWAIT"),
        ("2 sendto(3,\"\\1\\0\",16,MSG_NOSIGNAL,NULL,0) = 16\n", "allow", "sendto with MSG_NOSIGNAL written by name (qemu 11)"),
        ("2 sendto(3,0x1,16,MSG_DONTWAIT|MSG_NOSIGNAL,NULL,0) = 16\n", "allow", "sendto with both flags by name"),
        ("2 sendto(3,0x1,16,MSG_OOB,NULL,0) = 16\n", "refused", "sendto with MSG_OOB by name"),
        ("2 sendto(3,65908,1,16385,0,0) = 1\n", "refused", "send with MSG_OOB"),
        ("2 sendto(3,65908,1,0,1082129068,16) = 1\n", "refused", "sendto an address"),
        ("2 clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID|CLONE_DETACHED,"
         "child_stack=0x3fff8f70,parent_tidptr=0x3fff8f94,tls=0x3fff8ff4,child_tidptr=0x00042764) = 3\n", "allow", "musl's thread"),
        ("2 clone(CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID|0x11,child_stack=0x00000000,parent_tidptr=0x00000000,tls=0x00000000,child_tidptr=0x00042764) = 3\n",
         "refused", "a process (fork)"),
        ("2 futex(0x3fff8f9c,FUTEX_PRIVATE_FLAG|FUTEX_WAKE,1,0x0004279c,0x3fff8fe0,1073713120) = 1\n", "allow", "FUTEX_WAKE"),
        ("2 futex(0x407ffa88,FUTEX_LOCK_PI,1,NULL,NULL,0) = 0\n", "refused", "a PI futex"),
        ("2 tgkill(2,2,6) = 0\n", "allow", "a signal to itself"),
        ("2 tgkill(1,1,9) = -1 errno=1 (Operation not permitted)\n", "refused", "a signal to another process"),
        ("2 socket(2,2,0) = 3\n", "refused", "a socket of its own"),
        ("2 openat(AT_FDCWD,\"/etc/pass)wd\",O_RDONLY) = 3\n", "refused", "a file opened (a ) in its quoted name)"),
        ("2 execve(\"/bin/sh\",{\"sh\",NULL},NULL) = 0\n", "refused", "an exec"),
        ("2 statx(272088,NULL,0,0,NULL) = -1 errno=14 (Bad address)\n", "enosys", "statx: ENOSYS on an Echo, where musl falls back"),
        ("2 clock_gettime64(1,0x407ffa60) = 0\n", "enosys", "clock_gettime64: the same"),
        ("2 Unknown syscall 500\n", "enosys", "a number above 386 by itself"),
        ("2 Unknown syscall 281\n", "refused", "socket by its number"),
        ("2 getrandom(0x407ffa60,16,0) = 16\n", "allow", "getrandom")):
    got = judged(line)
    check(got and got[0][1] == want and len(got) == 1, f"the harness reads {what}: {want} ({got})")

two = judged("2 futex(0x3fff8f9c,FUTEX_PRIVATE_FLAG|FUTEX_WAIT,2,NULL,NULL,0)2 rt_sigprocmask(SIG_BLOCK,0x00010328,0x3fff8ef0) = 0\n"
             "2 tgkill(1,1,9) = -1\n = 0\n")
check(two == [("futex", "allow"), ("rt_sigprocmask", "allow"), ("tgkill", "refused")],
      f"a call that blocks has another thread's written behind it on its line, its result later: each read ({two})")
t = harness.Trace()
a = t.feed("2 mmap2(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIV")
b = t.feed("ATE|MAP_ANONYMOUS,-1,0) = 0x3fffd000\n2 socket(2,")
c = t.feed("2,0) = 3\n")
check(a == [] and [x[1] for x in b] == ["mmap2"] and [x[1] for x in c] == ["socket"], "a call read once its argument list is whole, whatever the pieces the log comes in")
check(harness.value("PROT_READ|0x20") == 0x21 and harness.value("-1") == 0xFFFFFFFF and harness.value("NULL") == 0 and harness.value("O_RDWR") is None,
      "arguments: names, numbers and the two mixed; a name it does not know is none")


# ---- the log is the plugin's to write into: qemu-user shares its descriptor table with the program, and its log is
# one of them (review of 1e98a25, I2).  Each call on a descriptor the program was neither given nor made is refused,
# and the log is read a line at a time: a line that is not one qemu writes ends the reading
def foreign(text, qemu=(4,)):
    t = harness.Trace(qemu=set(qemu))
    calls = t.feed(text)
    return [(c[1], c[5]) for c in calls], t.broken

got, broken = foreign("2 set_tid_address(449856,0,124,0,449220,449108) = 2\n2 write(4,0x10692,26)\n1 getpid((((((((((((((((\n = 26\n"
                      "2 socket(PF_INET,SOCK_STREAM,IPPROTO_IP) = 5\n")
check([n for n, _ in got] == ["set_tid_address", "write"] and got[0][1] == "" and "qemu's own" in got[1][1] and "does not close" in broken,
      f"a write into qemu's log (its descriptor 4) is refused by its own line, which comes before what it wrote; the forged line ends the reading: {got} {broken!r}")
got, broken = foreign("2 close(4) = 0\n")
check(got and "not the plugin's" in got[0][1], f"closing qemu's log: refused ({got})")
got, broken = foreign("2 getpid(\n")
check(broken and "does not close" in broken, f"a call whose argument list does not close on its line: the log does not read ({broken!r})")
got, broken = foreign("2 getpid() = 2\nwhat is this\n")
check(broken and "no call" in broken, f"a line that is no call: the log does not read ({broken!r})")
import time as _t
t0, tr = _t.monotonic(), harness.Trace(qemu={4})
tr.feed("2 getpid(")
for _ in range(2048):
    tr.feed("(" * 1024)
check(tr.broken and "longer than" in tr.broken and _t.monotonic() - t0 < 3,
      f"a line that never ends (2 MB in 1 kB pieces): refused once past {harness.LINE_MAX} characters, in {_t.monotonic() - t0:.2f} s (not read again with every piece)")
# the descriptors it holds: given 0 to 3, made by dup, pipe2, eventfd2, F_DUPFD_CLOEXEC; gone by close; qemu's never
got, _ = foreign("2 dup(0) = 5\n2 write(5,0x1,1) = 1\n2 close(5) = 0\n2 write(5,0x1,1) = -1 errno=9 (Bad file descriptor)\n")
check([w for _, w in got][:3] == ["", "", ""] and "neither given it nor made" in got[3][1], f"dup's descriptor is the plugin's until it closes it ({got})")
got, _ = foreign("2 pipe2(0x40800,524288,0,0,0,0) = 0\n2 write(6,0x1,1) = 1\n2 read(5,0x1,1) = 1\n2 write(7,0x1,1) = 1\n")
check([w == "" for _, w in got] == [True, True, True, False], f"pipe2's two descriptors (qemu writes neither): the two lowest free, past qemu's 4 ({got})")
got, _ = foreign("2 dup3(0,4,0) = 4\n")
check(got and "qemu's own" in got[0][1], f"dup3 onto qemu's log: refused ({got})")
got, _ = foreign("2 fcntl64(0,F_DUPFD_CLOEXEC,30) = 30\n2 write(30,0x1,1) = 1\n2 eventfd2(0,0) = 5\n2 epoll_create1(0) = 6\n2 epoll_ctl(6,1,5,0x1) = 0\n")
check(all(w == "" for _, w in got), f"F_DUPFD_CLOEXEC, eventfd2, epoll_create1 and epoll_ctl on what they made: the plugin's ({got})")
got, _ = foreign("2 close_range(3,4294967295,0) = 0\n")
check(got and "qemu's own" in got[0][1], f"close_range over qemu's descriptors: refused ({got})")
got, _ = foreign("2 pwritev2(4,0x1,1,0,0,0) = 1\n")
check(got and "qemu's own" in got[0][1], f"a call the table answers ENOSYS on an Echo, which goes through under qemu (pwritev2), on qemu's log: refused ({got})")
got, _ = foreign("2 clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID|CLONE_DETACHED,"
                 "child_stack=0x1,parent_tidptr=0x1,tls=0x1,child_tidptr=0x1) = 3\n2 eventfd2(0,0)2 dup(0) = 5\n = 6\n2 write(5,0x1,1) = 1\n2 write(6,0x1,1) = 1\n")
check(all(w == "" for _, w in got), f"with threads a result may be another's: new descriptors counted as the kernel gives them, the lowest free ({got})")
got, _ = foreign("2 write(4,0x1,1) = 1\n", qemu=(5,))
check(got and "neither given it nor made" in got[0][1], f"a descriptor that is nobody's yet is not the plugin's either ({got})")

# qemu's own set is taken when the harness first sees the process that holds the log.  qemu's loader may still have
# the program's file open then (it maps it and closes it before the guest runs): that number is the program's to be
# given next, and an honest program that got it was refused (a review of 01e80b8).  A stand-in qemu holds the file
# as its descriptor 5 for a while, gives it back and writes the guest's calls: an eventfd2 that the kernel gives 5,
# and a close of it.  A second one keeps the file open, and its guest closes 5: that one stays qemu's
def fake_qemu(keep):
    q = os.path.join(top, f"fake-qemu-{keep}")
    with open(q, "w") as f:
        f.write(f"""#!{sys.executable}
import os, sys, time
log, prog = sys.argv[2], sys.argv[4]
lf = os.open(log, os.O_WRONLY | os.O_APPEND)
ex = os.open(prog, os.O_RDONLY)
assert (lf, ex) == (4, 5), (lf, ex)
time.sleep(1)
if not {keep}:
    os.close(ex)
    ev = os.eventfd(0)
    assert ev == 5, ev
    os.write(lf, b"9 eventfd2(0,0) = 5\\n9 close(5) = 0\\n")
else:
    os.write(lf, b"9 close(5) = 0\\n")
time.sleep(1)
""")
    os.chmod(q, 0o755)
    return q
fakep = os.path.join(top, "fake-program")
with open(fakep, "wb") as f:
    f.write(b"\x7fELF not run")
man_ = {"requires": {"core": 1}, "capabilities": {}, "settings": []}
own_tmp, tempfile.tempdir = tempfile.tempdir, os.path.join(top, "tmp")      # (harness.run's own work folder: where it can be seen)
os.makedirs(tempfile.tempdir)
try:
    if USERNS:
        rep_ = harness.run(fakep, man_, fake_qemu(False), 1)
        check("eventfd2" in rep_.calls and "close" in rep_.calls and "not the plugin's" not in (rep_.why or ""),
              f"qemu's loader held the program's file when its set was taken, and gave it back: the descriptor the program got with that number is the program's ({rep_.why})")
        rep_ = harness.run(fakep, man_, fake_qemu(True), 1)
        check("close" in rep_.calls and "qemu's own" in (rep_.why or ""), f"one qemu keeps open stays qemu's: a close of it refused ({rep_.why})")
    else:
        rep_ = harness.run(fakep, man_, fake_qemu(False), 1)
        check(not rep_.ok and rep_.why == sandbox.NO_USERNS, f"no user namespace for its bounds: the harness refuses, as sandbox.run does ({rep_.why})")
    check(os.listdir(tempfile.tempdir) == [], f"the harness's work folder is gone after its runs ({os.listdir(tempfile.tempdir)})")
finally:
    tempfile.tempdir = own_tmp


# ---- the smoke test: where no sandbox can be had, it fails whole, before any program runs (a review of bccb6a9)
import contextlib, io as _io
def smoke_of(root_, pkgdir, **kw):
    out = _io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            n = index.smoke(root_, pkgdir, **kw)
        return n, out.getvalue()
    except index.Bad as x:
        return str(x), out.getvalue()
spkgs = os.path.join(top, "smoke-pkgs")
os.makedirs(spkgs)
open(os.path.join(spkgs, "example-1.hmp"), "wb").write(b"not looked at before the sandbox")
_was_sw, _was_bw = sandbox.sandbox_works, sandbox.find_bwrap
sandbox.find_bwrap = lambda: "/bin/true"
try:
    sandbox.sandbox_works = lambda bwrap, work: "the test's own: no user namespace"
    got, said = smoke_of(make_root(entry([version()])), spkgs, qemu="/bin/true")
    check("no program can be run here" in str(got) and "the test's own" in str(got), f"no sandbox to be had: smoke fails, before any version ({got})")
    sandbox.sandbox_works = _was_sw
    if not USERNS:
        got, said = smoke_of(make_root(entry([version()])), spkgs, qemu="/bin/true")
        check(sandbox.NO_USERNS in str(got), f"and here, where there is none: said so ({got})")
    else:
        got = sandbox.sandbox_works("/bin/false", top)
        check(got and "status 1" in got and not os.path.exists(os.path.join(top, "sandbox-probe")), f"the probe: a bubblewrap that fails is said ({got!r})")
        check(sandbox.sandbox_works("/bin/true", top) is None, "the probe: one that runs passes")
finally:
    sandbox.sandbox_works, sandbox.find_bwrap = _was_sw, _was_bw
got, said = smoke_of(make_root(entry([version()])), os.path.join(top, "nothing-here"), qemu="/bin/true")
check(got == 0 and "no package" in said, f"a version fetch did not have: said, not run, no failure of the smoke test's (fetch warned) ({said.strip()})")
got, said = smoke_of(make_root(entry([{"version": 1, "commit": "c" * 40, "workflow": WF, "manifest": "d" * 64,
                                       "package": "https://github.com/Gamer92000/example/releases/download/v1/example-1.hmp"}],
                                     tier="official", source="https://github.com/Gamer92000/example")), spkgs)
check(got == 0 and "nothing to run" in said, "an official version: not run (the harness is for community versions not published yet)")

# ---- everything the sandbox runs is bounded: the wall clock, its folder's bytes, and each process's address space,
# file size, CPU time and processes (sandbox.run, sandbox.LIMITS)
def bounded_run(cmd, kind="probe", seconds=20, **kw):
    t0 = _t.monotonic()
    try:
        code = sandbox.run(["sh", "-c", cmd], kind, seconds, "the test", out=os.path.join(top, "bounded.log"), cwd=top, **kw)
        why = ""
    except sandbox.Failed as x:
        code, why = None, str(x)
    return code, why, _t.monotonic() - t0
if USERNS:
    code, why, took = bounded_run("sleep 30", seconds=1)
    check("more than 1 s" in why and took < 5, f"the wall clock: ended after {took:.1f} s ({why})")
    grow = os.path.join(top, "grow")
    os.makedirs(grow)
    # (a file a MB, each of its own name by a counter: sh is POSIX's, Ubuntu's dash, which has no $RANDOM, and a name
    # of $RANDOM's wrote one file over and over there, never more than 1 MB: the run of cc64177 on GitHub's runner)
    code, why, took = bounded_run(f"i=0; while :; do i=$((i + 1)); head -c 1048576 /dev/zero > {grow}/$i; done", watch=grow, watch_max=8 << 20, watch_files=100000)
    check("grew past 8 MB" in why and took < 10, f"its folder's bytes: ended at 8 MB ({why}, {took:.1f} s)")
    shutil.rmtree(grow)
    _lim = dict(sandbox.LIMITS["probe"])
    sandbox.LIMITS["probe"].update(fsize=1 << 20, cpu=2, procs=40, **{"as": 512 << 20})
    try:
        code, why, took = bounded_run(f"head -c 4194304 /dev/zero > {top}/big.out")
        check(code != 0 and os.path.getsize(os.path.join(top, "big.out")) <= 1 << 20, f"a file past its size: its writer ended at 1 MB ({os.path.getsize(os.path.join(top, 'big.out'))} bytes, status {code})")
        code, why, took = bounded_run("while :; do :; done", seconds=30)
        check(code is not None and code != 0 and took < 10, f"CPU time: a busy loop ended after its 2 s of CPU ({took:.1f} s, status {code})")
        code, why, took = bounded_run(f"{sys.executable} -c 'b = bytearray(1 << 30)'")
        check(code not in (0, None), f"address space: 1 GB not had under 512 MB (status {code})")
        code, why, took = bounded_run("for i in $(seq 200); do sleep 3 & done; wait", seconds=20)
        started_ = open(os.path.join(top, "bounded.log"), errors="replace").read()
        check("fork" in started_.lower() or "resource" in started_.lower() or "again" in started_.lower(),
              f"processes: 200 sleeps not had with room for 40 more ({started_.strip()[-160:]!r})")
        # the bound is each run's own (its user namespace): two runs at once, the user's other processes coming and going
        # beside them (here 120 more after both started), and each still has its 40 (a review of 01e80b8: the bound was
        # the user's tasks at the start plus room, which parallel runs and a job's other steps took: "cannot fork")
        import threading as _th
        res = {}
        def _two(n):
            log_ = os.path.join(top, f"twice-{n}.log")
            try:
                res[n] = (sandbox.run(["sh", "-c", "sleep 1; for i in $(seq 30); do sleep 2 & done; wait; echo done"], "probe", 30, "the test",
                                        out=log_, cwd=top), open(log_, errors="replace").read())
            except sandbox.Failed as x:
                res[n] = (None, str(x))
        ts = [_th.Thread(target=_two, args=(n,)) for n in (1, 2)]
        for t in ts:
            t.start()
        _t.sleep(0.3)
        load = [subprocess.Popen(["sleep", "4"]) for _ in range(120)]
        for t in ts:
            t.join()
        for p_ in load:
            p_.wait()
        check(all(res[n][0] == 0 and res[n][1].strip() == "done" for n in (1, 2)),
              f"processes: two runs at once, 120 more of the user's started beside them: each has its own 40 ({[(res[n][0], res[n][1].strip()[-120:]) for n in (1, 2)]})")
    finally:
        sandbox.LIMITS["probe"].clear()
        sandbox.LIMITS["probe"].update(_lim)
check(sandbox.tail.__doc__ and "::" in sandbox.tail.__doc__, "(sandbox.tail says why it indents)")
with open(os.path.join(top, "stranger.log"), "wb") as f:
    f.write(b"x" * 100000 + b"\n::error::the job is yours\n\x1b[2J\x1b]8;;evil\x07 colours\n")
shown = sandbox.tail(os.path.join(top, "stranger.log"), 200)
check(all(l.startswith("  | ") for l in shown.splitlines()) and "\x1b" not in shown and "\x07" not in shown and len(shown) < 400,
      f"a stranger's log as it is printed: its end only, each line indented (no \"::\" command for the CI runner), no control characters: {shown[-120:]!r}")

# ---- the serial of a second site of one commit (a publish of the same commit run again, index.yml), and
# never over another commit's site (a review of 01e80b8: an older run's publish put its older tree over a newer
# commit's site, one serial higher): --bump goes only over a site whose signed built-from.txt names this commit
bump_root = make_root(entry([version()]))
os.makedirs(os.path.join(top, "nopkgs"))
A, B = "a" * 40, "b" * 40
def build_site(dest, serial, previous=None, bump=False, commit=A, root=None, key="index"):
    out = _io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            index.build(root or bump_root, os.path.join(top, "nopkgs"), dest, serial, os.path.join(top, key + ".key"), previous, bump=bump, commit=commit)
        return json.load(open(os.path.join(dest, "index.json")))["serial"]
    except index.Bad as x:
        return str(x)
s1 = os.path.join(top, "site-1")
build_site(s1, 1700000000)
index.sign(bump_root, s1, os.path.join(top, "index.key"))
check(open(os.path.join(s1, "built-from.txt")).read().startswith(f"commit {A}\nindex.json ") and os.path.exists(os.path.join(s1, "built-from.txt.sig")),
      "the site says which commit made it: built-from.txt (the commit, the index's SHA-256), signed")
check(build_site(os.path.join(top, "site-2"), 1700000000, s1, bump=True) == 1700000000, "the same site again with --bump: the published serial, nothing new")
with open(os.path.join(bump_root, "revoked.json"), "w") as f:
    json.dump({"serial": 1, "entries": []}, f)
check("another index needs a higher one" in str(build_site(os.path.join(top, "site-3"), 1700000000, s1)), "a new revocation list at the same commit's serial: refused without --bump")
check(build_site(os.path.join(top, "site-4"), 1700000000, s1, bump=True) == 1700000001, "and with --bump, of the commit that made the published site: one more than its serial")
check("another index needs a higher one" in str(build_site(os.path.join(top, "site-5"), 1700000000, s1, bump=True, commit=B)),
      "with --bump, of another commit whose time is not higher: refused (no bump over another commit's site)")
check("another index needs a higher one" in str(build_site(os.path.join(top, "site-6"), 1700000000, s1, bump=True, commit=None)),
      "with --bump and no commit named: refused")
nameless = os.path.join(top, "site-nameless")
build_site(nameless, 1700000000, commit=None)
index.sign(bump_root, nameless, os.path.join(top, "index.key"))
with open(os.path.join(bump_root, "revoked.json"), "w") as f:
    json.dump({"serial": 2, "entries": []}, f)
check(not os.path.exists(os.path.join(nameless, "built-from.txt")) and "another index needs a higher one" in str(build_site(os.path.join(top, "site-7"), 1700000000, nameless, bump=True)),
      "a published site that names no commit (the tool before): no bump over it")
# the finding's case: commit B (newer) took a plugin out and was published; commit A's run publishes after it
newer_root, older_root = make_root(entry([], id="other")), make_root(entry([version()]))
newer = os.path.join(top, "site-newer")
build_site(newer, 1700000100, commit=B, root=newer_root)
index.sign(newer_root, newer, os.path.join(top, "index.key"))
check("another index needs a higher one" in str(build_site(os.path.join(top, "site-8"), 1700000000, newer, bump=True, commit=A, root=older_root)),
      "an older commit's tree built after a newer one's site was published: refused with --bump too (it would put back what the newer one took out)")
# the record is the index key's word on that very index
forged = os.path.join(top, "site-forged")
shutil.copytree(s1, forged)
with open(os.path.join(forged, "built-from.txt"), "w") as f:
    f.write(open(os.path.join(s1, "built-from.txt")).read().replace(A, B))
check("not signed by the index key" in str(build_site(os.path.join(top, "site-9"), 1700000000, forged, bump=True, commit=B)),
      "a published site whose built-from.txt was changed: not one the index key signed, refused")
moved = os.path.join(top, "site-moved")
shutil.copytree(s1, moved)
for n in ("built-from.txt", "built-from.txt.sig"):
    shutil.copy(os.path.join(newer, n), os.path.join(moved, n))
check("not the record of the index.json beside it" in str(build_site(os.path.join(top, "site-10"), 1700000000, moved, bump=True, commit=B)),
      "another site's signed built-from.txt beside this index: refused")
# a later commit whose time is not above the published serial (a committer's clock behind, or within a second of a
# serial bumped by one): --bump also over a site of a commit this one descends from (git merge-base --is-ancestor in
# the tree), so a revocation in it goes out now; never over one it does not descend from (a review of bccb6a9: it was
# refused, red, and the revocation waited for the next commit)
def tgit(*a):
    return subprocess.run(["git", "-C", groot, "-c", "user.name=t", "-c", "user.email=t@t", *a], capture_output=True, text=True, check=True).stdout.strip()
groot = make_root(entry([version()]))
tgit("init", "-q")
tgit("add", "-A")
tgit("commit", "-q", "-m", "c0")
c0 = tgit("rev-parse", "HEAD")
published0 = os.path.join(top, "site-g0")
build_site(published0, 1700000100, commit=c0, root=groot)
index.sign(groot, published0, os.path.join(top, "index.key"))
with open(os.path.join(groot, "revoked.json"), "w") as f:
    json.dump({"serial": 1, "entries": []}, f)
tgit("commit", "-q", "-am", "c1: a revocation")
c1 = tgit("rev-parse", "HEAD")
got = build_site(os.path.join(top, "site-g1"), 1700000050, published0, bump=True, commit=c1, root=groot)
check(got == 1700000101 and json.load(open(os.path.join(top, "site-g1", "index.json")))["revoked_serial"] == 1,
      f"a later commit (descends from the published site's) whose time is under the published serial, with --bump: one more than it, its revocation list in ({got})")
check("another index needs a higher one" in str(build_site(os.path.join(top, "site-g1b"), 1700000050, published0, commit=c1, root=groot)),
      "(and without --bump refused, as before)")
index.sign(groot, os.path.join(top, "site-g1"), os.path.join(top, "index.key"))
def described(text, message):
    with open(os.path.join(groot, "plugins", "example.json"), "w") as f:
        json.dump(entry([version()], description=text), f)
    tgit("commit", "-q", "-am", message)
    return tgit("rev-parse", "HEAD")
c2 = described("The next.", "c2")
got = build_site(os.path.join(top, "site-g2"), 1700000060, os.path.join(top, "site-g1"), bump=True, commit=c2, root=groot)
check(got == 1700000102, f"and its child over that site the same: one more again ({got})")
index.sign(groot, os.path.join(top, "site-g2"), os.path.join(top, "index.key"))
tgit("checkout", "-q", "-b", "side", c1)
cx = described("Beside.", "x: beside c2")
got = build_site(os.path.join(top, "site-gx"), 1700000060, os.path.join(top, "site-g2"), bump=True, commit=cx, root=groot)
check("another index needs a higher one" in str(got),
      f"with --bump, a commit beside the published site's (not descended from it), its time under the serial: refused (it would put back what that took out): {got}")
tgit("checkout", "-q", c1)
got = build_site(os.path.join(top, "site-g1b"), 1700000050, os.path.join(top, "site-g2"), bump=True, commit=c1, root=groot)
check("another index needs a higher one" in str(got), f"with --bump, the published site's parent (an older run publishing late): refused: {got}")
check("another index needs a higher one" in str(build_site(os.path.join(top, "site-gs"), 1700000050, published0, bump=True, commit="e" * 40, root=groot)),
      "with --bump, a commit git does not have (a shallow clone): refused, nothing assumed")

# ---- a new index key (README "A new index key", K1 of a review of hassmic a30d6ed): the published site is the old
# key's (A, index.key) until the first publish with the new one (B, other.key).  The commit that switches keeps A as
# keys/index-previous.pub: the build reads the published site with either, builds over it (serials, --bump by its
# built-from.txt), lists and signs with B alone.  Without index-previous.pub the switch stops the index publishing
# (what the review found): refused, as before.  Once the site is B's the previous key goes
def fails(f, *a):
    try:
        with contextlib.redirect_stdout(_io.StringIO()):
            f(*a)
    except index.Bad as x:
        return str(x)
    return ""
tgit("checkout", "-q", c2)
shutil.copy(os.path.join(groot, "keys", "index.pub"), os.path.join(groot, "keys", "index-previous.pub"))
shutil.copy(os.path.join(top, "other.pub"), os.path.join(groot, "keys", "index.pub"))
# The switch with revoked.json as it is (a review of hassmic 3c5d7ff, R1): the list is published again by the new key
# under a serial one above the published one, so that an Echo of both keys takes it as newer and keeps the new key's
# signature (one of the same serial it took as "the same", and kept the old key's, which hassmic's build of the new
# key alone reads as no list).  The next build, over the new key's site, keeps that serial for the unchanged list
tgit("add", "-A"); tgit("commit", "-q", "-m", "c3a: the index key changes, the revocation list as it is")
c3a = tgit("rev-parse", "HEAD")
rota = os.path.join(top, "site-rota")
got = build_site(rota, 1700000070, os.path.join(top, "site-g2"), bump=True, commit=c3a, root=groot, key="other")
ra, ia = json.load(open(os.path.join(rota, "revoked.json"))), json.load(open(os.path.join(rota, "index.json")))
check(got == 1700000103 and ra["serial"] == 2 and ra["entries"] == [] and ia["revoked_serial"] == 2,
      f"the key switched, revoked.json unchanged (serial 1): published by the new key under serial 2, one above the published list's ({got}, {ra}, {ia['revoked_serial']})")
index.sign(groot, rota, os.path.join(top, "other.key"))
os.unlink(os.path.join(groot, "keys", "index-previous.pub"))
got = build_site(os.path.join(top, "site-rota2"), 1700000300, rota, bump=True, commit=c3a, root=groot, key="other")
check(got == 1700000300 and json.load(open(os.path.join(top, "site-rota2", "revoked.json")))["serial"] == 2,
      f"the next build over the new key's site, revoked.json still serial 1 and unchanged: the published serial kept, not refused ({got})")
with open(os.path.join(groot, "revoked.json"), "w") as f:
    json.dump({"serial": 2, "entries": [{"id": "example", "reason": "r"}]}, f)
check("a changed list needs a higher one" in str(build_site(os.path.join(top, "site-rota3"), 1700000300, rota, bump=True, commit=c3a, root=groot, key="other")),
      "a changed list at the raised serial: refused (a higher one needed, as ever)")
tgit("checkout", "-q", "--", "revoked.json")
shutil.copy(os.path.join(top, "index.pub"), os.path.join(groot, "keys", "index-previous.pub"))
with open(os.path.join(groot, "revoked.json"), "w") as f:
    json.dump({"serial": 2, "entries": []}, f)
tgit("add", "-A"); tgit("commit", "-q", "-m", "c3: the index key changes, a revocation with it")
c3 = tgit("rev-parse", "HEAD")
rot = os.path.join(top, "site-rot")
got = build_site(rot, 1700000070, os.path.join(top, "site-g2"), bump=True, commit=c3, root=groot, key="other")
check(got == 1700000103, f"the key switched, the old one as keys/index-previous.pub: built over the old key's site, --bump by its built-from.txt ({got})")
check(fails(index.sign, groot, rot, os.path.join(top, "index.key")) != "" and fails(index.sign, groot, rot, os.path.join(top, "other.key")) == ""
      and fails(index.verify, rot, os.path.join(top, "other.pub")) == "" and fails(index.verify, rot, os.path.join(top, "index.pub")) != "",
      "signed with the new key alone (sign refuses the old one): the site verifies against the new key, not the old")
r = subprocess.run([sys.executable, os.path.join(HERE, "..", "tools", "index.py"), "check", "--root", groot, "--previous", os.path.join(top, "site-g2")], capture_output=True, text=True)
check(r.returncode == 0, f"check --previous over the old key's site: passes ({r.stdout[-200:]}{r.stderr[-200:]})")
out = os.path.join(top, "fetched-rot"); os.makedirs(out)
check(fails(index.fetch, groot, out, os.path.join(top, "site-g2")) == "", "fetch --previous over the old key's site: it is read")
os.unlink(os.path.join(groot, "keys", "index-previous.pub"))
check("not one the index key signed" in str(build_site(os.path.join(top, "site-rot2"), 1700000070, os.path.join(top, "site-g2"), bump=True, commit=c3, root=groot, key="other")),
      "without keys/index-previous.pub: the old key's site is none to go by (refused, as before the fix)")
r = subprocess.run([sys.executable, os.path.join(HERE, "..", "tools", "index.py"), "check", "--root", groot, "--previous", os.path.join(top, "site-g2")], capture_output=True, text=True)
check(r.returncode != 0 and "not one the index key signed" in r.stdout + r.stderr, "... check --previous too")
with open(os.path.join(groot, "revoked.json"), "w") as f:
    json.dump({"serial": 3, "entries": []}, f)
check(build_site(os.path.join(top, "site-rot3"), 1700000200, rot, commit=c3, root=groot, key="other") == 1700000200,
      "once the published site is the new key's: the next build goes by it without the previous key")
for bad_prev, why in ((open(os.path.join(groot, "keys", "index.pub"), "rb").read(), "is keys/index.pub"), (bytes(32), "any signature holds"), (b"\x01" + bytes(31), "any signature holds"),
                      (bytes.fromhex("ee" + "ff" * 31), "any signature holds"), (b"short", "32 bytes")):
    open(os.path.join(groot, "keys", "index-previous.pub"), "wb").write(bad_prev)
    check(why in str(build_site(os.path.join(top, "site-rotx"), 1700000300, rot, commit=c3, root=groot, key="other")), f"keys/index-previous.pub that {why}: refused")
os.unlink(os.path.join(groot, "keys", "index-previous.pub"))


# ---- a community plugin end to end, where its tools are: the template built as its author's release builds it
template = os.environ.get("TEMPLATE") or os.path.join(os.path.dirname(os.path.dirname(HERE)), "hassmic-plugin-template")
zig = os.environ.get("INDEX_ZIG") or shutil.which("zig") or next((z for z in (os.path.join(os.path.dirname(os.path.dirname(HERE)), "echo-dot-assist", "toolchain", "zig", "zig"),)
                                                                  if os.path.isfile(z)), None)
qemu, bwrap = harness.find_qemu(), sandbox.find_bwrap()
def on_scopes(t):
    """the template speaks the protocol's versioned scopes: its manifest says what it requires (and its sdk/ is hassmic's
    of that protocol, which its make sync copies in); one from before them is refused by this index, rightly"""
    try:
        return isinstance(json.loads(open(os.path.join(t, "manifest.json")).read()).get("requires"), dict)
    except (OSError, ValueError):
        return False
missing = [w for w, x in (("the template (TEMPLATE, ../hassmic-plugin-template)", os.path.isfile(os.path.join(template, "manifest.json"))),
                         ("a template on the protocol's versioned scopes (its manifest's \"requires\": hassmic's sdk/ synced in, the manifest moved)",
                          not os.path.isfile(os.path.join(template, "manifest.json")) or on_scopes(template)),
                         ("zig (INDEX_ZIG)", zig), ("qemu-arm", qemu), ("bwrap", bwrap), ("git", shutil.which("git")),
                         ("a user namespace of its own (unprivileged user namespaces)", USERNS)) if not x]
if missing:
    print(f"note: a community plugin end to end not tried, for want of: {'; '.join(missing)}")
else:
    cc = f"{zig} cc -target arm-linux-musleabihf -mcpu=cortex_a7"
    head = subprocess.run(["git", "-C", template, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()

    def released(change=None, name="release"):
        """the template's package as its release job makes it (its own make, the author's key), from its HEAD's tree
        with CHANGE made to it: the bytes"""
        d = os.path.join(top, name)
        os.makedirs(d)
        subprocess.run(f"git -C {template} archive {head} | tar -x -C {d}", shell=True, check=True)
        if change:
            change(d)
        env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=os.path.join(top, ".zc"), ZIG_LOCAL_CACHE_DIR=os.path.join(d, ".zl"))
        r = subprocess.run(["make", "-C", d, "build/example-1.hmp", "KEY=" + os.path.join(top, "author.key"), "PLUGIN_CC=" + cc], env=env, capture_output=True, text=True)
        if r.returncode:
            raise SystemExit(f"FAIL the template's make: {r.stderr[-600:]}")
        return open(os.path.join(d, "build", "example-1.hmp"), "rb").read()

    def edit(path, old, new):
        def go(d):
            p = os.path.join(d, path)
            s = open(p).read()
            assert old in s, (path, old)
            open(p, "w").write(s.replace(old, new, 1))
        return go

    def as_entered(data, package=REL):
        p = os.path.join(top, "entered.hmp")
        open(p, "wb").write(data)
        r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "entry", p], capture_output=True, text=True)
        v = json.loads(r.stdout)
        return dict(v, commit=head, workflow=WF, package=package)

    good_pkg = released()
    good = as_entered(good_pkg)
    written = json.loads(open(os.path.join(template, "manifest.json")).read())
    check(good["capabilities"] == written["capabilities"] and good["version"] == written["version"]
          and set(good) == index.COMMUNITY_KEYS and good["package"] == REL,
          "index.py entry <the release's package>: a community version's fields, the template's capabilities as written there")
    RELEASES[REL] = good_pkg
    words = {k: written[k] for k in ("name", "author", "description")}     # (the entry says what the manifest says)
    root = make_root(entry([good], **words))
    pk = os.path.join(top, "e2e-pkgs")
    check(index.fetch(root, pk) == 0, "fetched from its release")
    site = os.path.join(top, "e2e-site")
    r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", pk, site, "--serial", "1700000000", "--key", os.path.join(top, "index.key"),
                        "--root", root, "--strict"], capture_output=True, text=True)
    ix = json.load(open(os.path.join(site, "index.json"))) if r.returncode == 0 else {"plugins": [{"versions": [{}], "tier": None}]}
    v = ix["plugins"][0]["versions"][0]
    listed = index.members(open(os.path.join(site, "packages", "example-1.hmp"), "rb").read(), "listed") if r.returncode == 0 else {}
    check(r.returncode == 0 and ix["plugins"][0]["tier"] == "community" and v.get("commit") == head and v.get("broad") == [] and "build" not in v and "harness" not in v
          and v.get("release") == REL and v.get("release_sha256") == hashlib.sha256(good_pkg).hexdigest()
          and plugcheck.listing_read(listed, json.loads(listed["manifest.json"]), open(os.path.join(top, "index.pub"), "rb").read()) == ("community", 1700000000),
          "index.py build lists it: tier community, its commit and release, attested; the package's listing says community" + ("" if r.returncode == 0 else ": " + r.stderr))
    index.sign(root, site, os.path.join(top, "index.key"))
    check(subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "verify", site, "--pub", os.path.join(top, "index.pub")], capture_output=True).returncode == 0,
          "and the site verifies (signatures, packages, listings, the attestations' bundles)")

    # the ways the build refuses it: what the entry names is every byte of the package
    sk = otatool.secret(os.path.join(top, "other.key"))
    f = index.members(good_pkg, "good")
    for what, why, v_, data, said in (
            ("a manifest digest that is not the package's", "not the one the entry names", dict(good, manifest="0" * 64), good_pkg, words),
            ("a signature that is not the package's", "not the signature the entry names", dict(good, signature=otatool.sign(sk, plugcheck.SIGN_MANIFEST + f["manifest.json"]).hex()), good_pkg, words),
            ("the package signed by another key (the entry naming that signature)", "not signed by the entry's author key",
             dict(good, signature=otatool.sign(sk, plugcheck.SIGN_MANIFEST + f["manifest.json"]).hex()), plugcheck.tar_bytes([("manifest.json", f["manifest.json"]), ("manifest.sig", otatool.sign(sk, plugcheck.SIGN_MANIFEST + f["manifest.json"])),
                                        ("plugin", f["plugin"]), ("LICENSE", f["LICENSE"])]), words),
            ("capabilities that are not the declared ones (storage 2 for 1)", "other capabilities than the entry declares",
             dict(good, capabilities={**good["capabilities"], "storage": 2}), good_pkg, words),
            ("another LICENSE than the entry names (the release asset replaced after the merge)", "LICENSE is not the one the entry names",
             good, plugcheck.tar_bytes([(n, b"Proprietary\n" if n == "LICENSE" else f[n]) for n in ("manifest.json", "manifest.sig", "plugin", "LICENSE")]),
             words),
            # (a review of 9b02fdb, 4: what an Echo shows is the manifest's, and a package called itself another plugin
            # under an entry that said otherwise)
            ("a manifest that calls itself what its entry does not (microWakeWord)", "the manifest's name", good, good_pkg, dict(words, name="microWakeWord")),
            ("... by another author", "the manifest's author", good, good_pkg, dict(words, author="hassmic")),
            ("... described otherwise", "the manifest's description", good, good_pkg, dict(words, description="The official wake word engine."))):
        d = tempfile.mkdtemp(prefix="bad-", dir=top)
        open(os.path.join(d, "example-1.hmp"), "wb").write(data)
        r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", d, os.path.join(d, "site"), "--serial", "1700000000",
                            "--key", os.path.join(top, "index.key"), "--root", make_root(entry([v_], **said))], capture_output=True, text=True)
        check(r.returncode != 0 and why in r.stderr and not os.path.exists(os.path.join(d, "site", "index.json")), f"refused, nothing written: {what} ({r.stderr.strip()[-160:]})")

    # the smoke test on it, and on programs it refuses
    got, said = smoke_of(root, pk)
    check(got == 0 and "the harness passed" in said, "index.py smoke: the template's program in the harness: passed\n     " + said.strip().replace("\n", "\n     "))
    sock_pkg = released(edit("src/main.c", "int main(", "#include <sys/socket.h>\nstatic int early(void) { return socket(AF_INET, SOCK_DGRAM, 0); }\n"
                                                         "__attribute__((constructor)) static void opens(void) { early(); }\nint main("), "release-sock")
    # (I3) what a program that is refused did before the harness stopped it stays in the sandbox: qemu's -strace
    # judges a call after it ran.  A listener on the host's loopback that hears nothing, a file outside the run's
    # folder that is not there
    import socket as _so
    listener = _so.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    escaped = os.path.join(top, "escaped")
    reach_pkg = released(edit("src/main.c", "int main(", "#include <sys/socket.h>\n#include <netinet/in.h>\n#include <fcntl.h>\n#include <unistd.h>\n"
                              "__attribute__((constructor)) static void reach(void) { int s = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in a = {0}; "
                              f"a.sin_family = AF_INET; a.sin_port = htons({listener.getsockname()[1]}); a.sin_addr.s_addr = htonl(0x7f000001); "
                              f"connect(s, (struct sockaddr *)&a, sizeof a); int f = open(\"{escaped}\", O_WRONLY | O_CREAT, 0644); if (f >= 0) write(f, \"out\", 3); }}\n"
                              "int main("), "release-reach")
    for what, data in (("a program that opens a socket of its own", sock_pkg), ("a program that connects to the host and writes outside its folder", reach_pkg)):
        d = tempfile.mkdtemp(prefix="smoke-", dir=top)
        open(os.path.join(d, "example-1.hmp"), "wb").write(data)
        got, said = smoke_of(make_root(entry([as_entered(data)], **words)), d)
        check(got == 1 and "a system call the sandbox refuses: socket(" in said, f"smoke: refused, {what}: " + next((l for l in said.splitlines() if l.startswith("error:")), said)[:240])
    listener.setblocking(False)
    try:
        listener.accept()
        heard = True
    except BlockingIOError:
        heard = False
    listener.close()
    check(not heard and not os.path.exists(escaped),
          "the harness's sandbox: a refused program's connect to the host's loopback reached nothing, its file outside the run's folder is not there"
          + (f" (heard: {heard}, written: {os.path.exists(escaped)})" if heard or os.path.exists(escaped) else ""))

    # (I2) the harness on programs that go for qemu's log, built here for ARM: one writes a line of its own into it,
    # one closes it (then nothing more of it would be logged), one floods its stderr (bounded, LIMITS["harness"])
    progs = os.path.join(top, "progs")
    os.makedirs(progs)
    sources = {
        "forge": 'static const char f[] = "\\n2 getpid()\\n2 getpid((((((((\\n"; for (int fd = 4; fd < 12; fd++) syscall(SYS_write, fd, f, sizeof f - 1);',
        "closelog": "syscall(SYS_close, 4);",
        "flood": "static char b[65536]; for (int i = 0; i < 2048; i++) syscall(SYS_write, 2, b, sizeof b);",
    }
    man = json.loads(open(os.path.join(template, "manifest.json")).read())
    for n, body in sources.items():
        with open(os.path.join(progs, n + ".c"), "w") as f:
            f.write("#include <unistd.h>\n#include <sys/syscall.h>\n#include <sys/socket.h>\n__attribute__((constructor)) static void go(void) { " + body
                    + " syscall(SYS_socket, 2, 1, 0); }\nint main(void) { for (;;) pause(); }\n")
        r = subprocess.run(cc.split() + ["-static", "-O1", "-o", os.path.join(progs, n), os.path.join(progs, n + ".c")], capture_output=True, text=True)
        if r.returncode:
            check(False, f"{n}: built: {r.stderr[-300:]}")
            continue
        run_ = os.path.join(progs, n + "-run")
        os.makedirs(run_)
        rep_ = harness.run(os.path.join(progs, n), man, qemu, 3, prefix=sandbox.sandbox(bwrap, [run_, progs], [qemu], scratch=os.path.join(run_, "scratch")), work=run_)
        if n == "flood":
            size = os.path.getsize(os.path.join(run_, "stderr.log"))
            check(not rep_.ok and size <= sandbox.LIMITS["harness"]["fsize"], f"a program that writes 128 MB to its stderr: ended at {size >> 20} MB, refused ({rep_.why})")
        else:
            check(not rep_.ok and "not the plugin's" in rep_.why and "socket" not in rep_.calls,
                  f"a program that {'writes into' if n == 'forge' else 'closes'} qemu's log: refused by that call, before anything it did after: {rep_.why}")

    # the greeting: the template's own program (its client offers every scope of its SDK, each at version 1) under a
    # manifest that requires a later version of one, or a scope its SDK does not have: REFUSED, as hassmic refuses an
    # SDK older than the manifest (plugin.c's HELLO); under its own requires it passed above
    ex = os.path.join(progs, "example")
    with open(ex, "wb") as f_:
        f_.write(index.members(good_pkg, "it")["plugin"])
    os.chmod(ex, 0o755)
    for req_, lack_ in (({**man["requires"], "storage": 2}, "storage 2"), ({**man["requires"], "later.scope": 1}, "later.scope 1")):
        run_ = os.path.join(progs, "example-run-" + lack_.split()[0])
        os.makedirs(run_)
        rep_ = harness.run(ex, dict(man, requires=req_), qemu, 2, prefix=sandbox.sandbox(bwrap, [run_, progs], [qemu], scratch=os.path.join(run_, "scratch")), work=run_)
        check(not rep_.ok and f"does not speak {lack_}, which its manifest requires" in (rep_.why or ""),
              f"the harness: a client that does not speak {lack_}, which the manifest requires: refused at its HELLO ({rep_.why})")

shutil.rmtree(top)
print("community: " + ("FAILED" if failed else "all passed"))
sys.exit(1 if failed else 0)
