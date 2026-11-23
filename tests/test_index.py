#!/usr/bin/env python3
"""tools/index.py on a stand-in tree: an official plugin's package as its own repository releases it (the author's
signature, no listing; the program a made-up ARM ELF of headers only, nothing is run), built into a site with the
index key's listing added to each package, signed and verified; then each way an entry, a package, the revocation list or the site can be wrong, one at
a time.  Then the manifest rules an Echo has (index.manifest_check), each at its limit and past it, and, when
hassmic's tree is beside this one (HASSMIC: another) and there is a C compiler, the same manifests and 400 changed
at random (CHANGED, SEED) through hassmic's own ps_manifest_parse and runnable, as its ps_scan asks them: what the
Echo refuses, the index refuses, but for a version of a scope one build does not have yet ("needs a newer hassmic"),
which the index lists all the same (with the version's "requires"), refusing only what no hassmic has (SCOPES, held
to hassmic's plugmsg.h).  Then the index beside its revocation list (revoked_serial, what it withdraws left out),
every bound an Echo has (BOUNDS, held to hassmic's plugin_index.h), and fetch: from the published site first, a
release that cannot be had left out.  No network: fetch's downloads are a stand-in that fails."""
import copy, hashlib, io, json, os, random, re, shutil, struct, subprocess, sys, tarfile, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(os.path.dirname(HERE), "tools")
sys.path.insert(0, TOOLS)
import attest, index, otatool, plugcheck

# gh is the tests' stand-in (tests/fake_gh.py: no network): by default it attests any package as the honest build of
# what is asked, its repository's own CI at the entry's commit; tests/test_attest.py has every way it is not
os.environ["INDEX_GH"] = os.path.join(HERE, "fake_gh.py")
os.environ.pop("INDEX_FAKE_GH", None)
WF = ".github/workflows/release.yml"              # each version's release workflow, as the entries name it

failed = False
def check(cond, what):
    global failed
    print(("ok   " if cond else "FAIL ") + what)
    failed |= not cond


def elf():
    """the least an ELF for 32-bit ARM has to show: EABI5, static, a stack that is marked and not executable"""
    h = bytearray(52)
    h[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HH", h, 16, 2, 40)
    struct.pack_into("<I", h, 28, 52)
    struct.pack_into("<I", h, 36, 0x05000000)
    struct.pack_into("<HH", h, 42, 32, 2)
    ph = lambda t, fl: struct.pack("<8I", t, 0, 0, 0, 0, 0, fl, 0)
    return bytes(h) + ph(1, 5) + ph(0x6474E551, 6) + b"program"


def refused(f, *a, **k):
    """what index.py says against it, "" when it took it"""
    try:
        f(*a, **k)
    except index.Bad as e:
        return str(e)
    return ""


def retar(data, change):
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        f = {m.name: t.extractfile(m).read() for m in t.getmembers()}
    change(f)
    out = os.path.join(top, "re.hmp")
    plugcheck.tar_write(list(f.items()), out)
    return open(out, "rb").read()


top = tempfile.mkdtemp()
root, pkgs = os.path.join(top, "root"), os.path.join(top, "pkgs")
for d in ("plugins", "keys"): os.makedirs(os.path.join(root, d))
os.mkdir(pkgs)
for k in ("author", "index", "other"):
    otatool.keygen(os.path.join(top, k + ".key"), os.path.join(top, k + ".pub"))
K, KPUB = os.path.join(top, "index.key"), open(os.path.join(top, "index.pub"), "rb").read()
shutil.copy(os.path.join(top, "index.pub"), os.path.join(root, "keys", "index.pub"))
open(os.path.join(top, "prog"), "wb").write(elf())
open(os.path.join(top, "LICENSE"), "w").write("MIT\n")
manifest = {"id": "testplug", "name": "Test plugin", "version": 1, "version_name": "1.0", "requires": {"core": 1, "storage": 1}, "author": "tests",
            "source": index.OFFICIAL_SOURCE + "testplug", "license": "MIT", "description": "A stand-in.", "models": ["*"],
            "memory_mb": 8, "threads": 1, "capabilities": {"storage": 4}}


GONE = object()                                 # package(1, name=GONE): a manifest without it
def package(version, listed=None, **more):
    """as the plugin's repository releases it: packed and signed by the author, no listing (LISTED: with one by that
    key already, which is nobody's to add but the index's)"""
    m = {k: x for k, x in dict(manifest, version=version, **more).items() if x is not GONE}
    if "requires" not in more and isinstance(m.get("capabilities"), dict):
        m["requires"] = plugcheck.requires_for(m["capabilities"])     # (what a manifest of those capabilities says)
    mf, side, out = (os.path.join(top, n) for n in ("manifest.json", "side.hmp", "out.hmp"))
    open(mf, "w").write(json.dumps(m))
    if plugcheck.requires_check(m) is None:
        plugcheck.pack(mf, os.path.join(top, "prog"), os.path.join(top, "author.key"), side, license_=os.path.join(top, "LICENSE"))
    else:                                       # (what plugcheck.py signs no more: packed as it packs, for the index to refuse)
        sk = otatool.secret(os.path.join(top, "author.key"))
        mj = json.dumps(dict(m, author_key=sk[32:].hex(), digest=hashlib.blake2b(elf(), digest_size=32).hexdigest()), indent=1, ensure_ascii=False).encode() + b"\n"
        plugcheck.tar_write([("manifest.json", mj), ("manifest.sig", otatool.sign(sk, plugcheck.SIGN_MANIFEST + mj)), ("plugin", elf()), ("LICENSE", b"MIT\n")], side)
    digest = hashlib.blake2b(plugcheck.members(side)["manifest.json"], digest_size=32).hexdigest()
    if listed:
        plugcheck.list_package(side, os.path.join(top, listed + ".key"), out)
    return open(out if listed else side, "rb").read(), digest


def as_listed(site_, name):
    """a package as the site has it, and its members"""
    data = open(os.path.join(site_, "packages", name), "rb").read()
    return data, index.members(data, name)


def entry(versions, **over):
    """an entry, each version's package its own release asset (named by the id the entry has)"""
    pid = over.get("id", "testplug")
    e = {"id": "testplug", "name": "Test plugin", "description": "A stand-in.", "author": "tests",
         "author_key": open(os.path.join(top, "author.pub"), "rb").read().hex(), "tier": "official",
         "source": index.OFFICIAL_SOURCE + "testplug",
         "versions": [{"version": v, "commit": "c" * 40, "workflow": WF, "manifest": d, "package": index.OFFICIAL_SOURCE + f"testplug/releases/download/v{v}/{pid}-{v}.hmp"} for v, d in versions]}
    e.update(over)
    return e


def put(e=None, revoked=None, name="testplug.json"):
    d = os.path.join(root, "plugins")
    for n in os.listdir(d): os.unlink(os.path.join(d, n))
    if e is not None: open(os.path.join(d, name), "w").write(json.dumps(e))
    open(os.path.join(root, "revoked.json"), "w").write(json.dumps(revoked or {"serial": 0, "entries": []}))


def site(n):
    return os.path.join(top, f"site{n}")


# ---- a good one, through to the signed site
p1, d1 = package(1)
p2, d2 = package(2)
open(os.path.join(pkgs, "testplug-1.hmp"), "wb").write(p1)
open(os.path.join(pkgs, "testplug-2.hmp"), "wb").write(p2)
put(entry([(1, d1), (2, d2)]))
check(refused(index.load, root) == "", "an entry with two versions keeps the rules")
check(refused(index.build, root, pkgs, site(1), 100, K) == "", "built: both packages are the ones the entry names")
ix = json.load(open(os.path.join(site(1), "index.json")))
v = ix["plugins"][0]["versions"]
check([x["requires"] for x in v] == [{"core": 1, "storage": 1}] * 2, "and the least version of each scope each speaks, as its manifest says (\"requires\")")
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", pkgs, site(9), "--serial", "100", "--key", K, "--root", root], capture_output=True, text=True)
check(r.returncode == 0 and "warning" not in r.stdout, "with no warning: what a version requires is no reason for one")
check(all(list(x) == ["version", "version_name", "requires", "models", "capabilities", "commit", "workflow", "manifest", "package", "size", "sha256",
                       "release", "release_sha256", "attestation", "attestation_sha256"] for x in v),
      "an official version's fields in index.json, in their order (no \"broad\": a community version's; hassmic's tests/plugsite.py writes these bytes)")
check(v[0]["release"] == entry([(1, d1)])["versions"][0]["package"] and v[0]["release_sha256"] == hashlib.sha256(p1).hexdigest()
      and v[0]["attestation"] == "packages/testplug-1.hmp.sigstore.jsonl"
      and v[0]["attestation_sha256"] == hashlib.sha256(open(os.path.join(site(1), "packages", "testplug-1.hmp.sigstore.jsonl"), "rb").read()).hexdigest()
      and attest.subjects(open(os.path.join(site(1), "packages", "testplug-1.hmp.sigstore.jsonl"), "rb").read()) == {hashlib.sha256(p1).hexdigest()},
      "where each came from: the release asset's address and SHA-256 (the package as its CI made it), and the bundles of the attestations that held, "
      "beside the package and named by their SHA-256 under the index's signature")
check(ix["serial"] == 100 and [x["version"] for x in v] == [1, 2] and v[1]["capabilities"] == {"storage": 4} and v[1]["version_name"] == "1.0"
      and v[0]["package"] == "packages/testplug-1.hmp",
      "the index: its serial, the versions with what each asks for, the packages beside it")
l1, f1 = as_listed(site(1), "testplug-1.hmp")
check({k: f1[k] for k in f1 if k != "listing.sig"} == index.members(p1, "p1") and v[0]["size"] == len(l1) and v[0]["sha256"] == hashlib.sha256(l1).hexdigest(),
      "each package as its author released it, with the index's listing added: the size and SHA-256 the index names are the listed one's")
m1 = json.loads(f1["manifest.json"])
check(plugcheck.listing_read(f1, m1, KPUB) == ("official", 100), "the listing: the index key's, official, under the index's serial")
check(f1["listing.sig"].split(b"\n", 1)[1] == plugcheck.SIGN_LISTING + f"id testplug\nversion 1\ntier official\nmanifest {d1}\nserial 100\n".encode()
      and plugcheck.SIGN_LISTING == b"hassmic plugin listing 2\n",
      "its text: \"hassmic plugin listing 2\", id, version, tier, the manifest's digest, the serial; nothing else")
check(not otatool.check(bytes.fromhex(f1["listing.sig"][:128].decode()), KPUB, index.SIGN_INDEX + f1["listing.sig"][129:])
      and not otatool.check(bytes.fromhex(f1["listing.sig"][:128].decode()), KPUB, f1["listing.sig"][129:].replace(b"listing 2", b"listing 1")),
      "a listing's signature is none for an index, nor for the first form of a listing (the release key's)")
check(plugcheck.listing_read(f1, m1, open(os.path.join(top, "other.pub"), "rb").read()) is None, "nor a listing by another key")
check(refused(index.verify, site(1), os.path.join(top, "index.pub")) != "", "an unsigned site does not verify")
check(refused(index.sign, root, site(1), os.path.join(top, "other.key")) != "", "signing with a key that is not keys/index.pub's: refused")
index.sign(root, site(1), os.path.join(top, "index.key"))
check(refused(index.verify, site(1), os.path.join(top, "index.pub")) == "", "signed with the index key: it verifies")
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "check", "--root", root, "--previous", site(1)], capture_output=True, text=True)
check(r.returncode == 0 and "warning" not in r.stdout, "the check with the published index: no warning (what a version requires is in its listing, no reason for one)")
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "check", "--root", root], capture_output=True, text=True)
check(r.returncode == 0 and "warning" not in r.stdout, "(with nothing published it has no package to know it from)")
check(refused(index.verify, site(1), os.path.join(top, "other.pub")) != "", "not against another key")
check(open(os.path.join(site(1), "index.json.sig"), "rb").read() != open(os.path.join(site(1), "revoked.json.sig"), "rb").read()
      and not otatool.check(open(os.path.join(site(1), "revoked.json.sig"), "rb").read(), open(os.path.join(top, "index.pub"), "rb").read(),
                            index.SIGN_INDEX + open(os.path.join(site(1), "revoked.json"), "rb").read()),
      "the revocation list's signature is none for an index (each names its purpose)")
ixp = os.path.join(site(1), "index.json")
keep = open(ixp, "rb").read()
open(ixp, "wb").write(keep.replace(b'"serial": 100', b'"serial": 999'))
check(refused(index.verify, site(1), os.path.join(top, "index.pub")) != "", "a changed index: its signature does not hold")
open(ixp, "wb").write(keep)
pk = os.path.join(site(1), "packages", "testplug-1.hmp")
open(pk, "wb").write(p1)
check("not the package" in refused(index.verify, site(1), os.path.join(top, "index.pub")), "a package swapped on the site: found")
open(pk, "wb").write(l1)
check(refused(index.verify, site(1), os.path.join(top, "index.pub")) == "", "(put back: it verifies)")
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", pkgs, site(1070), "--serial", "100", "--key", os.path.join(top, "other.key"), "--root", root], capture_output=True, text=True)
check(r.returncode == 0 and "not one to publish" in r.stdout and refused(index.sign, root, site(1070), os.path.join(top, "other.key")) != "",
      "built with another key (a pull request's throwaway one): it says so, and sign refuses that key")
index.sign(root, site(1070), K)
check("no listing by the index key" in refused(index.verify, site(1070), os.path.join(top, "index.pub")),
      "and a site whose lists the index key signed but whose packages another key listed does not verify")

# ---- serials only grow, against a published site the index key signed
check(refused(index.build, root, pkgs, site(2), 100, K, site(1)) == "", "the published index again under its serial: built (a run repeated)")
put(entry([(1, d1)]))
check("higher" in refused(index.build, root, pkgs, site(3), 100, K, site(1)), "another index under the published one's serial: refused")
check("goes back" in refused(index.build, root, pkgs, site(3), 99, K, site(1)), "a serial that goes back: refused")
check(refused(index.build, root, pkgs, site(3), 101, K, site(1)) == "", "with a higher one: built")
check("not one the index key signed" in refused(index.build, root, pkgs, site(4), 102, K, site(3)), "a published site without the index key's signature is none to go by")
os.mkdir(os.path.join(top, "none"))
check(refused(index.build, root, pkgs, site(4), 102, K, os.path.join(top, "none")) == "", "an empty folder: nothing published yet")
check("not a time" in refused(index.build, root, pkgs, site(5), 2 ** 40, K), "a serial from a clock far ahead: refused")
check("not empty" in refused(index.build, root, pkgs, site(2), 102, K), "never into a folder that has files")
put(entry([(1, d1), (2, d2)]))

# ---- packages that are not what the entry names
def build_with(data, e=None, n=[10]):
    n[0] += 1
    open(os.path.join(pkgs, "testplug-1.hmp"), "wb").write(data)
    put(e or entry([(1, d1)]))
    return refused(index.build, root, pkgs, site(n[0]), 200, K)

check(build_with(p1) == "", "(one version, as it is: built)")
listed, dl = package(1, listed="other")
check(dl == d1 and "carries a listing already" in build_with(listed), "a package with a listing in it already (anyone's): refused, the index adds its own")
listed, dl = package(1, listed="index")
check("carries a listing already" in build_with(listed), "even one by the index key: the listing is made here, for this index's serial")
check("not the one the entry names" in build_with(p2), "another version's package under this one's name: refused")
check("not the one the entry names" in build_with(p1, entry([(1, "0" * 64)])), "a manifest that is not the one named: refused")
check("author key" in build_with(p1, entry([(1, d1)], author_key=open(os.path.join(top, "other.pub"), "rb").read().hex())),
      "the entry names another author key than the manifest's: refused")
# what an Echo shows (the install's dialog, the card, the browse row) is the manifest's name, author and description:
# the entry's are those (a review of 9b02fdb, 4: a package called itself "microWakeWord" by "hassmic" under an entry
# that said otherwise)
for k, other in (("name", "microWakeWord"), ("author", "hassmic"), ("description", "The official wake word engine.")):
    check(f"the manifest's {k}" in build_with(p1, entry([(1, d1)], **{k: other})), f"the entry's {k} another than the manifest's ({other!r}): refused")
check("program is not" in build_with(retar(p1, lambda f: f.__setitem__("plugin", elf() + b"more"))), "a changed program: refused")
check("does not belong" in build_with(retar(p1, lambda f: f.__setitem__("extra", b"x"))), "a file that is no part of a package: refused")
check("no LICENSE" in build_with(retar(p1, lambda f: f.pop("LICENSE"))), "no licence in it: refused")
check("no package" in build_with(b"not a tar at all" * 100), "no tar: refused")
check("follows" in build_with(p1 + b"more" * 128), "something after the tar's end: refused")
check(build_with(p1[:124] + b"\x80" + b"\0" * 9 + p1[134:136] + p1[136:]) != "", "a size in GNU's base-256 form: refused")
odd, do = package(1, capabilities={"storage": 10 ** 400})
check("more than 39 characters" in build_with(odd, entry([(1, do)])), "a number no manifest has: refused")
odd, do = package(1, name="<img src=x>")
check("name" in build_with(odd, entry([(1, do)])), "markup in a manifest's name: refused")
check("follows" in build_with(p1[:-1024] + b"\x01" + p1[-1023:]), "nor inside its padding")
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t, tarfile.open(fileobj=io.BytesIO(p1)) as old:
    for ti in old:
        ti.pax_headers = {"comment": "x"}; t.addfile(ti, old.extractfile(ti))
check(build_with(buf.getvalue()) != "", "a pax tar, which no Echo reads: refused")
odd, do = package(1, version_name={"a": 1})
check("version_name" in build_with(odd, entry([(1, do)])), "a manifest whose version_name is no text: not repeated under the index's signature")
odd, do = package(1, models=[["x"], {"a": None}])
check("models" in build_with(odd, entry([(1, do)])), "nor models that are no names")
odd, do = package(1, capabilities={"storage": "\u202egnp.exe"})
check("capabilities" in build_with(odd, entry([(1, do)])), "nor a capability with a direction mark in it")
for bad_version in ("7\ntier official\nmanifest " + "0" * 64 + "\nserial 0", True, 1.0, 0):
    open(os.path.join(top, "manifest.json"), "w").write(json.dumps(dict(manifest, version=bad_version)))
    try:
        plugcheck.pack(os.path.join(top, "manifest.json"), os.path.join(top, "prog"), os.path.join(top, "author.key"), os.path.join(top, "bad.hmp"), listed=K)
        took = True
    except SystemExit:
        took = False
    check(not took, f"plugcheck signs nothing for a manifest whose version is {bad_version!r:.20}")
os.unlink(os.path.join(pkgs, "testplug-1.hmp"))
put(entry([(1, d1), (2, d2)]))
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", pkgs, site(3000), "--serial", "200", "--key", K, "--root", root], capture_output=True, text=True)
ix = json.load(open(os.path.join(site(3000), "index.json"))) if r.returncode == 0 else {}
check(r.returncode == 0 and "warning: testplug version 1: no package" in r.stdout and [v["version"] for v in ix["plugins"][0]["versions"]] == [2]
      and os.path.exists(os.path.join(site(3000), "revoked.json")),
      "a version entered whose package cannot be had: left out with a warning, the rest and the revocation list published (one gone release blocked every publish)")
open(os.path.join(pkgs, "testplug-1.hmp"), "wb").write(p1)

# ---- the manifest rules of the Echo (index.manifest_check; hassmic's form, ps_manifest_parse, combination), one family at a time:
# at the limit it is built, past it refused with the reason.  seen: every manifest tried, for the C code below
seen = []
def words_of(mj):
    """the entry's name, author and description as the manifest MJ has them, where an entry can have them (the
    build holds the two to each other; a manifest's own words that are no entry's are refused by its own rules first)"""
    try:
        m = json.loads(mj)
    except ValueError:
        return {}
    bound = {"name": index.BOUNDS["NAME_MAX"], "author": index.BOUNDS["AUTHOR_MAX"], "description": index.BOUNDS["DESCRIPTION_MAX"]}
    return {k: m[k] for k in bound if isinstance(m, dict) and index.text_bytes(m.get(k), bound[k])}

def listed(**more):
    """what the build says against version 1 with these fields changed, "" when it lists it"""
    data, digest = package(1, **more)
    seen.append(index.members(data, "it")["manifest.json"])
    return build_with(data, entry([(1, digest)], **words_of(index.members(data, "it")["manifest.json"])))

def listed_raw(change):
    """the same for a manifest whose bytes CHANGE made: what plugcheck.py would write another way"""
    mj = change(index.members(p1, "it")["manifest.json"])
    seen.append(mj)
    sk = otatool.secret(os.path.join(top, "author.key"))
    files = [("manifest.json", mj), ("manifest.sig", otatool.sign(sk, plugcheck.SIGN_MANIFEST + mj)), ("plugin", elf()), ("LICENSE", b"MIT\n")]
    return build_with(plugcheck.tar_bytes(files), entry([(1, hashlib.blake2b(mj, digest_size=32).hexdigest())], **words_of(mj)))

def said(tier="official", model=None, **more):
    """manifest_check alone, for what a build stops earlier (the entry names id, version and author key)"""
    m = {k: x for k, x in {**manifest, "author_key": "ab" * 32, "digest": "cd" * 32, **more}.items() if x is not GONE}
    if "requires" not in more and isinstance(m.get("capabilities"), dict):
        m["requires"] = plugcheck.requires_for(m["capabilities"])
    raw = json.dumps(m, ensure_ascii=False).encode()
    seen.append(raw)
    return refused(index.manifest_check, raw, "it", tier, model)

def in_raw(change, tier="official", model=None):
    """manifest_check alone on bytes CHANGE made of a manifest that passes"""
    raw = change(json.dumps({**manifest, "author_key": "ab" * 32, "digest": "cd" * 32}).encode())
    seen.append(raw)
    return refused(index.manifest_check, raw, "it", tier, model)

def raw_says(why, change):
    """manifest_check says WHY against the bytes CHANGE makes, and no build lists them (which may stop earlier, at its
    own reading of the manifest, in other words)"""
    return why in in_raw(change) and listed_raw(change) != ""

def takes(what, **more):
    r = listed(**more)
    check(r == "", what + (f": {r}" if r else ""))
def refuses(what, why, **more): check(why in listed(**more), what)

# texts: bytes, not characters, and nothing that is no text
takes("a name of 48 bytes: built", name="n" * 48)
refuses("of 49: refused", '"name" is not text of at most 48 bytes', name="n" * 49)
refuses("48 bytes are 24 of a character of two", '"name" is not text', name="é" * 25)
takes("(24 of them: built)", name="é" * 24)
refuses("a manifest without a name: refused", '"name" is missing', name=GONE)
refuses("without an author", '"author" is missing', author=GONE)
check("no plugin or no author" in said(author=""), "an author of no characters: refused")
takes("a description of 240 bytes, a source of 200, a licence of 32, a version_name of 24: built",
      description="d" * 240, source="s" * 200, license="l" * 32, version_name="v" * 24)
refuses("a description of 241: refused", '"description" is not text of at most 240', description="d" * 241)
refuses("a source of 201", '"source" is not text of at most 200', source="s" * 201)
refuses("a licence of 33", '"license" is not text of at most 32', license="l" * 33)
refuses("a version_name of 25", '"version_name" is not text of at most 24', version_name="v" * 25)
takes("none of three: built", source=GONE, license=GONE, version_name=GONE)
refuses("none of the four: refused, the description is the entry's (a review of 9b02fdb, 4)", "the manifest's description", description=GONE, source=GONE, license=GONE, version_name=GONE)
refuses("a licence that is null: refused (left out instead)", '"license" is not text', license=None)
refuses("a tab in a description", "control character", description="two\twords")
refuses("a DEL in a licence", "control character", license="MIT\x7f")
check(listed_raw(lambda b: b.replace(b'"A stand-in."', b'"' + b"\\u0041" * 170 + b'"')) == "", "a description of 1020 bytes as written, in escapes: built")
check('"description" is not text' in listed_raw(lambda b: b.replace(b'"A stand-in."', b'"' + b"\\u0041" * 171 + b'"')), "of 1026: refused, as the Echo's reader does")
check("written with an escape" in listed_raw(lambda b: b.replace(b'"name"', b'"\\u006eame"')), "a key written with an escape, which the Echo does not find: refused")
check(listed_raw(lambda b: b + b"\0more") != "", "a manifest with a NUL and more after it: refused")
check("over 32768 bytes" in said(extra="x" * 32768), "a manifest over 32768 bytes: refused")
deep = lambda n, v=0: v if not n else [deep(n - 1, v)]
takes("a value 64 deep: built", extra=deep(63))
refuses("65 deep: refused", "nested more than 64 deep", extra=deep(64))
refuses("NaN, which is no JSON: refused", "NaN is no JSON", extra=float("nan"))

# the text as a whole (the Echo's form()): also where the Echo reads nothing, in keys of its own and in a catalog
at_caps = lambda more: lambda b: b.replace(b'"capabilities"', more + b', "capabilities"')
check(listed_raw(lambda b: b + b"\n \t\r") == "", "white space after the manifest: built")
check(listed_raw(lambda b: b" " + b) != "", "white space before it: refused")
check(listed_raw(lambda b: b"\xef\xbb\xbf" + b) != "", "a byte order mark before it")
check(listed_raw(lambda b: b + b" {}") != "" and "not JSON as the Echo reads it" in in_raw(lambda b: b + b" {}"), "a second value after it")
check(listed_raw(lambda b: b + b"\0") != "", "a NUL after it")
check("not one JSON object" in refused(index.manifest_check, b"[" + seen[0] + b"]", "it", "official"), "a manifest in a list")
takes("a text nobody asked for, with a character written as an escape pair: built", extra="caf\u00e9 \U0001F600")
refuses("a tab written as an escape, in a key the Echo does not read: refused", "control character", extra="two\twords")
refuses("a \\u0007 there", "control character", extra=["a", {"b": "bell\x07"}])
check("half a character" in listed_raw(at_caps(b'"x": "\\ud83d"')), "half a surrogate pair there")
refuses("a DEL there, as a byte (the Echo refuses the byte anywhere in the manifest)", "control character (0x7f)", extra="\x7f")
refuses("a DEL in a key the Echo does not read", "control character (0x7f)", extra={"a\x7fb": 1})
refuses("a DEL in a catalog's key", "control character (0x7f)", **{"x-catalog": {"items": [{"id\x7f": "a"}]}})
check(raw_says("control character (0x7f)", lambda b: b + b"\x7f") and raw_says("control character (0x7f)", lambda b: b.replace(b'"capabilities"', b'\x7f"capabilities"')),
      "a DEL outside every text, after the manifest or between two fields")
takes("(the characters beside it, ~ and U+0080: built)", extra="~\u0080", license="MIT~")
check("control character" in listed_raw(at_caps(b'"x": "\\u007f"')) and "control character" in listed_raw(at_caps(b'"x": "\\u007F"')), "a DEL written as an escape")
check("half a character" in listed_raw(at_caps(b'"x": "\\udc00\\ud800"')), "a surrogate pair the wrong way round")
check(listed_raw(at_caps(b'"x": "\\uD83D\\uDE00 \\/ \\\\n \\""')) == "", "(a pair, a slash, a backslash before an n, a quote: built)")
check("twice" in listed_raw(at_caps(b'"x": [{"a": 1, "a": 2}]')), "a key twice in an object the Echo does not read: refused")
check("written with an escape" in listed_raw(at_caps(b'"x": [{"\\u0061": 1}]')), "a key written with an escape there")
check(listed_raw(at_caps(b'"x": [1.7e308, -1.7e308, 1e-999, 0.0, -0, -0.0, 1E+2, ' + b"9" * 39 + b', -' + b"9" * 38 + b', 0.' + b"0" * 36 + b'1, 1' + b"0" * 34 + b'e-34]')) == "",
      "numbers as JSON writes them, up to 1.7e308 and of up to 39 characters: built")
for long_number in (b"9" * 40, b"-" + b"9" * 39, b"0." + b"0" * 37 + b"1", b"1" + b"0" * 35 + b"e-35", b"1." + b"0" * 34 + b"E+00", b"9" * 60, b"9" * 5000):
    check(raw_says("more than 39 characters", at_caps(b'"x": {"y": [' + long_number + b']}')),
          f"a number of {len(long_number)} characters ({long_number[:8].decode()}...), in a key the Echo does not read: refused")
check("more than 39 characters" in listed_raw(lambda b: b.replace(b'"memory_mb": 8', b'"memory_mb": 8.' + b"0" * 38)) and
      "memory_mb is 8 to 96" in listed_raw(lambda b: b.replace(b'"memory_mb": 8', b'"memory_mb": ' + b"9" * 39)), "and where it reads one (of 39 digits: no whole number of 32 bits)")
for bad_number in (b"1.75e308", b"-1.75e308", b"1e999", b"01", b"1.", b".5", b"+1", b"1e", b"0x10", b"Infinity", b"-Infinity", b"NaN"):
    check(listed_raw(at_caps(b'"x": ' + bad_number)) != "", f"the number {bad_number.decode()}: refused")
# UTF-8 and nothing else, the whole text (the Echo's utf8_ok): in a text it reads, in one it does not, in a key
for what, no_utf8 in (("a byte that begins no character", b"\xff"), ("a continuation byte alone", b"\x80"), ("a character cut short", b"\xc3"), ("three bytes of four", b"\xf0\x9f\x98"),
                      ("a character written longer than it needs", b"\xc0\xaf"), ("a NUL written in two bytes", b"\xc0\x80"), ("three bytes for one of two", b"\xe0\x81\x81"),
                      ("half a surrogate pair as bytes", b"\xed\xa0\x80"), ("a whole pair as bytes (CESU-8)", b"\xed\xa0\xbd\xed\xb8\x80"), ("a character past U+10FFFF", b"\xf4\x90\x80\x80"),
                      ("a lead byte of five", b"\xf8\x88\x80\x80\x80"), ("Latin-1", b"caf\xe9")):
    check(raw_says("not UTF-8", lambda b: b.replace(b'"A stand-in."', b'"A stand-in' + no_utf8 + b'"')) and raw_says("not UTF-8", at_caps(b'"x": ["a' + no_utf8 + b'b"]'))
          and raw_says("not UTF-8", at_caps(b'"x": {"k' + no_utf8 + b'": 1}')), f"{what}: refused, where the Echo reads, where it does not, and in a key")
check(raw_says("not UTF-8", lambda b: b + b"\xff") and raw_says("not UTF-8", lambda b: b.replace(b'"capabilities"', b'\xff"capabilities"')), "a byte that is no UTF-8 after the manifest, or between two fields")
# (in the licence: a description is the entry's too, and an entry's text has no control character, U+0080 one)
check(listed_raw(lambda b: b.replace(b'"MIT"', b'"\xc2\x80 \xdf\xbf \xe0\xa0\x80 \xed\x9f\xbf \xee\x80\x80 \xef\xbf\xbf \xf0\x90\x80\x80 \xf4\x8f\xbf\xbf"')) == "",
      "(the first and the last character of two, three and four bytes, and the ones around the surrogates: built)")

# id, version, keys: the entry names them, so a build never gets this far with another
check(said(id="abc") == "" and said(id="a" * 24) == "", "an id of 3 and of 24: taken")
# (the Echo's ps_id_ok at 3feeda2: a package's file is <id>-<version>.hmp, and "abc--1.hmp" was version 1 of "abc-")
for good_id in ("a-b", "a-b-c", "0-9", "a1-b2-c3", "ab-" + "c" * 21, "a-" * 11 + "bc", "micro-wake-word"):
    check(said(id=good_id) == "", f"the id {good_id[:10]!r}, hyphens between its parts: taken")
for bad_id in ("ab", "a" * 25, "-abc", "Abc", "a_b", "a.b", "abc-", "ab-", "a--b", "a---b", "ab--", "--a", "-a-", "---", "a-b-", "a" * 23 + "-", "a" * 11 + "--" + "a" * 11, "a-b--c", "a-" * 12 + "b"):
    check("the plugin's id" in said(id=bad_id) or '"id" is not text of at most 24' in said(id=bad_id), f"the id {bad_id[:8]!r}: refused")
check(said(version=1) == "" and said(version=1000000000) == "", "versions 1 and 1000000000: taken")
for bad_version in (0, -1, 1000000001, "3", 1.5, True, None, GONE):
    check("version: a whole number" in said(version=bad_version), f"the version {bad_version if bad_version is not GONE else 'left out'!r:.12}: refused")
check(said(author_key="AB" * 32, digest="0f" * 32) == "", "keys and digests in hex of either case: taken (the Echo's isxdigit)")
check("author_key: 64 hex" in said(author_key="ab" * 31 + "a") and "digest: 64 hex" in said(digest="cd" * 32 + "c") and "digest: 64 hex" in said(digest="g" * 64)
      and '"digest" is missing' in said(digest=GONE), "of 63 or 65 digits, of other letters, or none: refused")

# requires (requires_parse): the least version of each scope it speaks, core and its capabilities' scopes, nothing else
takes("requires core 1 and storage 1, for storage: built", requires={"core": 1, "storage": 1})
takes("(in another order: built)", requires={"storage": 1, "core": 1})
takes("requires core 1 and nothing else, for no capability: built", capabilities={}, requires={"core": 1})
takes("files, wake: core 1, files 1, wake 1", capabilities={"wake": True, "files": 8}, requires={"core": 1, "files": 1, "wake": 1})
check('the manifest has no "requires": the least version of each scope it speaks, {"core": 1, ...}' in said(requires=GONE), "no requires: refused, in the Echo's words")
for value in ([], [["core", 1]], "core 1", 1, None, True):
    check('the manifest has no "requires"' in said(requires=value), f"requires that is {json.dumps(value)}: refused (an object)")
check('"requires" names no version of core, which every plugin speaks' in said(requires={"storage": 1}), "requires without core: refused")
check('"requires" names no version of core' in said(capabilities={}, requires={}), "an empty requires: refused (no core)")
check('capability "storage": its scope is not in "requires" ("storage": the least version it speaks)' in said(requires={"core": 1}),
      "a capability whose scope requires does not name: refused")
check('capability "wake": its scope is not in "requires"' in said(capabilities={"wake": True, "files": 8}, requires={"core": 1, "files": 1}), "(one of two left out too)")
check('"requires" names files, which the manifest does not ask for' in said(requires={"core": 1, "storage": 1, "files": 1}),
      "a scope required whose capability it does not ask for: refused")
check('"requires" names button, which the manifest does not ask for' in said(capabilities={}, requires={"core": 1, "button": 1}), "(and with no capability at all)")
check("no hassmic has storage 2 yet" in said(requires={"core": 1, "storage": 2}), "a scope's version no hassmic has (SCOPES): refused")
check("no hassmic has core 2 yet" in said(requires={"core": 2, "storage": 1}), "core 2 too")
check("no hassmic has future.scope 1 yet" in said(requires={"core": 1, "storage": 1, "future.scope": 1}), "a scope no hassmic knows: refused, as a later hassmic's")
check("no hassmic has storage 7, core 3, a_b 1 yet" in said(requires={"storage": 7, "core": 3, "a_b": 1}), "each one named, in the manifest's order")
check("no hassmic has storage 2 yet" in said(requires={"storage": 2}), "(before core is asked for, as requires_parse asks)")
check("no hassmic has storage 65535 yet" in said(requires={"core": 1, "storage": 65535}), "65535: a version, and none a hassmic has")
for value in (0, -1, 65536, 2 ** 32 + 1, 1.5, "1", True, False, None, [1], {"v": 1}):
    check('"requires": "storage": a version, a whole number from 1' in said(requires={"core": 1, "storage": value}), f"a version {json.dumps(value)}: refused")
check('"requires": "core": a version' in said(requires={"core": 0, "storage": 1}), "core 0: refused")
for name in ("", "Core", "net-lan", "a b", "é", "a" * 25, "storage/1", "-", "a:b"):
    check('"requires": a scope\'s name is 1 to 24 of a-z, 0-9, . and _' in said(requires={"core": 1, "storage": 1, name: 1}), f"a scope named {name[:12]!r}: refused")
check('"requires": a scope\'s name' in said(requires={"Bad": 1, "core": 9}), "a name before a version no hassmic has: the name refused first, as the Echo reads them in order")
check('"' + "a" * 24 + '": a version' in said(requires={"core": 1, "storage": 1, "a" * 24: 0}), "24 bytes are a name (its version, 0, the reason)")
check("no hassmic has " + "a" * 24 + " 1 yet" in said(requires={"core": 1, "storage": 1, "a" * 24: 1}), "(and with 1: a later hassmic's scope)")
for written in (b"1.0", b"1e0", b"-0", b"0.1e1", b"01", b"+1"):
    core_as = lambda r, w=written: r.replace(b'"core": 1,', b'"core": ' + w + b",", 1)   # (requires is the one place "core" is)
    why = in_raw(core_as)
    check(why != "" and listed_raw(core_as) != "",
          f"core written {written.decode()}: refused ({why[:60]})")
check(raw_says("twice", lambda r: r.replace(b'"core": 1,', b'"core": 1, "core": 1,', 1)), "a scope named twice: refused")
check(raw_says("escape", lambda r: r.replace(b'"core": 1,', b'"\\u0063ore": 1,', 1)), "a scope's name written with an escape: refused")

# limits
takes("96 MB and 16 threads: built", memory_mb=96, threads=16)
takes("(8 MB and 1 thread, and neither named: built)", memory_mb=GONE, threads=GONE)
refuses("97 MB: refused", "memory_mb is 8 to 96", memory_mb=97)
refuses("7 MB", "memory_mb is 8 to 96", memory_mb=7)
refuses("17 threads", "threads is 1 to 16", threads=17)
refuses("no thread", "threads is 1 to 16", threads=0)
refuses("\"16\" MB, a text", "memory_mb is 8 to 96", memory_mb="16")
refuses("16.5 MB", "memory_mb is 8 to 96", memory_mb=16.5)
refuses("4294967312 MB, whose low 32 bits are 16", "memory_mb is 8 to 96", memory_mb=4294967312)
refuses("threads that are null", "threads is 1 to 16", threads=None)
refuses("threads that are true", "threads is 1 to 16", threads=True)
check("memory_mb is 8 to 96" in listed_raw(lambda b: b.replace(b'"memory_mb": 8', b'"memory_mb": 16.0')), "16.0 MB, which is not written as a whole number")
check("memory_mb is 8 to 96" in listed_raw(lambda b: b.replace(b'"memory_mb": 8', b'"memory_mb": 1.6e1')), "nor is 1.6e1")
check("version: a whole number" in in_raw(lambda b: b.replace(b'"version": 1', b'"version": 1e0')) and in_raw(lambda b: b) == "", "a version written 1e0: refused")

# models
takes("no models named (every model): built", models=GONE)
takes("one model named: built", models=["donut"])
takes("one that is a name beside one that is none: built, as the Echo skips the other", models=["donut", "Not A Model"])
refuses("no model in the list: refused", "models name no model", models=[])
refuses("models that are one name, not a list", "models are a list of names", models="donut")
refuses("models that are null", "models are a list of names", models=None)
takes("a name of 32 bytes beside it: built", models=["donut", "x" * 32])
refuses("of 33: refused", "models are a list of names", models=["donut", "x" * 33])
refuses("of none", "models are a list of names", models=["donut", ""])
refuses("a number among them", "models are a list of names", models=["*", 5])
refuses("a list among them", "models are a list of names", models=["*", ["donut"]])
refuses("only what no model is called", "models name no model", models=["Not A Model"])
check(said(model="donut", models=["biscuit", "donut"]) == "" and said(model="donut", models=["*"]) == "" and said(model="donut", models=GONE) == "",
      "(asked for one model: its name, \"*\" or no list)")
check("not for this model (donut)" in said(model="donut", models=["biscuit"]) and "not for this model" in said(model="donut", models=[]), "(another model's plugin: not this one's)")

# capabilities
takes("no capability at all: built", capabilities={})
# API 0.6: net.lan and net.internet as the Echo reads them (plugin_store.c reach_parse): a list of 1 to 4 entries of
# exactly proto and ports, 1 to 8 whole ports (never 5555) or "any"
NL, NI = [{"proto": "tcp", "ports": [80, 443]}, {"proto": "udp", "ports": "any"}], [{"proto": "tcp", "ports": [443]}]
takes("net.lan and net.internet as the Echo reads them: built", capabilities={"net.lan": NL, "net.internet": NI})
takes("net.internet at DNS's ports (it has the internet anyway), net.lan at the ports beside them", capabilities={"net.lan": [{"proto": "udp", "ports": [54, 852, 5353]}], "net.internet": [{"proto": "udp", "ports": [53, 853]}]})
for cap_, v_, why_ in (("net.lan", True, "is a list of"), ("net.lan", [], "has no entry"), ("net.internet", [443], "and nothing else"),
                       ("net.lan", [{"proto": "tcp", "ports": [80], "tls": True}], "and nothing else"), ("net.lan", [{"ports": [80]}], "\"proto\" is"),
                       ("net.internet", [{"proto": "sctp", "ports": [80]}], "\"proto\" is"), ("net.lan", [{"proto": "tcp", "ports": [5555]}], "not 5555"),
                       ("net.lan", [{"proto": "tcp", "ports": [0]}], "not 5555"), ("net.lan", [{"proto": "tcp", "ports": ["80"]}], "not 5555"),
                       ("net.internet", [{"proto": "tcp", "ports": "all"}], "or \"any\""), ("net.lan", [{"proto": "tcp", "ports": []}], "names no port"),
                       ("net.lan", [{"proto": "tcp", "ports": list(range(1, 10))}], "ports an entry at most"),
                       ("net.lan", [{"proto": "udp", "ports": [53]}], "asking the internet (DNS)"), ("net.lan", [{"proto": "tcp", "ports": [80, 853]}], "asking the internet (DNS)"),
                       ("net.internet", [{"proto": "tcp", "ports": [1]}] * 5, "entries at most")):
    refuses(f"{cap_} of {json.dumps(v_)[:40]}: refused", why_, capabilities={cap_: v_})
# API 0.3 (hassmic's docs/plugins.md phase 4): net.udp, net.discover, ha.entities, ha.actions as the Echo reads them
# (plugin_store.c ps_manifest_parse, discover_parse, entities_parse, actions_parse)
ENT = {"name": "a", "kind": "sensor", "label": "A"}
ACT = {"name": "go", "label": "Go", "page": True}
OK3 = {"audio.music": True, "audio.volume": True, "state": True, "net.udp": 4, "net.discover": {"udp": 3483, "to": "broadcast"},
       "ha.entities": [ENT, {"name": "b", "kind": "number", "label": "B", "min": -1.5, "max": 10, "step": 0.5, "unit": "dB", "icon": "mdi:volume-high"},
                       {"name": "c", "kind": "select", "label": "C", "options": ["x", "y"]}, {"name": "d", "kind": "event", "label": "D", "types": ["press", "hold"]},
                       {"name": "e", "kind": "sensor", "label": "E", "decimals": 2, "unit": "W"}],
       "ha.actions": [ACT, {"name": "say", "label": "Say", "args": [{"name": "text", "type": "string"}, {"name": "n", "type": "int"}]}]}
takes("API 0.3's capabilities, each as the Echo reads it: built", capabilities=OK3)
takes("net.discover to a multicast group: built", capabilities={"net.discover": {"udp": 1900, "to": "239.255.255.250"}})
def caps3(**over): return {k: v for k, v in dict(OK3, **over).items() if v is not GONE}
for value, why in ((0, "1 to 4 ports"), (5, "1 to 4 ports"), (True, "1 to 4 ports"), ("2", "1 to 4 ports"), (2.0, "1 to 4 ports")):
    refuses(f"net.udp {json.dumps(value)}: refused", why, capabilities=caps3(**{"net.udp": value}))
for value, why in ((3483, "and nothing else"), ({"udp": 3483}, "to is"), ({"udp": 5555, "to": "broadcast"}, "not 5555"), ({"udp": 0, "to": "broadcast"}, "not 5555"),
                   ({"udp": 3483, "to": "10.0.0.255"}, "multicast group"), ({"udp": 3483, "to": "240.0.0.1"}, "multicast group"), ({"udp": 3483, "to": "224.0.0.256"}, "multicast group"),
                   ({"udp": 3483, "to": "239.255.255.025"}, "without zeros"), ({"udp": 3483, "to": "broadcast", "ttl": 4}, "nothing else"), ({"udp": 3483, "to": "Broadcast"}, "multicast group"),
                   ({"udp": 2330, "to": "broadcast"}, "hassmic's own"), ({"udp": 28928, "to": "broadcast"}, "hassmic's own"), ({"udp": 28930, "to": "239.255.255.250"}, "hassmic's own"),
                   ({"udp": 28999, "to": "broadcast"}, "hassmic's own"), ({"udp": 53, "to": "broadcast"}, "asking the internet (DNS)"), ({"udp": 853, "to": "239.255.255.250"}, "asking the internet (DNS)")):
    refuses(f"net.discover {json.dumps(value)}: refused", why, capabilities=caps3(**{"net.discover": value}))
for value, why in (([], "names no entity"), (True, "a list of entities"), ([dict(ENT, kind="light")], "no kind"), ([dict(ENT, name="A")], "a name is 1 to 32"),
                   ([{"name": "a", "kind": "sensor"}], "its label"), ([dict(ENT, label="")], "its label"), ([dict(ENT, kind="switch", unit="W")], "does not read"),
                   ([dict(ENT, icon="fa:x")], "an icon is"), ([dict(ENT, decimals=7)], "decimals 0 to 6"), ([{"name": "a", "kind": "number", "label": "A", "min": 5, "max": 5}], "min below max"),
                   ([{"name": "a", "kind": "number", "label": "A", "step": 0}], "min below max"), ([{"name": "a", "kind": "number", "label": "A", "max": 2e9}], "within a billion"),
                   ([{"name": "a", "kind": "number", "label": "A", "min": "0"}], "min below max"), ([{"name": "a", "kind": "select", "label": "A"}], "are a list"),
                   ([{"name": "a", "kind": "select", "label": "A", "options": []}], "an empty list"), ([{"name": "a", "kind": "select", "label": "A", "options": ["x", "x"]}], "twice"),
                   ([{"name": "a", "kind": "select", "label": "A", "options": [5]}], "options: 1 to 12"), ([{"name": "a", "kind": "event", "label": "A", "types": ["Press"]}], "types: 1 to 8"),
                   ([ENT, ENT], "a twice"), ([dict(ENT, name=f"n{i}", label=f"N{i}") for i in range(17)], "16 at most"), ([dict(ENT, setting="x")], "no such row"),
                   ([ENT, dict(ENT, name="b", kind="switch")], "two are labelled \"A\"")):
    refuses(f"ha.entities {json.dumps(value)[:60]}: refused", why, capabilities=caps3(**{"ha.entities": value}))
for value, why in (([], "names no action"), ([dict(ACT, calls=True)], "needs the capability \"call\""), ([dict(ACT, page=1)], "page is true or false"),
                   ([dict(ACT, args=[{"name": "n", "type": "int"}])], "without arguments"), ([{"name": "go", "label": "Go", "args": [{"name": "n", "type": "float"}]}], "\"string\" or \"int\""),
                   ([{"name": "go", "label": "Go", "args": {"n": "int"}}], "args are a list"), ([{"name": "go", "label": "Go", "args": [{"name": "n", "type": "int"}] * 2}], "an argument twice"),
                   ([{"name": "go", "label": "Go", "args": [{"name": f"a{i}", "type": "int"} for i in range(5)]}], "4 arguments at most"), ([ACT, ACT], "go twice"),
                   ([dict(ACT, name=f"n{i}", label=f"N{i}") for i in range(9)], "8 at most"), ([ACT, dict(ACT, name="go2")], "two are labelled \"Go\"")):
    refuses(f"ha.actions {json.dumps(value)[:60]}: refused", why, capabilities=caps3(**{"ha.actions": value}))
# API 0.4 (phase 5, calls): call, and an action marked "calls" only beside it (plugin_store.c actions_parse)
takes("call, and actions marked calls beside it (one also a button on the card): built",
      capabilities={"call": True, "ha.actions": [dict(ACT, calls=True), {"name": "dial", "label": "Dial", "calls": True, "args": [{"name": "number", "type": "string"}]},
                                                 {"name": "hang_up", "label": "Hang up", "calls": False}]})
refuses("calls that is not true or false: refused", "calls is true or false", capabilities={"call": True, "ha.actions": [dict(ACT, calls="yes")]})
refuses("call beside wake: refused (sealed)", "asks for a way out", capabilities={"wake": True, "call": True})
# API 0.7: button (parameterless, sealed away from wake), and an entity's "page" (plugin_store.c entities_parse: true
# or false, only on a kind with a state, only in a manifest of API 0.7 or later, as a hassmic of 0.6 reads no "page")
takes("button: built", capabilities={"button": True})
refuses("button that is 1: refused", "it has no parameters", capabilities={"button": 1})
refuses("button that is an object: refused", "it has no parameters", capabilities={"button": {"keys": ["action"]}})
refuses("button beside wake: refused (sealed: when a person is at the Echo is a way out)", "asks for a way out", capabilities={"wake": True, "files": 1, "button": True})
PAGED = [dict(ENT, page=True), {"name": "b", "kind": "binary_sensor", "label": "B", "page": True}, {"name": "c", "kind": "text_sensor", "label": "C", "page": True},
         {"name": "d", "kind": "switch", "label": "D", "page": True}, {"name": "e", "kind": "number", "label": "E", "page": True},
         {"name": "f", "kind": "select", "label": "F", "options": ["x"], "page": True}, {"name": "g", "kind": "button", "label": "G", "page": False},
         {"name": "h", "kind": "event", "label": "H", "types": ["p"], "page": False}, {"name": "i", "kind": "sensor", "label": "I", "page": False}]
takes("an entity's page on each kind with a state, false on a button and an event (ha.entities 1): built", capabilities={"ha.entities": PAGED})
for value_, why_ in ((1, "page is true or false"), ("yes", "page is true or false"), (None, "page is true or false")):
    refuses(f"page that is {json.dumps(value_)}: refused", why_, capabilities={"ha.entities": [dict(ENT, page=value_)]})
refuses("page on a button: refused", "has no state to show", capabilities={"ha.entities": [{"name": "g", "kind": "button", "label": "G", "page": True}]})
refuses("page on an event: refused", "has no state to show", capabilities={"ha.entities": [{"name": "h", "kind": "event", "label": "H", "types": ["p"], "page": True}]})
# net.server (API 0.2): its entries as the Echo reads them (plugin_store.c net_parse)
NROWS = [{"name": "server", "label": "Server", "type": "host"}, {"name": "port", "label": "Port", "type": "int", "min": 1, "max": 65535},
         {"name": "wide", "label": "Wide", "type": "int", "min": 0, "max": 65535}, {"name": "mode", "label": "Mode", "type": "select", "options": ["a"]}]
def net(*entries): return dict(capabilities={"storage": 4, "log.read": True, "net.server": list(entries)}, settings=NROWS)
takes("net.server: a UDP server at the port entered, a TCP one at listed ports: built",
      **net({"setting": "server", "proto": "udp", "ports": "setting:port"}, {"setting": "server", "proto": "tcp", "ports": [6514, 443]}))
for e, why in (({"setting": "mode", "proto": "udp", "ports": [514]}, "a row of type host"), ({"setting": "server", "proto": "sctp", "ports": [514]}, "\"tcp\" or \"udp\""),
               ({"setting": "server", "ports": [514]}, "\"tcp\" or \"udp\""), ({"setting": "server", "proto": "udp"}, "a list of ports"),
               ({"setting": "server", "proto": "udp", "ports": []}, "names no port"), ({"setting": "server", "proto": "udp", "ports": [5555]}, "not 5555"),
               ({"setting": "server", "proto": "udp", "ports": [65536]}, "from 1 to 65535"), ({"setting": "server", "proto": "udp", "ports": ["514"]}, "whole number"),
               ({"setting": "server", "proto": "udp", "ports": list(range(1, 10))}, "8 ports"), ({"setting": "server", "proto": "udp", "ports": "setting:wide"}, "type int from 1"),
               ({"setting": "server", "proto": "udp", "ports": "setting:mode"}, "type int from 1"), ({"setting": "server", "proto": "udp", "ports": "any"}, "\"setting:<row>\""),
               ({"setting": "server", "proto": "udp", "ports": [514], "any": True}, "does not read"), (5, "an entry is an object")):
    refuses(f"net.server {str(e)[:60]}: refused", why, **net(e))
refuses("net.server: five servers", "4 servers at most", **net(*[{"setting": "server", "proto": "udp", "ports": [514]}] * 5))
# hassmic 08399dc's review (N1): the server and its port are the owner's to enter, a default in either row refused
refuses("net.server: its server row with a default (the author's server)", "where the owner enters the server, has a default",
        capabilities={"net.server": [{"setting": "server", "proto": "udp", "ports": [514]}]}, settings=[dict(NROWS[0], default="198.51.100.7")] + NROWS[1:])
refuses("net.server: its port row with a default", "where the owner enters the port, has a default",
        capabilities={"net.server": [{"setting": "server", "proto": "udp", "ports": "setting:port"}]}, settings=[NROWS[0], dict(NROWS[1], default=514)] + NROWS[2:])
takes("a host row with a default that no net.server entry names: built", capabilities={"storage": 4}, settings=[dict(NROWS[0], default="example.org")])
refuses("net.server: none", "names no server", **net())
refuses("net.server: not a list", "a list of servers", capabilities={"net.server": {"setting": "server"}}, settings=NROWS)
takes("each one that has no parameters, as true: built", capabilities={c: True for c in index.CAPS_PLAIN if c != "wake"})
for plain_cap in index.CAPS_PLAIN:
    refuses(f"{plain_cap} that is 1, not true: refused", "it has no parameters", capabilities={plain_cap: 1})
refuses("wake that is \"yes\"", "it has no parameters", capabilities={"wake": "yes"})
refuses("state that is a list", "it has no parameters", capabilities={"state": []})
refuses("call that is an object", "it has no parameters", capabilities={"call": {}})
check(index.unmet({"core": 1, "wake": 1, "files": 1}) == [] and index.unmet({"x": 3, "storage": 1, "core": 2}) == ["x 3", "core 2"]
      and index.unmet({"button": 1, "core": 1}, {"core": 1, "button": 0}) == ["button 1"] and index.unmet({}) == [],
      "unmet: the versions a table lacks, in the manifest's order, a name it does not know among them")
# rule 48 (hassmic's docs/plugins.md 3.3, 5.3): a community plugin that hears every request does not reach the internet
for tier_, caps_, ok_ in (("community", {"request.audio": True, "net.internet": NI}, False), ("official", {"request.audio": True, "net.internet": NI}, True),
                          ("community", {"request.audio": True, "net.lan": NL}, True), ("community", {"request.text": True, "net.internet": NI}, True),
                          ("community", {"request.audio": True}, True)):
    r_ = said(tier_, capabilities=caps_)
    check((r_ == "") == ok_ and (ok_ or "may not reach the internet" in r_), f"{tier_}, {' and '.join(caps_)}: {'listed' if ok_ else 'not listed'} ({r_ or 'taken'})")
refuses("a manifest without capabilities: refused", 'no "capabilities"', capabilities=GONE)
refuses("capabilities that are a list", 'no "capabilities"', capabilities=["storage"])
refuses("a capability no Echo knows", "which no Echo knows", capabilities={"storage": 4, "net.everything": True})
refuses("one that is false", "leave it out instead of false", capabilities={"state": False})
refuses("one that is null", "leave it out instead of false", capabilities={"call": None})
takes("storage of 1 kB, files of 1 MB: built", capabilities={"storage": 1, "files": 1})
takes("of 1024 kB and 64 MB: built", capabilities={"storage": 1024, "files": 64})
refuses("storage of 1025 kB: refused", '"storage" is 1 to 1024', capabilities={"storage": 1025})
refuses("of none", '"storage" is 1 to 1024', capabilities={"storage": 0})
refuses("storage that is true", '"storage" is 1 to 1024', capabilities={"storage": True})
refuses("files of 65 MB", '"files" is 1 to 64', capabilities={"files": 65})
refuses("files that are a list of names", '"files" is 1 to 64', capabilities={"files": ["models"]})
check("twice" in listed_raw(lambda b: b.replace(b'"storage": 4', b'"storage": 4, "storage": 4')), "a capability twice: refused")

# the rows a capability names (the Echo's refs_ok at 3feeda2): a row the manifest has, and no file list
row = [{"name": "server", "label": "Server", "type": "host"}, {"name": "port", "label": "Port", "type": "int"},
       {"name": "models", "label": "Models", "type": "files", "item": {"by": "stem", "files": [{"suffix": ".bin", "max_kb": 16}]}}]
def names(value, cap="net.lan", rows=row): return dict(capabilities={"files": 8, cap: value}, settings=rows)
NO_ROW = "and the manifest has no such row"
# (since hassmic's API 0.6 no capability takes a value of any form: these values pass rule 45 and are refused after it
# by the capability's own form, net.lan's here, as the Echo refuses them: refs_ok before reach_parse)
def passes45(what, **more):
    r = said(**more); check(r and NO_ROW not in r, what + f" ({r})")
passes45("a capability that names a row the manifest has (\"to\": \"setting:server\"): rule 45 passes it", **names([{"to": "setting:server", "ports": "setting:port"}]))
passes45("named by the entry's own \"setting\": \"server\": passes", **names({"setting": "server"}))
passes45("the text alone as a capability's value, and deep inside one: passes", **names("setting:server", cap="net.internet"))
passes45("(inside a list in an object in a list: passes)", **names([{"setting": "port", "to": ["setting:server"]}], cap="net.lan"))
check(NO_ROW not in said(settings=row, capabilities={"files": 8, "net.lan": [[[[[[{"a": [{"b": {"setting": "port", "to": [[["setting:server"]]]}}]}]]]]]]})
      and NO_ROW in said(settings=row, capabilities={"files": 8, "net.lan": [[[[[[{"a": [{"b": {"setting": "port", "to": [[["setting:nope"]]]}}]}]]]]]]}),
      "(and however deep, where the index's own limit on what it repeats does not stop a build first)")
passes45("a text that only has the word in it, and a key that only begins with it: passes", **names({"to": "a setting:nope", "settings": "nope", "Setting": 5, "setting:nope": "x", "note": "setting"}))
takes("a capability that names rows the manifest has, in the form it reads (net.server): built",
      **names([{"setting": "server", "proto": "udp", "ports": "setting:port"}], cap="net.server", rows=[row[0], dict(row[1], min=1, max=65535), row[2]]))
refuses("one that names a row the manifest does not have: refused", NO_ROW, **names([{"to": "setting:nope"}]))
refuses("with no settings at all", NO_ROW, **names([{"to": "setting:server"}], rows=GONE))
refuses("a row that is a file list is none to name", NO_ROW, **names([{"to": "setting:models"}]))
refuses("nor by \"setting\": \"models\"", NO_ROW, **names({"setting": "models"}))
refuses("\"setting\": \"nope\"", NO_ROW, **names({"setting": "nope"}))
refuses("the name of no row at all (\"setting:\")", NO_ROW, **names("setting:"))
refuses("a row's name and more (\"setting:server \")", NO_ROW, **names("setting:server "))
refuses("a row's name in other letters (\"setting:Server\")", NO_ROW, **names("setting:Server"))
refuses("deep inside a list of lists", NO_ROW, **names([[["x", ["setting:nope"]]]]))
refuses("in the second of two capabilities", NO_ROW, capabilities={"files": 8, "net.lan": [{"to": "setting:server"}], "net.internet": ["setting:nope"]}, settings=row)
for no_name in (5, True, None, ["server"], {"name": "server"}, "", "setting:server", "s" * 34):
    refuses(f"\"setting\": {json.dumps(no_name)[:14]}, which is no row's name", NO_ROW, **names({"setting": no_name}))
takes("(a key \"setting\" outside the capabilities is nobody's: built)", settings=[dict(row[0], setting="nope")], **{"x-note": {"setting": "nope", "to": "setting:nope"}})
# (bytes with a capability added: its scope added to requires as well, speaks() below)
speaks = lambda b, *scopes: b.replace(b'"core": 1,', b'"core": 1, ' + b"".join(b'"' + x.encode() + b'": 1, ' for x in scopes), 1)
check(NO_ROW in listed_raw(lambda b: speaks(b.replace(b'"storage": 4', b'"storage": 4, "net.lan": ["\\u0073etting:nope"]'), "net.lan")), "the text written with an escape (\"\\u0073etting:nope\") is one too: refused")
check(NO_ROW in listed_raw(lambda b: speaks(b.replace(b'"storage": 4', b'"storage": 4, "net.lan": ["setting\\u003anope"]'), "net.lan")), "and with its colon as one")
check(NO_ROW in listed_raw(lambda b: speaks(b.replace(b'"storage": 4', b'"storage": 4, "net.lan": {"setting": "n\\u006fpe"}'), "net.lan")), "and a \"setting\" whose name is")
check(NO_ROW not in listed_raw(lambda b: speaks(b.replace(b'"storage": 4', b'"storage": 4, "net.lan": ["\\u0073etting:server", {"setting": "s\\u0065rver"}], "net.internet": "setting\\u003aserver"').replace(
    b'"capabilities"', b'"settings": [{"name": "server", "label": "Server", "type": "host"}], "capabilities"'), "net.lan", "net.internet")), "(a row the manifest has, named with escapes: rule 45 passes it)")

# combinations
takes("wake with files and storage: built", capabilities={"wake": True, "files": 8, "storage": 4})
for out in ("state", "net.lan", "net.server", "net.internet", "net.udp", "net.discover", "log.read", "log.read.full", "audio.music", "audio.volume",
            "call", "request.audio", "request.text", "ha.entities", "ha.actions", "button"):
    refuses(f"wake with {out}: refused", "asks for a way out", capabilities={"wake": True, out: [{"setting": "server", "proto": "udp", "ports": [514]}] if out == "net.server" else NL if out == "net.lan" else NI if out == "net.internet" else OK3.get(out, True)},
            settings=[{"name": "server", "label": "Server", "type": "host"}])
takes("the whole log for an official plugin: built", capabilities={"log.read.full": True})
check("official plugins only" in said(tier="community", capabilities={"log.read.full": True}) and said(tier="community", capabilities={"log.read": True}) == "",
      "the whole log for any other: refused (the technical log: taken)")

# settings
host = {"name": "server", "label": "Server", "type": "host"}
def setting(**more): return [{k: x for k, x in dict(host, **more).items() if x is not GONE}]
takes("32 settings: built", settings=[dict(host, name=f"s{i}") for i in range(32)])
refuses("33: refused", "more than 32 settings", settings=[dict(host, name=f"s{i}") for i in range(33)])
refuses("two of one name", "setting server twice", settings=[host, dict(host, type="text")])
refuses("a setting that is a name only", "a setting is not an object", settings=["server"])
refuses("settings by name, not in a list", "settings are a list", settings={"server": host})
takes("a setting with a name of 32, a label of 64, a help of 240 and a unit of 12 bytes: built",
      settings=setting(name="n" * 32, label="l" * 64, help="h" * 240, unit="u" * 12))
refuses("a name of 33: refused", "a setting's \"name\" is not text of at most 32", settings=setting(name="n" * 33))
refuses("a label of 65", "a setting's \"label\" is not text of at most 64", settings=setting(label="l" * 65))
refuses("a help of 241", "a setting's \"help\" is not text of at most 240", settings=setting(help="h" * 241))
refuses("a unit of 13", "a setting's \"unit\" is not text of at most 12", settings=setting(unit="u" * 13))
refuses("no label", "a setting's \"label\" is missing", settings=setting(label=GONE))
refuses("no type", "a setting's \"type\" is missing", settings=setting(type=GONE))
for bad_name in ("Server", "my-server", "my server", ""):
    refuses(f"a setting called {bad_name!r}", "lower case letters, digits and _", settings=setting(name=bad_name))
for kind in ("bool", "int", "text", "host", "secret"):
    takes(f"a setting of type {kind}: built", settings=setting(type=kind))
refuses("of a type there is none of: refused", "no type 'colour'", settings=setting(type="colour"))
# a default is of its setting's kind, and one a value typed into the row could be
for kind in ("text", "secret"):
    takes(f"a {kind} with a default of 64 bytes: built", settings=setting(type=kind, default="d" * 64))
    refuses("of 65: refused", "its default is text of at most 64 bytes", settings=setting(type=kind, default="d" * 65))
    for default in (514, True, None, ["a"], {"a": 1}):
        refuses(f"a {kind} whose default is {default!r}", "its default is text", settings=setting(type=kind, default=default))
for default in ("host.example-1.org", "192.168.1.2", "h" * 64, "a", "7", "a-b", "a--b.c", "A.B.C", "xn--bcher-kva.example", "a.b.c.d.e.f", ".".join(["h" * 12] * 5)):
    takes(f"a host whose default is {default!r:.24}: built", settings=setting(default=default))
for default in ("bad host", "a_b", "http://x", "h\u00f6st", "[::1]", "h" * 65, 514, None, True, ["a"], "", "-", ".", "...", ".a", "a.", "a..b", "-a", "a-", "-a.b", "a-.b", "a.-b", "a.b-", "a.b.",
                "a:80", "a/b", "::1", "a.\u00e9", "\uff41.b", "a.b ", " a.b"):
    refuses(f"a host whose default is {default!r:.24}: refused", "its default is a host name", settings=setting(default=default))
takes("a bool whose default is true, one whose default is false: built", settings=setting(type="bool", default=True) + setting(name="other", type="bool", default=False))
for default in (1, 0, "true", None):
    refuses(f"a bool whose default is {default!r}: refused", "its default is true or false", settings=setting(type="bool", default=default))
takes("an int whose default is its min, one whose is its max: built", settings=setting(type="int", min=1, max=65535, default=1) + setting(name="other", type="int", min=1, max=65535, default=65535))
takes("with neither, a default of 1000000: built", settings=setting(type="int", default=1000000))
refuses("of 1000001: refused", "a whole number within min and max", settings=setting(type="int", default=1000001))
for default in (0, 65536, 1.5, "514", True, None):
    refuses(f"an int from 1 to 65535 whose default is {default!r}", "a whole number within min and max", settings=setting(type="int", min=1, max=65535, default=default))
with_setting = lambda text: lambda b: b.replace(b'"capabilities"', b'"settings": [{"name": "s", "label": "S", ' + text + b'}], "capabilities"')
check("a whole number within min and max" in listed_raw(with_setting(b'"type": "int", "default": 5.0')), "an int whose default is written 5.0")
check("a whole number within min and max" in listed_raw(with_setting(b'"type": "int", "min": -5, "default": -0')), "written -0, which is 0 written another way: refused")
check(listed_raw(with_setting(b'"type": "int", "min": -5, "default": 0')) == "" and listed_raw(with_setting(b'"type": "int", "min": -5, "default": -1')) == "", "(written 0, and -1: built)")
check("min is a whole number" in listed_raw(with_setting(b'"type": "int", "min": -0')) and "max is a whole number" in listed_raw(with_setting(b'"type": "int", "max": -0')), "a min or a max written -0")
check("min is a whole number" in listed_raw(with_setting(b'"type": "text", "min": -0')) and "max is a whole number" in listed_raw(with_setting(b'"type": "bool", "max": -0')),
      "also on a setting that is no int (the Echo reads both of every setting)")
check(listed_raw(with_setting(b'"type": "text", "min": 0, "max": 0')) == "" and listed_raw(with_setting(b'"type": "int", "min": 0, "max": 0, "default": 0')) == "", "(written 0: built)")
check("more than 39 characters" in listed_raw(with_setting(b'"type": "int", "default": ' + b"0" * 0 + b"1" * 40)) and "a whole number within min and max" in listed_raw(with_setting(b'"type": "int", "default": ' + b"1" * 39)),
      "an int whose default has 40 digits, and 39")
takes("an int from 1 to 65535, and one from 5 to 5: built", settings=setting(type="int", min=1, max=65535) + setting(name="other", type="int", min=5, max=5))
takes("an int with neither (0 to 1000000): built", settings=setting(type="int"))
refuses("an int whose min is over its max: refused", "min over max", settings=setting(type="int", min=6, max=5))
refuses("an int from 1000001, with no max (1000000)", "min over max", settings=setting(type="int", min=1000001))
takes("(a min of 1000000 there: built)", settings=setting(type="int", min=1000000))
refuses("a max that is \"9\", a text", "max is a whole number", settings=setting(type="int", max="9"))
refuses("a max that is 9.5", "max is a whole number", settings=setting(type="text", max=9.5))
refuses("a min past 32 bits", "min is a whole number", settings=setting(type="int", min=-(1 << 31) - 1))
takes("(the least and the most 32 bits hold: built)", settings=setting(type="int", min=-(1 << 31), max=(1 << 31) - 1))

# select
takes("a select of 12 options, one of 32 bytes, one a number: built", settings=setting(type="select", options=["o" * 32, 5] + [f"o{i}" for i in range(10)]))
refuses("of 13: refused", "its options", settings=setting(type="select", options=[f"o{i}" for i in range(13)]))
refuses("an option of 33 bytes", "its options", settings=setting(type="select", options=["o" * 33]))
refuses("an option of no characters", "its options", settings=setting(type="select", options=["a", ""]))
refuses("an option that is null", "its options", settings=setting(type="select", options=["a", None]))
refuses("an option that is true", "its options", settings=setting(type="select", options=["a", True]))
refuses("an option that is 1.5", "its options", settings=setting(type="select", options=["a", 1.5]))
takes("an option that is a number of 32 digits: built", settings=setting(type="select", options=[int("1" * 32), -int("1" * 31)]))
refuses("of 33: refused", "its options", settings=setting(type="select", options=[int("1" * 33)]))
refuses("an option twice", "the option 'a' twice", settings=setting(type="select", options=["a", "b", "a"]))
refuses("5 and \"5\", which are one to the Echo", "the option '5' twice", settings=setting(type="select", options=[5, "5"]))
refuses("options that are an object", "a select without options", settings=setting(type="select", options={"a": "A"}))
for default in ("fast", 5, "5"):
    takes(f"a select of fast, slow and 5 whose default is {default!r}: built", settings=setting(type="select", options=["fast", "slow", 5], default=default))
for default in ("nope", "", 6, 5.0, True, None, ["fast"]):
    refuses(f"whose default is {default!r}: refused", "its default is one of its options", settings=setting(type="select", options=["fast", "slow", 5], default=default))
check("one of its options" in listed_raw(with_setting(b'"type": "select", "options": [0], "default": -0')), "a select of 0 whose default is written -0")
check("its options" in listed_raw(with_setting(b'"type": "select", "options": [0, -0], "default": 0')) and "its options" in listed_raw(with_setting(b'"type": "select", "options": [-0]')),
      "an option written -0: refused (it would be an option beside 0)")
check(listed_raw(with_setting(b'"type": "select", "options": [0, -1, "-0"], "default": 0')) == "" and listed_raw(with_setting(b'"type": "select", "options": [0, -1, "-0"], "default": "-0"')) == ""
      and listed_raw(with_setting(b'"type": "select", "options": [0, -1, "-0"], "default": -1')) == "", "(0, -1 and the text \"-0\", each the default in turn: built)")
check("one of its options" in listed_raw(with_setting(b'"type": "select", "options": ["-0"], "default": -0')), "a select of the text \"-0\" whose default is the number -0")
refuses("a select without options", "a select without options", settings=setting(type="select"))
refuses("with an empty list of them", "a select without options", settings=setting(type="select", options=[]))
takes("(options on a setting that is no select are not looked at: built)", settings=setting(type="text", options=[None] * 20))
with_option = lambda o: lambda b: b.replace(b'"capabilities"', b'"settings": [{"name": "mode", "label": "Mode", "type": "select", "options": ["' + o + b'"]}], "capabilities"')
check(listed_raw(with_option(b"\\u0061" + b"a" * 26)) == "", "an option of 32 bytes as written, with an escape: built")
check("its options" in listed_raw(with_option(b"\\u0061" + b"a" * 27)), "of 33 as written (28 as read): refused, as the Echo's reader does")

# files
part = {"suffix": ".bin", "max_kb": 64}
field = {"name": "level", "label": "Level", "type": "int", "min": 0, "max": 9}
models = {"name": "models", "label": "Models", "type": "files", "item": {"by": "stem", "files": [part]}}
def files(caps={"files": 8}, item=None, **more):
    s = {k: x for k, x in dict(models, **({"item": item} if item is not None else {}), **more).items() if x is not GONE}
    return {"capabilities": caps, "settings": [s]}
def parts(*p): return {"by": "stem", "files": [{k: v for k, v in dict(part, **x).items() if v is not GONE} for x in p]}
takes("a file list: built", **files())
refuses("without the capability files: refused", 'does not ask for "files"', **files(caps={"storage": 4}))
refuses("items grouped another way", 'grouped "by": "stem"', **files(item={"by": "name", "files": [part]}))
refuses("no item named", 'grouped "by": "stem"', **files(item=GONE))
refuses("an item of no files", "an item has no files", **files(item={"by": "stem", "files": []}))
refuses("an item whose files are missing", "an item has no files", **files(item={"by": "stem"}))
takes("an item of 4 files: built", **files(item=parts(*({"suffix": f".s{i}"} for i in range(4)))))
refuses("of 5: refused", "more than 4 files an item", **files(item=parts(*({"suffix": f".s{i}"} for i in range(5)))))
takes("a suffix of a dot and 15 letters and digits, a file of 16384 kB, kept under a name of 32 bytes: built",
      **files(item=parts({"suffix": ".Abcdefghijklm15", "max_kb": 16384, "as": "a" * 28 + ".bin", "optional": True})))
refuses("a suffix of 17 bytes: refused", "a file's \"suffix\" is not text of at most 16", **files(item=parts({"suffix": ".abcdefghijklmn16"})))
for bad_suffix in ("bin", ".", ".tar.gz", ".b-n", ".b/n", ".b\\n", ".b n", ""):
    refuses(f"the suffix {bad_suffix!r}", "a file's suffix", **files(item=parts({"suffix": bad_suffix})))
refuses("a file without a suffix", "a file's \"suffix\" is missing", **files(item=parts({"suffix": GONE})))
refuses("a file of 16385 kB", "max_kb is 1 to 16384", **files(item=parts({"max_kb": 16385})))
refuses("of 0 kB", "max_kb is 1 to 16384", **files(item=parts({"max_kb": 0})))
refuses("of no size named", "max_kb is 1 to 16384", **files(item={"by": "stem", "files": [{"suffix": ".bin"}]}))
refuses("kept under a name of 33 bytes", "a file's \"as\" is not text of at most 32", **files(item=parts({"as": "a" * 33})))
for bad_as in (".hidden", "a/b", "a b", "fields", "title", "checked", "..", "modél"):
    refuses(f"kept as {bad_as!r}", "a file's name (as)", **files(item=parts({"as": bad_as})))
takes("(kept as \"\": under file + its suffix, as with none named: built)", **files(item=parts({"as": ""})))
refuses("two files of one suffix", "a file twice", **files(item=parts({"as": "one"}, {"as": "two"})))
refuses("two files kept under one name", "a file twice", **files(item=parts({"as": "one"}, {"suffix": ".dat", "as": "one"})))
refuses("a second file kept under the first's own name", "a file twice", **files(item=parts({}, {"suffix": ".dat", "as": "file.bin"})))
refuses("optional that is 1, not true", "optional is true or false", **files(item=parts({"optional": 1})))
takes("64 items: built", **files(max_items=64))
refuses("65: refused", "max_items 1..64", **files(max_items=65))
refuses("no item at all", "max_items 1..64", **files(max_items=0))
takes("8 fields, of each type: built", **files(fields=[dict(field, name=f"f{i}", type=("text", "number", "int")[i % 3]) for i in range(8)]))
refuses("9 fields: refused", "more than 8 fields", **files(fields=[dict(field, name=f"f{i}") for i in range(9)]))
refuses("a field of a type there is none of", "its name or its type", **files(fields=[dict(field, type="bool")]))
refuses("a field called Level", "its name or its type", **files(fields=[dict(field, name="Level")]))
refuses("a field without a label", "a field's \"label\" is missing", **files(fields=[{"name": "level", "type": "int"}]))
refuses("a field with a label of 65 bytes", "a field's \"label\" is not text of at most 64", **files(fields=[dict(field, label="l" * 65)]))
refuses("a field whose max is \"9\", a text", "min, max and step are numbers", **files(fields=[dict(field, max="9")]))
refuses("a field whose step is true", "min, max and step are numbers", **files(fields=[dict(field, step=True)]))
refuses("a field whose min is null", "min, max and step are numbers", **files(fields=[dict(field, min=None)]))
takes("a field from 5 to 5, one from 0.5, one up to 1e9 by default: built", **files(fields=[dict(field, min=5, max=5), {"name": "b", "label": "B", "type": "number", "min": 0.5, "max": 0.5, "step": 0.01},
                                                                                         {"name": "c", "label": "C", "type": "number", "min": 1e9}]))
refuses("a field whose min is over its max: refused", "min over max", **files(fields=[dict(field, min=9, max=0)]))
refuses("a field from 1000000001 with no max (1e9)", "min over max", **files(fields=[{"name": "c", "label": "C", "type": "number", "min": 1000000001}]))
refuses("a field with no min (0) and a max under it", "min over max", **files(fields=[{"name": "c", "label": "C", "type": "number", "max": -0.5}]))
refuses("two fields of one name", "field level twice", **files(fields=[field, dict(field, type="text")]))
with_field = lambda text: lambda b: re.sub(rb'"capabilities": \{\s*"storage": 4\s*\}', b'"settings": [{"name": "m", "label": "M", "type": "files", "item": {"by": "stem", "files": [{"suffix": ".bin", "max_kb": 1}]}, '
                                                                                  b'"fields": [{"name": "f", "label": "F", "type": "number", ' + text + b'}]}], "capabilities": {"files": 1}', b).replace(b'"storage": 1', b'"files": 1', 1)
check(listed_raw(with_field(b'"min": 0.' + b"0" * 36 + b'1')) == "", "a field's number of 39 bytes as written: built")
check("more than 39 characters" in listed_raw(with_field(b'"min": 0.' + b"0" * 37 + b'1')), "of 40: refused, as any number of the manifest")
check("more than 39 characters" in listed_raw(with_field(b'"min": 1' + b"0" * 38 + b'e-38, "max": 5')), "(1 to 5, written so that its first 39 bytes are 1e38)")
check("more than 39 characters" in listed_raw(with_field(b'"step": ' + b"1" * 40)) and listed_raw(with_field(b'"step": ' + b"1" * 39)) == "", "a step of 40 digits (of 39: built)")
check(listed_raw(with_field(b'"min": -0, "max": -0, "step": -0')) == "" and listed_raw(with_field(b'"min": -0.0, "max": 0')) == "", "(a field's numbers written -0, which are no whole numbers to the Echo: built)")
refuses("a default on a file list", "a file list has none", **files(default="a"))
refuses("a default of null there", "a file list has none", **files(default=None))
refuses("an item that is a list", 'grouped "by": "stem"', **files(item=[{"by": "stem", "files": [part]}]))
refuses("files of an item by name, not in a list", "an item has no files", **files(item={"by": "stem", "files": {"a": part}}))
refuses("fields by name, not in a list", "its fields are a list", **files(fields={"level": field}))
refuses("a file whose max_kb is 64.0", "max_kb is 1 to 16384", **files(item=parts({"max_kb": 64.0})))
refuses("a control character in a catalog, which only the page reads", "control character", **files(catalog={"items": [{"id": "a", "title": "A\u0007"}]}))
takes("a catalog, which is the page's to read: built", **files(catalog={"label": "Models", "base": "https://example.org/models/", "items": [{"id": "a", "title": "A"}]}))
open(os.path.join(pkgs, "testplug-1.hmp"), "wb").write(p1)

# ---- held to hassmic's own code: ps_manifest_parse and runnable (which asks combination), compiled as its unit
# test compiles them (Makefile, unit-plugin_store) and asked as its ps_scan asks them, on the manifests above and on
# 400 changed at random (CHANGED, SEED: more, others).  What the Echo refuses is refused here; the other way round
# is counted and said (the index may ask for more, never for less).  One rule of requires_parse's is left out, and
# said: a version one build lacks of a scope (an older hassmic), which the index lists with the version's "requires"
RICH = dict(manifest, author_key="ab" * 32, digest="cd" * 32, memory_mb=16, threads=2, requires={"core": 1, "files": 1, "storage": 1, "wake": 1},
            capabilities={"files": 8, "storage": 4, "wake": True}, settings=[
    {"name": "server", "label": "Server", "type": "host", "help": "Where it sends", "default": "ha.local"},
    {"name": "port", "label": "Port", "type": "int", "min": 1, "max": 65535, "default": 514, "unit": "s"},
    {"name": "mode", "label": "Mode", "type": "select", "options": ["fast", "slow"], "default": "fast"},
    {"name": "on", "label": "On", "type": "bool", "default": True},
    {"name": "key", "label": "Key", "type": "secret"},
    {"name": "models", "label": "Models", "type": "files", "max_items": 16,
     "item": {"by": "stem", "files": [{"suffix": ".json", "max_kb": 16, "optional": True}, {"suffix": ".tflite", "max_kb": 1024, "as": "model.tflite"}]},
     "fields": [{"name": "cutoff", "label": "Cutoff", "type": "number", "min": 0.5, "max": 0.99, "step": 0.01}],
     "catalog": {"label": "Models", "items": [{"id": "a", "title": "A"}]}}])
SIZES = (0, 1, 3, 4, 5, 8, 9, 11, 12, 13, 15, 16, 17, 24, 25, 32, 33, 48, 49, 64, 65, 96, 97, 200, 201, 240, 241, 1023, 1024, 1025, 16384, 16385)
ODD = (None, True, False, 0, 1, -1, 2 ** 31, 2 ** 32 + 16, 10 ** 9, 10 ** 9 + 1, 16.0, 1.5, 1e300, float("nan"), "", "*", "stem", ".bin", "wake", "int", "files", "donut",
       "two\twords", "\x7f", "0.1", "1.0", " 0.1", "00.1", "-", "a.", "AB" * 32, [], {}, ["*"], ["donut"], [1], {"by": "stem"})
KEYS = ("name", "label", "type", "default", "min", "max", "step", "options", "item", "files", "by", "suffix", "as", "max_kb", "optional", "max_items", "fields",
        "help", "unit", "models", "settings", "capabilities", "memory_mb", "threads", "version", "requires", "core", "id") + index.CAPS + ("bogus",)
DEFAULTS = ("fast", "slow", "nope", "", 5, "5", 0, 1, 514, 65535, 65536, -1, 0.5, 5.0, True, False, None, "host.name", "1.2.3.4", "bad host", "a_b", "höst", "d" * 64, "d" * 65, ["fast"],
            "-", ".", "...", "a.", ".a", "a..b", "-a.b", "a-.b", "a.-b", "a.b-", "a-b.c-d", "a--b", "h" * 63 + ".", ("h" * 31 + ".") * 2 + "h")
OPTIONS = (["a", "a"], [5, "5"], [5, 5], [5, 6], ["5", "fast"], [1.5], [True], [None], [], {}, ["fast", "slow", "fast"], [int("1" * 32)], [int("1" * 33)], ["o" * 32], ["o" * 33], "fast")
# ids as ps_id_ok takes and refuses them at 3feeda2, and what a capability says of a settings row (refs_ok): RICH's
# rows are server, port, mode, on, key, and models, which is a file list
IDS = ("abc", "a-b", "a-b-c", "ab-cd-ef", "a1-2b", "a" * 24, "a-" * 11 + "bc", "abc-", "ab-", "-abc", "a--b", "a---b", "ab--", "--ab", "-a-", "---", "a-b-", "a" * 23 + "-", "a" * 22 + "-a",
       "a" * 11 + "--" + "a" * 11, "a-" * 12 + "a", "a-b--c", "ab", "a-", "a_b", "A-b", "a-b ", "a\u2010b")
ROWS = ("server", "port", "mode", "on", "key", "models", "nope", "", "Server", "server ", " server", "server:", "setting:server", "cutoff", "n0", "o0", "s" * 32, "s" * 33, "s" * 34, "é", "a/b")
REFS = tuple("setting:" + n for n in ROWS) + ("setting", "setting:", "settings:server", "Setting:server", " setting:server", "x setting:nope", "setting :server", "setting:server:port")
def ref(g):
    """a capability's value that names rows, one way or several"""
    how = g.randrange(9)
    if how == 0: return g.choice(REFS)
    if how == 1: return [{"to": g.choice(REFS), "ports": g.choice(REFS + ("any", [80]))}]
    if how == 2: return {"setting": g.choice(ROWS + (5, True, None, ["server"], {"name": "server"}, 1.5))}
    if how == 3: return [g.choice(REFS), [g.choice(REFS)], {"a": {"b": [g.choice(REFS)]}}]
    if how == 4: return {"setting": g.choice(ROWS), "to": g.choice(REFS)}
    if how == 5: return [{"x": [{"setting": g.choice(ROWS)}]}, g.choice(REFS)]
    if how == 6: return {g.choice(REFS): "x", "settings": g.choice(ROWS), "Setting": g.choice(ROWS), "setting ": "nope"}      # (keys are not read as texts)
    if how == 7: return {"setting": {"setting": g.choice(ROWS)}}
    return [g.choice(ROWS), {"to": "setting:server"}, {"setting": "port"}]
PARAM = ("net.server", "net.lan", "net.internet", "net.udp", "net.discover", "ha.entities", "ha.actions")     # capabilities with a value (net.server and API 0.3's: read, below)
def nets(g):
    """net.server's value, near what the Echo takes (plugin_store.c net_parse): RICH's rows, and every way one is not"""
    def entry():
        e = {"setting": g.choice(("server", "server", "server", "port", "mode", "models", "nope", 5, "")), "proto": g.choice(("udp", "tcp", "tcp", "sctp", "UDP", 5)),
             "ports": copy.deepcopy(g.choice(([514], [514, 6514], [1, 65535], [], [5555], [0], [65536], ["514"], list(range(1, 9)), list(range(1, 10)), "setting:port", "setting:port",
                                              "setting:mode", "setting:server", "setting:nope", "any", [514.0], [-1], 514, None, {"p": 1})))}
        for k in g.sample(("setting", "proto", "ports"), g.choice((0, 0, 0, 0, 1))): del e[k]
        if g.random() < 0.1: e[g.choice(("any", "to", "Ports"))] = True
        return e
    v = [entry() for _ in range(g.choice((1, 1, 2, 4, 5, 0)))]
    return g.choice((v, v, v, v, v[0] if v else {}, "setting:server", 0))
def p4(g, cap):
    """API 0.3's capabilities with parameters, near what the Echo takes (plugin_store.c ps_manifest_parse's net.udp,
    discover_parse, entities_parse, actions_parse), and every way one is not"""
    pick = lambda *xs: copy.deepcopy(g.choice(xs))
    if cap == "net.udp": return pick(1, 2, 4, 0, 5, -1, True, "2", 2.0, [2], None)
    if cap == "net.discover":
        v = {"udp": pick(3483, 1900, 1, 65535, 5555, 0, 65536, "3483", 3483.0, None, 2330, 28928, 28930, 28999, 29000, 28927, 53, 853), "to": pick("broadcast", "broadcast", "239.255.255.250", "224.0.0.1", "239.255.255.255",
             "240.0.0.1", "223.255.255.255", "10.0.0.255", "239.255.255.025", "239.1.1", "Broadcast", "", "239.255.255.250 ", 5)}
        if g.random() < 0.15: del v[g.choice(("udp", "to"))]
        if g.random() < 0.1: v[g.choice(("ttl", "port", "group"))] = 1
        return g.choice((v, v, v, [v], 3483))
    if cap == "ha.entities":
        def ent(i):
            kind = g.choice(index.ENTITY_KINDS + ("light", ""))
            e = {"name": pick(f"e{i}", f"e{i}", f"e{i}", "A", "", "a" * 33, "a-b"), "kind": kind, "label": pick("L", "L", "Lé", "", "x" * 65)}
            if g.random() < 0.3: e["icon"] = pick("mdi:music", "mdi:", "fa:x", "mdi:Music")
            if kind in ("sensor", "number") and g.random() < 0.5: e["unit"] = pick("W", "dB", "x" * 13)
            if kind == "sensor" and g.random() < 0.4: e["decimals"] = pick(0, 6, 7, -1, 1.5)
            if kind == "number":
                for k in ("min", "max", "step"):
                    if g.random() < 0.5: e[k] = pick(0, 1, -1.5, 10, 100, 0.5, 2e9, -2e9, "1", 0.0)
            if kind in ("select", "event"):
                key = "options" if kind == "select" else "types"
                if g.random() < 0.9: e[key] = pick(["a", "b"], ["a"], [], ["a", "a"], ["A"], [5], ["x"] * 13, [f"t{k}" for k in range(9)], "a")
            if g.random() < 0.1: e[g.choice(("unit", "options", "types", "decimals", "min", "setting", "calls"))] = pick("x", 1, ["a"])
            if g.random() < 0.3: e["page"] = pick(True, True, False, 1, "yes", None)
            return e
        v = [ent(i) for i in range(g.choice((1, 1, 2, 3, 0, 17)))]
        if v and g.random() < 0.1: v.append(copy.deepcopy(v[0]))
        return g.choice((v, v, v, v, v[0] if v else {}, True))
    def act(i):
        a = {"name": pick(f"a{i}", f"a{i}", "A", "", "a" * 33), "label": pick("Go", "Go", "", "x" * 65)}
        if g.random() < 0.5: a["page"] = pick(True, False, 1, "yes")
        if g.random() < 0.6: a["args"] = [{"name": pick(f"n{k}", f"n{k}", "N", "n0"), "type": pick("int", "string", "float", "")} for k in range(g.choice((0, 1, 2, 4, 5)))]
        if g.random() < 0.1: a[g.choice(("calls", "args", "icon"))] = pick(True, {"n": "int"}, "x")
        return a
    v = [act(i) for i in range(g.choice((1, 1, 2, 0, 9)))]
    if v and g.random() < 0.1: v.append(copy.deepcopy(v[0]))
    return g.choice((v, v, v, v, v[0] if v else {}, True))
MODELS = (["*"], ["donut"], ["biscuit"], ["biscuit", "donut"], [""], ["*", ""], ["*", 5], ["*", None], ["*", "x" * 32], ["*", "x" * 33], [["*"]], "*", None, {"a": "*"}, [], ["Not A Model", "donut"])
ESCAPES = (b"\\n", b"\\t", b"\\r", b"\\b", b"\\f", b"\\u0000", b"\\u0007", b"\\u001f", b"\\u001F", b"\\u0020", b"\\u007f", b"\\u007F", b"\\u0080", b"\\ud800", b"\\udc00", b"\\uD83D\\uDE00",
           b"\\ud83dx", b"\\ud83d\\n", b"\\ud83d\\u0041", b"\\udc00\\ud800", b"\\/", b"\\\\n", b"\\\"", b"\x7f", b"\xc3\xa9", b"\xff", b"\xc3", b"\xed\xa0\x80",
           b"\x80", b"\xc0\x80", b"\xc1\xbf", b"\xe0\x9f\xbf", b"\xed\x9f\xbf", b"\xee\x80\x80", b"\xed\xbf\xbf", b"\xf0\x8f\xbf\xbf", b"\xf0\x9f\x98\x80", b"\xf0\x9f\x98",
           b"\xf4\x8f\xbf\xbf", b"\xf4\x90\x80\x80", b"\xf8\x88\x80\x80\x80", b"~", b"\xc2\x80")
NUMBERS = (b"1.7e308", b"1.75e308", b"-1.75e308", b"1e999", b"-1e999", b"1e-999", b"01", b"-01", b"1.", b".5", b"+1", b"1e", b"1e+", b"-", b"0x10", b"1-2", b"1.2.3", b"--1", b"-0", b"0.0", b"1E2",
           b"9" * 60, b"0." + b"0" * 60 + b"1", b"NaN", b"Infinity", b"-Infinity", b"nul", b"True",
           b"9" * 39, b"9" * 40, b"-" + b"9" * 38, b"-" + b"9" * 39, b"0." + b"0" * 36 + b"1", b"0." + b"0" * 37 + b"1", b"1" + b"0" * 34 + b"e-34", b"1" + b"0" * 35 + b"e-35", b"-0.0", b"-0e0", b"0", b"-1")
# the bytes themselves, one way each: what json.dumps would not write
BYTES = (
    lambda r, g: r + b"\0more",
    lambda r, g: g.choice((b" ", b"\n", b"\xef\xbb\xbf", b"[", b"\0")) + r,
    lambda r, g: r + g.choice((b"\n", b" \t\r\n", b" {}", b"{}", b",", b"x", b"\0", b" \0", b"}", b"1", b'""', b"]", b" null")),
    lambda r, g: r[:-1] + g.choice((b"", b" ", b",}")),
    lambda r, g: r.replace(b'"threads": 2', b'"threads": ' + g.choice((b"2.0", b"02", b"2e0", b"-0", b"+2", b'"2"', b"true", b"null", b"16", b"17"))),
    lambda r, g: r.replace(b'"memory_mb": 16', b'"memory_mb": ' + g.choice((b"1.6e1", b"16.0", b"016", b"4294967312", b"9" * 30, b"-16"))),
    lambda r, g: r.replace(b'"version": 1,', b'"version": ' + g.choice((b"1.0", b"1e0", b"01", b"0", b"-1", b"1000000000", b"1000000001", b"10000000000", b"99999999999")) + b","),
    lambda r, g: r.replace(b'"name"', b'"\\u006eame"', g.choice((1, 2))),
    lambda r, g: r.replace(b'"label"', b'"l\\u0061bel"', 1),
    lambda r, g: r.replace(b'"wake"', b'"wa\\u006be"'),
    lambda r, g: r.replace(b'"title"', b'"t\\u0069tle"'),
    lambda r, g: r.replace(b'"Test plugin"', b'"' + b"\\u0041" * g.choice((8, 9, 170, 171)) + b'"'),
    lambda r, g: r.replace(b'"fast", ', b'"f\\u0061' + b"s" * g.choice((25, 26, 27)) + b'", '),
    lambda r, g: r.replace(b'"core": 1', b'"core": ' + g.choice((b"1.0", b"1e0", b"01", b"+1", b"-0", b"0", b"2", b"65535", b"65536", b'"1"', b"true", b"null", b"[1]",
                                                            b'1, "core": 1', b'1, "c\\u006fre": 1', b'1, "future": 1', b'1, "": 1', b'1, "Files": 1', b'1, "files": 1')), 1),
    lambda r, g: r.replace(b'"requires": {', g.choice((b'"requires": {"' + g.choice(index.CAPS + ("bogus", "x" * 24, "x" * 25)).encode() + b'": ' + g.choice((b"1", b"2", b"0")) + b", ",
                                                         b'"requires": [], "x-was": {', b'"x-requires": {')), 1),
    lambda r, g: r.replace(b'"max_items": 16', b'"max_items": ' + g.choice((b"1e999", b"16.0", b"1.6e1", b"64", b"65", b"0", b"-0", b"064"))),
    # texts and keys the Echo does not read, and the catalog
    lambda r, g: r.replace(b'"title": "A"', b'"title": "A' + g.choice(ESCAPES) + b'"'),
    lambda r, g: r.replace(b'{', b'{"x-note": "a' + g.choice(ESCAPES) + b'b", ', 1),
    lambda r, g: r.replace(b'"Where it sends"', b'"Where' + g.choice(ESCAPES) + b'"'),
    lambda r, g: r.replace(b'"Key"', b'"K' + g.choice(ESCAPES) + b'"'),
    lambda r, g: r.replace(b'"id": "a"', b'"i' + g.choice(ESCAPES) + b'": "a"'),
    lambda r, g: r.replace(b'"label": "Models", "items"', g.choice((b'"label": "Models", "label": "M", "items"', b'"items": [], "label": "Models", "items"', b'"a": {"b": 1, "c": 2, "b": 3}, "items"',
                                                                    b'"a": [{"b": 1}, {"b": 1}], "items"'))),
    lambda r, g: r.replace(b'{', g.choice((b'{"zz": 1, "zz": 2, ', b'{"zz": {"zz": 1}, ', b'{"id": "testplug", ', b'{"capabilities": {}, ', b'{"settings": [], ')), 1),
    lambda r, g: r.replace(b'"wake": true', g.choice((b'"wake": true, "wake": true', b'"wake": true, "state": true, "state": true', b'"wake": 1', b'"wake": "true"', b'"wake": [true]'))),
    lambda r, g: r.replace(b'{', b'{"zz": ' + g.choice(NUMBERS) + b', ', 1),
    lambda r, g: r.replace(b'"id": "a"', b'"id": "a", "n": [' + g.choice(NUMBERS) + b']'),
    lambda r, g: r.replace(b'"max_kb": 16,', b'"max_kb": ' + g.choice(NUMBERS[:22] + (b"16.0", b"1.6e1", b"016", b"16384", b"16385")) + b','),
    # numbers a field is held to
    lambda r, g: r.replace(b'"min": 0.5, "max": 0.99', g.choice((b'"min": 0.99, "max": 0.5', b'"min": 0.5, "max": 0.5', b'"max": "9"', b'"min": 2e9', b'"min": 1e9', b'"max": -1', b'"max": -0.0', b'"min": true',
                                                                 b'"min": null, "max": 1', b'"min": 1e999', b'"min": -1e308, "max": 1.7e308', b'"min": 0.' + b"0" * 36 + b'1', b'"min": 0.' + b"0" * 37 + b'1',
                                                                 b'"min": 1' + b"0" * 38 + b'e-38, "max": 5', b'"min": 5, "max": 1' + b"0" * 38 + b'e-38', b'"min": 0.' + b"0" * 40 + b'1e41, "max": 5',
                                                                 b'"min": ' + b"9" * 39, b'"min": ' + b"9" * 40))),
    lambda r, g: r.replace(b'"step": 0.01', b'"step": ' + g.choice(NUMBERS)),
    # options and defaults as they are written
    lambda r, g: r.replace(b'["fast", "slow"], "default": "fast"', g.choice((b'[0, -0], "default": -0', b'[0], "default": -0', b'["0"], "default": 0', b'[0], "default": "0"', b'["-0"], "default": -0',
                                                                            b'[5], "default": 5.0', b'[5], "default": 5e0', b'["f\\u0061st"], "default": "fast"', b'["fast"], "default": "f\\u0061st"',
                                                                            b'[' + b"1" * 32 + b'], "default": ' + b"1" * 32, b'[' + b"1" * 33 + b'], "default": ' + b"1" * 33, b'[1], "default": 01',
                                                                            b'["\xc3\xa9"], "default": "\\u00e9"', b'["a", "\\u0061"]', b'[1, 1.0]', b'[1, "1"]', b'[-1, "-1"], "default": -1',
                                                                            b'[-0]', b'[0, -1], "default": -1', b'[0, -1], "default": 0', b'[0, "-0"], "default": "-0"', b'[0, "-0"], "default": -0',
                                                                            b'[-00]', b'[-01]', b'[-10], "default": -10'))),
    lambda r, g: r.replace(b'"default": 514', b'"default": ' + g.choice((b"514.0", b"5.14e2", b"0514", b"-0", b"1", b"65535", b"65536", b"0", b'"514"', b"true", b"null", b"99999999999"))),
    # the rules of 4d907f1 (they stand at 3feeda2): -0 where a whole number is read, a host's default, 0x7f and bytes that are no UTF-8 anywhere
    lambda r, g: r.replace(b'"min": 1, "max": 65535, "default": 514', g.choice((b'"min": -0, "max": 65535, "default": 514', b'"min": 0, "max": -0, "default": 0', b'"min": 0, "max": 0, "default": -0',
                                                                              b'"min": 0, "max": 0, "default": 0', b'"min": -1, "max": 0, "default": -0', b'"min": -1, "max": 0, "default": -1',
                                                                              b'"min": -0, "max": -0', b'"min": -00', b'"max": -0.0', b'"min": ' + b"1" * 40, b'"max": ' + b"1" * 39))),
    lambda r, g: r.replace(b'"label": "Key"', b'"label": "Key", ' + g.choice((b'"min": -0', b'"max": -0', b'"min": 0, "max": 0', b'"min": -1, "max": -2', b'"max": 1.0', b'"min": "0"'))),
    lambda r, g: r.replace(b'"default": "ha.local"', b'"default": "' + g.choice((b"", b"-", b".", b"..", b"a", b"a.", b".a", b"a..b", b"-a", b"a-", b"a-b", b"a.-b", b"a-.b", b"1.2.3.4", b"1.2.3.4.", b"a_b", b"a b",
                                                                                 b"A-1.b-2.C", b"h\\u0061.local", b"h\\u002e", b"\\u002d", b"a\xc3\xa9", b"a\x7f", b"h" * 64, b"h" * 65, b"h" * 63 + b".")) + b'"'),
    lambda r, g: (lambda at: r[:at] + g.choice((b"\x7f", b"\xff", b"\x80", b"\xc3", b"\xc0\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xc3\xa9", b"\xf0\x9f\x98\x80")) + r[at:])(g.randrange(len(r) + 1)),
    lambda r, g: r.replace(b'"wake": true', b'"wake": true, "storage": ' + g.choice((b"-0", b"0", b"1", b"1024", b"1025", b"01", b"1.0", b"1" * 40))),
    lambda r, g: r.replace(b'"default": true', b'"default": ' + g.choice((b"false", b"1", b"0", b'"true"', b"null", b"[true]"))),
    # the rules of 3feeda2: an id's hyphens, and the rows a capability names, as they are written
    lambda r, g: r.replace(b'"id": "testplug"', b'"id": "' + g.choice((b"a-b", b"abc-", b"a--b", b"-abc", b"a\\u002db", b"abc\\u002d", b"a\\u002d-b", b"a-\\u002db", b"ab\\u002d\\u002d", b"a-b-c",
                                                                     b"a\\u002db\\u002dc", b"abc\\u002D")) + b'"'),
    lambda r, g: r.replace(b'"storage": 4', b'"storage": 4, "' + g.choice(PARAM).encode() + b'": ' + g.choice((
        b'"\\u0073etting:server"', b'"\\u0073etting:nope"', b'"setting\\u003aserver"', b'"setting\\u003anope"', b'"setting:s\\u0065rver"', b'"setting:serv\\u0045r"', b'"setting:models"',
        b'"setting:\\u006dodels"', b'"\\/setting:nope"', b'"setting:server\\/"', b'"s\\u0065tting:"', b'"SETTING:nope"', b'["x", "setting:port", ["setting:\\u0070ort"]]',
        b'{"setting": "s\\u0065rver"}', b'{"setting": "n\\u006fpe"}', b'{"setting": "\\u006dodels"}', b'{"setting": "server", "setting ": "nope"}', b'{"setting": 5}', b'{"setting": null}',
        b'{"setting": ["server"]}', b'{"setting": "setting:server"}', b'{"a": {"setting": "' + b"\\u0073" * g.choice((1, 32, 33, 34, 170, 171)) + b'"}}',
        b'[{"setting": "port"}, {"setting": "key"}, {"to": "setting:mode", "on": "setting:on"}]', b'"setting:' + b"\\u0073" * g.choice((1, 32, 33, 200)) + b'"',
        b'"setting:server\xc3\xa9"', b'"setting:\xf0\x9f\x98\x80"', b'{"setting": "\xc3\xa9"}'))),
    lambda r, g: r.replace(b'"settings": [', g.choice((b'"x-note": {"setting": "nope", "to": "setting:nope"}, "settings": [', b'"x-note": ["setting:nope"], "settings": [',
                                                      b'"settings": [{"name": "nope", "label": "setting:gone", "type": "text", "default": "setting:gone", "setting": "gone"}, '))),
)

def changed(rng):
    """RICH with one to three things about it changed, as bytes"""
    m = copy.deepcopy(RICH)
    if rng.random() < 0.3:                      # (not sealed by wake: the other capabilities get their turn)
        del m["capabilities"]["wake"]
    for _ in range(rng.choice((1, 1, 1, 2, 3))):
        spots = []
        def walk(v):
            for k in (v if isinstance(v, dict) else range(len(v)) if isinstance(v, list) else ()):
                spots.append((v, k)); walk(v[k])
        walk(m)
        c, k = rng.choice(spots)
        v, how = c[k], rng.randrange(15)
        settings = [s for s in m.get("settings", []) if isinstance(s, dict)] if isinstance(m.get("settings"), list) else []
        if how == 0:
            del c[k]
        elif how == 1 and isinstance(v, str):
            c[k] = (v[:1] if v[:1] == "." else "") + rng.choice(("a", "é", "A", "7", "_", "-", ".", " ")) * rng.choice(SIZES[:28])
        elif how == 2 and type(v) in (int, float):
            c[k] = rng.choice(SIZES) * rng.choice((1, 1, 1, -1)) + rng.choice((0, 0, 0, 0.5))
        elif how == 3 and isinstance(v, list) and v:
            more = []
            for i in range(rng.choice(SIZES[:21])):
                x = copy.deepcopy(v[-1])
                if isinstance(x, dict) and rng.random() < 0.9:
                    if "name" in x: x["name"] = f"n{i}"
                    if "suffix" in x: x["suffix"] = f".s{i}"; x.pop("as", None)
                more.append(f"o{i}" if isinstance(x, str) else x)
            c[k] = more
        elif how == 4 and isinstance(v, dict):
            v[rng.choice(KEYS)] = rng.choice(ODD + SIZES[:12])
        elif how in (5, 6) and isinstance(m.get("capabilities"), dict):
            m["capabilities"][rng.choice(index.CAPS + ("bogus",))] = rng.choice((True, True, True, True, 1, 4, 64, 65, 1024, 1025, False, None, [], "x", 2.5, {"ports": [80]}))
        elif how == 7 and settings:
            rng.choice(settings)["default"] = rng.choice(DEFAULTS)
        elif how == 8 and settings:
            s = rng.choice(settings)
            s["type"] = rng.choice(index.SETTING_TYPES + ("select", "select"))
            if rng.random() < 0.7: s["options"] = copy.deepcopy(rng.choice(OPTIONS))
            if rng.random() < 0.5: s["default"] = rng.choice(DEFAULTS)
        elif how == 9:
            m["models"] = copy.deepcopy(rng.choice(MODELS))
        elif how == 10 and settings and isinstance(settings[-1].get("fields"), list) and settings[-1]["fields"] and isinstance(settings[-1]["fields"][0], dict):
            f = copy.deepcopy(settings[-1]["fields"][0])
            f.update(rng.choice(({}, {"name": "other"}, {"name": "other", "min": 5, "max": 4}, {"name": "other", "min": 5, "max": 5}, {"name": "other", "max": -1},
                                 {"name": "other", "min": 1e9 + 1}, {"name": "other", "step": "1"}, {"name": "other", "type": "int", "min": True})))
            settings[-1]["fields"].append(f)
        elif how == 11:
            m["id"] = rng.choice(IDS)
        elif how in (12, 13) and isinstance(m.get("capabilities"), dict):
            # (a capability with parameters is one this build has no code behind: without wake, or the combination refuses it first)
            if rng.random() < 0.8: m["capabilities"].pop("wake", None)
            cap = rng.choice(PARAM)
            m["capabilities"][cap] = (nets(rng) if cap == "net.server" else reach(rng) if cap in ("net.lan", "net.internet") else p4(rng, cap)) \
                if cap in ("net.server", "net.lan", "net.internet", "net.udp", "net.discover", "ha.entities", "ha.actions") and rng.random() < 0.8 else ref(rng)
            if settings and rng.random() < 0.25:            # and now and then the row it names goes, or becomes a file list's name
                s = rng.choice(settings)
                if rng.random() < 0.5 and s in m["settings"]: m["settings"].remove(s)
                else: s["name"] = rng.choice(ROWS)
        else:
            c[k] = rng.choice(ODD + SIZES[:12])
    # what it speaks: mostly what a manifest of those capabilities says (plugcheck.requires_for: the change above
    # then is what is tried), now and then requires itself changed (every way requires_parse reads it, and does not)
    if isinstance(m.get("capabilities"), dict) and rng.random() < 0.85:
        m["requires"] = plugcheck.requires_for(m["capabilities"])
        if rng.random() < 0.3:                  # (in another order: the order is the manifest's, never a reason)
            m["requires"] = dict(rng.sample(list(m["requires"].items()), len(m["requires"])))
    elif rng.random() < 0.9:
        r = m.get("requires") if isinstance(m.get("requires"), dict) else {}
        how = rng.randrange(8)
        if how == 0: m.pop("requires", None)
        elif how == 1: r.pop("core", None)
        elif how == 2: r[rng.choice(list(r) or ["core"])] = rng.choice((2, 3, 65535, 65536, 0, -1, 1.0, "1", True, None))
        elif how == 3: r[rng.choice(index.CAPS)] = 1                       # a scope it may not ask for
        elif how == 4: r[rng.choice(("future", "net.lan2", "a" * 24, "zz_9.x"))] = rng.choice((1, 1, 2))   # one no hassmic has
        elif how == 5: r[rng.choice(("", "Core", "a" * 25, "net-lan", "é", "a b", "a/b"))] = 1
        elif how == 6 and r: r.pop(rng.choice(list(r)))                    # a capability's scope left out
        else: m["requires"] = rng.choice(([], "core", 1, None, [["core", 1]], {}))
        if how not in (0, 7): m["requires"] = r
    raw = json.dumps(m, ensure_ascii=rng.random() < 0.3).encode()
    if rng.random() < 0.4:                      # and now and then the bytes themselves
        raw = rng.choice(BYTES)(raw, rng)
    return raw

# The build "this hassmic" is held to: the newest has every scope at the version SCOPES names (held to plugmsg.h
# below), so the harness is asked a second time as an older build would answer (HASSMIC_PLUGIN_SCOPES: four scopes
# lowered to 0, which requires_parse holds a manifest to, storage and button among them, so that enough of those
# taken by any build lack one): what it lacks is unmet() against that table, said "needs a newer hassmic: ..."
LOWERED = dict(index.SCOPES, **{"storage": 0, "net.lan": 0, "ha.entities": 0, "button": 0})
def reach(rng):
    """net.lan's or net.internet's value (API 0.6), near what the Echo takes (plugin_store.c reach_parse)"""
    def entry():
        e = {"proto": rng.choice(["tcp", "udp", "tcp", "sctp"]), "ports": rng.choice([[80], [80, 443], "any", "any", [], [5555], [0], ["80"], "all", list(range(1, 10)), [53], [443, 853], [54]])}
        if rng.random() < 0.1: e[rng.choice(["tls", "to", "setting"])] = rng.choice([True, "lan", "server"])
        if rng.random() < 0.1: e.pop(rng.choice(["proto", "ports"]))
        return e
    return rng.choice([[entry()], [entry(), entry()], [entry() for _ in range(5)], [], True, [443]]) if rng.random() < 0.3 else [entry()]
def in_python(raw, tier, model):
    try:
        return "", index.manifest_check(raw, "it", tier, model)["requires"]
    except index.Bad as e:
        return str(e)[4:], None

HARNESS = r"""
#include "plugin_store.c"
int main(int argc, char **argv)
{
    static struct ps_manifest m; static char text[1 << 20]; char err[2][300], here_err[300], lacks[300]; unsigned low[PM_SCOPES];
    ps_scopes_env();                                        /* (HASSMIC_PLUGIN_SCOPES: an older build's versions) */
    for (int s = 0; s < PM_SCOPES; s++) low[s] = ps_scope_have(s);
    printf("%s", board.codename);
    for (int s = 0; s < PM_SCOPES; s++) printf(" %s:%u:%u", pm_scope_name(s), (unsigned)pm_scope_version(s), low[s]);
    printf(" |");
    for (int bit = 0; bit < NCAPS; bit++) printf(" %s", cap_names[bit]);
    printf("\n");
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb"); size_t n = f ? fread(text, 1, sizeof text - 1, f) : 0; int r, h, no[2], here[2]; unsigned caps;
        if (f) fclose(f);
        text[n] = 0; err[0][0] = err[1][0] = here_err[0] = 0;
        for (int s = 0; s < PM_SCOPES; s++) ps_scope_set(s, pm_scope_version(s));     /* what any build holds against it */
        r = ps_manifest_parse(text, n, &m, err[0], sizeof err[0]);
        if (r) memcpy(err[1], err[0], sizeof err[1]);
        caps = r ? 0u : (unsigned)m.caps;
        for (int k = 0; k < 2; k++)                         /* as ps_scan asks: by the tier the listing gave */
            no[k] = r || runnable(&m, k ? PS_SIDELOAD : PS_OFFICIAL, err[k], sizeof err[k]);
        for (int s = 0; s < PM_SCOPES; s++) ps_scope_set(s, low[s]);                   /* and what this one does */
        h = ps_manifest_parse(text, n, &m, here_err, sizeof here_err);
        for (int k = 0; k < 2; k++) here[k] = h || runnable(&m, k ? PS_SIDELOAD : PS_OFFICIAL, lacks, sizeof lacks);
        printf("%d %d %d %d %u %s\t%s\n", !no[0], !no[1], !here[0], !here[1], caps, no[0] ? err[0] : err[1], h ? here_err : "");
    }
    return 0;
}
"""
hassmic = os.environ.get("HASSMIC") or os.path.join(os.path.dirname(os.path.dirname(HERE)), "echo-dot-assist")
sources = ["src/hassmic/json.c", "src/hassmic/plugin_index.c", "src/hassmic/logread.c", "src/hassmic/hash.c", "src/hassmic/statefile.c", "src/third_party/monocypher.c", "devices/donut/board.c", "src/hassmic/volcurve.c"]
cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
if not cc or not all(os.path.isfile(os.path.join(hassmic, f)) for f in sources + ["src/hassmic/plugin_store.c", "sdk/plugmsg.h"]):
    print(f"note: not held to hassmic's own code: {'no hassmic tree at ' + hassmic if cc else 'no C compiler'}")
else:
    count, seed = int(os.environ.get("CHANGED", 400)), int(os.environ.get("SEED", 20261119))    # (more, or others: by hand)
    rng = random.Random(seed)
    tried = list(dict.fromkeys(seen))
    ours = len(tried)
    tried += [changed(rng) for _ in range(count)]
    open(os.path.join(top, "echo.c"), "w").write(HARNESS)
    r = subprocess.run([cc, "-O1", "-w", "-I" + os.path.join(hassmic, "sdk"), "-I" + os.path.join(hassmic, "src/hassmic"), "-I" + os.path.join(hassmic, "src/include"),
                        os.path.join(top, "echo.c")] + [os.path.join(hassmic, f) for f in sources] + ["-lm", "-lpthread", "-o", os.path.join(top, "echo")],
                       capture_output=True, text=True)
    check(r.returncode == 0, f"hassmic's ps_manifest_parse and runnable ({hassmic}) compile as its unit test builds them" + (": " + r.stderr[-600:] if r.returncode else ""))
    if r.returncode == 0:
        os.mkdir(os.path.join(top, "m"))
        names, out = [], []
        for i, raw in enumerate(tried):
            names.append(os.path.join(top, "m", str(i)))
            open(names[-1], "wb").write(raw)
        for i in range(0, len(names), 2000):                # (a command line holds so many names)
            lowered = ",".join(f"{k}:{v}" for k, v in LOWERED.items() if v != index.SCOPES[k])
            got = subprocess.run([os.path.join(top, "echo")] + names[i:i + 2000], capture_output=True, env=dict(os.environ, HASSMIC_PLUGIN_SCOPES=lowered)).stdout.decode(errors="replace").split("\n")
            head, out = got[0].split(), out + got[1:-1]
        model, lines = head[0], out
        scopes, caps_named = head[1:head.index("|")], head[head.index("|") + 1:]
        own = {x.split(":")[0]: int(x.split(":")[1]) for x in scopes}
        low = {x.split(":")[0]: int(x.split(":")[2]) for x in scopes}
        check(len(lines) == len(tried) and all(re.match(r"[01] [01] [01] [01] \d+ [^\t]*\t", l) for l in lines), f"it answered for each of {len(tried)} manifests ({ours} of the tests above, {count} changed, seed {seed}), as the model {model}")
        check(list(own.items()) == list(index.SCOPES.items()) and len(scopes) == len(own) and tuple(caps_named) == index.CAPS,
              f"its scopes and their versions are SCOPES (plugmsg.h PM_SCOPE_VERSION_*, in its order), its capabilities CAPS: {' '.join(scopes)}")
        check(low == LOWERED, f"and with HASSMIC_PLUGIN_SCOPES={lowered} it answers as a build without {' and '.join(k for k in LOWERED if LOWERED[k] != index.SCOPES[k])}")
        laxer, both, neither, lacking, unlike, other, why, of_changed, community_only = [], 0, 0, 0, [], [], {}, [0, 0], 0
        for i, (raw, line) in enumerate(zip(tried, lines)):
            f = line.split(" ", 5)
            f[5:] = f[5].split("\t", 1)
            echo, as_built, caps, err_here = [f[0] == "1", f[1] == "1"], [f[2] == "1", f[3] == "1"], int(f[4]), f[6]
            here = [in_python(raw, "official", model), in_python(raw, "community", model)]
            for k in (0, 1):
                if not echo[k] and not here[k][0]: laxer.append(f"{i} ({'official' if not k else 'not official'}): the Echo: {f[5]}: {raw[:300]!r}")
                # the rule left out: taken by any build's rules, refused by this one for a version of a scope it does
                # not have.  Then it is what unmet() says against this build's table, in the Echo's words, and only then
                if echo[k] and not here[k][0]:
                    lacks = index.unmet(here[k][1], LOWERED)
                    lacking += not as_built[k] and not k
                    if as_built[k] != (not lacks) or (lacks and err_here != "needs a newer hassmic: " + ", ".join(lacks)):
                        unlike.append(f"{i}: lacks {lacks}, this build: {err_here or 'taken'}: {raw[:300]!r}")
            # the index asks for any model: it takes what this model's Echo does, and what it refuses besides is the model
            anys = in_python(raw, "official", None)[0]
            if (anys and not here[0][0]) or (not anys and here[0][0] and "not for this model" not in here[0][0]): other.append(f"{i}: for any model: {anys or 'taken'}; for {model}: {here[0][0] or 'taken'}: {raw[:300]!r}")
            both += echo[0] and not here[0][0]
            neither += not echo[0] and bool(here[0][0])
            if i >= ours: of_changed[0] += echo[0] and not here[0][0]; of_changed[1] += not echo[0] and bool(here[0][0])
            for k in (0, 1):
                # (one the index refuses only for a community plugin, rule 48, is counted with those taken by both: as
                # official it is one, and the rule is the index's own, stricter than any Echo)
                if k and echo[0] and not here[0][0]: community_only += echo[1] and bool(here[1][0]); break
                if echo[k] and here[k][0]:
                    said_ = re.sub(r"setting [a-z0-9_]+|field '?[a-z0-9_]+'?", lambda x: x.group(0).split()[0] + " …", re.sub(r"the key '.*?'", "a key", here[k][0]))
                    said_ = re.sub(r": line \d+ column \d+ \(char \d+\)", "", said_)
                    why.setdefault((i < ours, said_[:120]), []).append(i)
                    break
        stricter = sum(len(x) for x in why.values())
        check(not laxer, f"what the Echo's code refuses is refused here, for an official plugin and for any other: {len(laxer)} refused by the Echo only" + "".join("\n     " + x for x in laxer[:20]))
        check(both >= 30 and neither >= 30 and (of_changed[0] >= count // 20 or count < 100) and both + neither + stricter + len({x.split(" ")[0] for x in laxer}) == len(tried),
              f"and both ways were tried: {both} manifests taken by both, {neither} refused by both, {stricter} refused here only "
              f"(of the {count} changed: {of_changed[0]}, {of_changed[1]}, {count - sum(of_changed)}):")
        print(f"note: refused here only for a community plugin (rule 48: request.audio with net.internet), taken as official: {community_only}")
        for (mine, reason), which in sorted(why.items(), key=lambda x: (-x[0][0], -len(x[1]), x[0][1])):
            print(f"note: refused here only, {len(which):2} of the {'tests above' if mine else 'changed ones'}: {reason}")
        check(not unlike and lacking >= 10, f"what an older build lacks of a version's requires is what unmet() says, in its words (\"needs a newer hassmic: ...\"), and only then does it refuse what any build's rules take ({lacking} of those taken by both)" + "".join("\n     " + x for x in unlike[:20]))
        print(f"note: left out of \"what the Echo refuses is refused here\": requires_parse against one build's own versions (an older one lacks a version a newer one has). "
              f"The build without {', '.join(k for k in LOWERED if LOWERED[k] != index.SCOPES[k])} refuses {lacking} of the {both} manifests taken by both (\"needs a newer hassmic: ...\"); "
              f"the index lists such a version with its \"requires\", and refuses only what no hassmic has (SCOPES)")
        check(not other, "asked for any model, as the index asks, it takes what it takes for this model, and refuses nothing else that it takes then but another model's plugin" + "".join("\n     " + x for x in other[:20]))

# ---- entries
def entry_bad(what, name="testplug.json", **over):
    put(entry([(1, d1), (2, d2)], **over), name=name)
    return refused(index.load, root)

check("community plugin's version has the fields" in entry_bad("", tier="community"),
      "a community plugin with an official one's versions (a package to fetch): refused, its fields named (tests/test_community.py has the rest)")
check("tier" in entry_bad("", tier="best"), "a tier there is none of: refused")
check(all("any signature holds" in entry_bad("", author_key=k) for k in ("00" * 32, "01" + "00" * 31, "ec" + "ff" * 30 + "7f")),
      "an author key of small order (all zero, the identity, the point of order 2): refused (K3 of a review of hassmic a30d6ed)")
# (R4 of a review of hassmic 3c5d7ff: encodings otatool's decode() does not read, which Monocypher, and so the Echo, reads
# as points of small order: weak() took them for no weak key, and the entry passed)
NONCANON = ("01" + "00" * 30 + "80", "ec" + "ff" * 31, "ed" + "ff" * 30 + "7f", "ed" + "ff" * 31, "ee" + "ff" * 30 + "7f", "ee" + "ff" * 31)
check(all("any signature holds" in entry_bad("", author_key=k) for k in NONCANON),
      "an author key in an encoding Monocypher reads as small order and otatool's decode() not at all (six): refused")
check("names the file" in entry_bad("", name="other.json"), "an entry in a file of another name: refused")
check("names the file" in entry_bad("", id="Test_Plug"), "an id hassmic would not take: refused")
check("names the file" in entry_bad("", name="-rf.json", id="-rf"), "nor one that starts with -")
for bad_id in ("abc-", "a--b", "ab--", "a-b-", "a" * 23 + "-", "ab", "a" * 25):
    check("names the file" in entry_bad("", name=bad_id + ".json", id=bad_id), f"nor {bad_id[:8]!r}, which the Echo's ps_id_ok refuses (a hyphen last, or two in a row; 3 to 24)")
for good_id in ("a-b", "test-plug-2", "a-" * 11 + "bc", "a" * 24):
    check(entry_bad("", name=good_id + ".json", id=good_id) == "", f"an id with hyphens between its parts ({good_id[:12]!r}): taken")
for an_id in ("abc", "a-b", "abc-", "a--b", "-abc", "a_b", "Abc", "ab", "a" * 24, "a" * 23 + "-", "a" * 25, "a\n", "abc\n"):
    check(bool(index.ID.fullmatch(an_id)) == (3 <= len(an_id) <= 24 and all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in an_id) and an_id[0] != "-" and an_id[-1] != "-" and "--" not in an_id),
          f"(the index's ID is ps_id_ok's rule, written out: {an_id[:8]!r})")
for word in index.ROUTE_WORDS:
    check("names the file" in entry_bad("", name=word + ".json", id=word), f"nor {word!r}, a word of the Echo's settings page under /api/plugins/ (ROUTE_WORDS)")
for good_id in ("uploads", "chunky", "my-upload", "index2"):
    check(entry_bad("", name=good_id + ".json", id=good_id) == "", f"an id that only begins or ends like one ({good_id!r}): taken")
# ... the same words as the Echo's own list, and ps_id_ok's answer for each: hassmic's plugin_store.c compiled and asked
# (a word added on one side only fails here)
ROUTES_C = r"""
#include "plugin_store.c"
int main(int argc, char **argv)
{
    for (const char *const *w = ps_route_words; *w; w++) printf("%s%s", w == ps_route_words ? "" : " ", *w);
    printf("\n");
    for (int i = 1; i < argc; i++) printf("%d", ps_id_ok(argv[i]));
    printf("\n");
    return 0;
}
"""
if cc and all(os.path.isfile(os.path.join(hassmic, f)) for f in sources + ["src/hassmic/plugin_store.c", "sdk/plugmsg.h"]):
    open(os.path.join(top, "routes.c"), "w").write(ROUTES_C)
    r = subprocess.run([cc, "-O0", "-w", "-I" + os.path.join(hassmic, "sdk"), "-I" + os.path.join(hassmic, "src/hassmic"), "-I" + os.path.join(hassmic, "src/include"),
                        os.path.join(top, "routes.c")] + [os.path.join(hassmic, f) for f in sources] + ["-lm", "-lpthread", "-o", os.path.join(top, "routes")],
                       capture_output=True, text=True)
    asked = list(index.ROUTE_WORDS) + ["uploads", "chunky", "my-upload", "index2", "a-b", "abc-", "a--b", "testplug", "microwakeword"]
    got = subprocess.run([os.path.join(top, "routes")] + asked, capture_output=True, text=True).stdout.split("\n") if r.returncode == 0 else ["", ""]
    check(r.returncode == 0 and tuple(got[0].split()) == index.ROUTE_WORDS and got[1] == "".join("1" if index.ID.fullmatch(x) else "0" for x in asked),
          f"ROUTE_WORDS are hassmic's ps_route_words, and ID answers as its ps_id_ok ({got[:2]}{': ' + r.stderr[-300:] if r.returncode else ''})")
else:
    print(f"note: the route words not held to hassmic's own: no hassmic tree at {hassmic} or no C compiler")
check("source is the plugin's GitHub repository" in entry_bad("", source=index.OFFICIAL_SOURCE + "../someone/else"), "a source that leaves the project by ..: refused")
check("source is the plugin's GitHub repository" in entry_bad("", source=index.OFFICIAL_SOURCE + "%2e%2e/someone"), "or by an escape")
check("source is the plugin's GitHub repository" in entry_bad("", source=index.OFFICIAL_SOURCE + "testplug/tree/main"), "or a path after the repository")
check("source is the plugin's GitHub repository" in entry_bad("", source="https://gitlab.com/Gamer92000/testplug"), "or another host than GitHub (whose attestations the index reads)")
check("project's own" in entry_bad("", source="https://github.com/someone/testplug"), "an official plugin's source elsewhere than the project's: refused")
check("one line" in entry_bad("", description="Test \u202eplugin"), "a description with a direction mark: refused")
check("one line" in entry_bad("", author="t\ud800"), "an author with half a character: refused")
e = entry([(1, d1)]); e["versions"][0]["version"] = 10 ** 30
put(e); check("higher" in refused(index.load, root), "a version no Echo takes: refused")
e = entry([(1, d1)]); e["versions"][0]["package"] = index.OFFICIAL_SOURCE + "testplug/releases/download/../../../../x/y/releases/download/v1/testplug-1.hmp"
put(e); check("own release asset" in refused(index.load, root), "a package path that leaves the plugin's releases by ..: refused")
for wrong in ("https://github.com/Gamer92000/echo-dot-assist/releases/download/v1/testplug-1.hmp", index.OFFICIAL_SOURCE + "testplug/releases/download/v1/testplug-2.hmp",
              index.OFFICIAL_SOURCE + "testplug/releases/download/v1/other-1.hmp", index.OFFICIAL_SOURCE + "testplug/releases/download/a/b/testplug-1.hmp",
              index.OFFICIAL_SOURCE + "testplug/releases/download//testplug-1.hmp", index.OFFICIAL_SOURCE + "testplug/releases/download/.x/testplug-1.hmp",
              index.OFFICIAL_SOURCE + "testplug/releases/latest/download/testplug-1.hmp", index.OFFICIAL_SOURCE + "testplug/releases/download/v%2F1/testplug-1.hmp"):
    e = entry([(1, d1)]); e["versions"][0]["package"] = wrong
    put(e); check("own release asset" in refused(index.load, root), f"a package that is not the plugin's own release asset of that version: refused ({wrong[19:80]})")
put(); open(os.path.join(root, "plugins", "testplug.json"), "w").write(json.dumps(entry([(1, d1)]))[:-1] + ', "author_key": "' + "ab" * 32 + '"}')
check("twice" in refused(index.load, root), "a field twice in an entry: refused")
check("project's own" in entry_bad("", source="https://github.com/someone/else"), "official with a source outside the project: refused")
check("author_key" in entry_bad("", author_key="AB" * 32), "an author key that is no lower case hex: refused")
check("one line" in entry_bad("", description="two\nlines"), "a description of two lines: refused")
e = entry([(2, d2), (1, d1)])
put(e); check("higher" in refused(index.load, root), "versions out of order: refused")
e = entry([(1, d1)]); e["versions"][0]["package"] = "http://github.com/x/y.hmp"
put(e); check("own release asset" in refused(index.load, root), "a package from anywhere but the plugin's own releases: refused")
e = entry([(1, d1)]); e["extra"] = 1
put(e); check("no other" in refused(index.load, root), "a field the entry does not have: refused")
os.mkdir(os.path.join(top, "empty")); os.mkdir(os.path.join(top, "empty", "plugins"))
open(os.path.join(top, "empty", "revoked.json"), "w").write('{"serial": 0, "entries": []}')
check(refused(index.load, os.path.join(top, "empty")) == "", "no plugins at all: an index all the same")

# ---- revocations
def revoke(r, previous=None):
    put(entry([(1, d1)]), r)
    return refused(index.load, root, previous)

good = {"serial": 3, "entries": [{"id": "someplug", "upto": 2, "reason": "sends what it hears"}, {"id": "otherplug", "reason": "gone"},
                                 {"author_key": "ab" * 32, "reason": "the key was taken"}]}
check(revoke(good) == "", "a plugin up to a version, a plugin whole, an author's key: taken")
# official ones too: the index key makes a plugin official, and may withdraw it (as hassmic's builds take it since
# 2026-11-21; a leaked author key of an official plugin could not be stopped otherwise)
check(revoke({"serial": 1, "entries": [{"id": "testplug", "reason": "x"}]}) == "", "an official plugin can be withdrawn by the index")
check(revoke({"serial": 1, "entries": [{"author_key": entry([])["author_key"], "reason": "x"}]}) == "", "and so can its author's key")
check("reason" in revoke({"serial": 1, "entries": [{"id": "someplug"}]}), "an entry without a reason: refused")
check(revoke({"serial": 1, "entries": [{"id": "abc-", "reason": "x"}, {"id": "a--b", "reason": "x"}]}) == "", "an id of the form older builds took from a file (\"abc-\", \"a--b\") can still be withdrawn")
check("a plugin's id" in revoke({"serial": 1, "entries": [{"id": "-abc", "reason": "x"}]}) and "a plugin's id" in revoke({"serial": 1, "entries": [{"id": "Abc", "reason": "x"}]}), "one that never was an id: refused")
check("serial" in revoke({"entries": []}), "a list without a serial: refused")
prev = os.path.join(top, "prev")
put(entry([(1, d1)]), good); index.build(root, pkgs, prev, 300, K); index.sign(root, prev, os.path.join(top, "index.key"))
check(revoke(good, prev) == "", "the published list again, its serial unchanged: taken")
check("higher" in revoke(dict(good, entries=good["entries"][:1]), prev), "another list under the same serial: refused")
check(revoke(dict(good, serial=4, entries=good["entries"][:1]), prev) == "", "with a higher serial: taken")
check("goes back" in revoke(dict(good, serial=2, entries=good["entries"][:1]), prev), "a changed list under a serial that goes back: refused")
# (the same list as published under a lower serial in revoked.json: the published one, under its serial, which the
# switch of the index's key raises by itself, README "A new index key"; nothing goes back.  R1 of a review of hassmic
# 3c5d7ff)
check(revoke(dict(good, serial=2), prev) == "" and index.load(root, prev)[1]["serial"] == 3,
      "the published list, revoked.json's serial lower: taken as published, under the published serial")
# an official plugin that is published keeps its entry: taken out in one change, it could be withdrawn in the next
put(None, {"serial": 4, "entries": [{"id": "testplug", "reason": "x"}]})
check("its entry stays" in refused(index.load, root, prev), "an official plugin's entry removed (and the plugin withdrawn): refused")
put(None, good)
check("its entry stays" in refused(index.load, root, prev), "removed alone, the first of two steps: refused")
put(entry([(1, d1)], author_key="cd" * 32), good)
check("its entry stays" in refused(index.load, root, prev), "its author key changed: refused")
put(entry([]), good)
check(refused(index.load, root, prev) == "", "its versions taken away: that it may")
import time as _t
check("more than a day after now" in revoke(dict(good, serial=int(_t.time()) + 2 * 86400, entries=[]), prev), "a revocation serial more than a day ahead (one every later list has to beat): refused")
check("more than a day after now" in revoke({"serial": 10 ** 12, "entries": []}), "also with nothing published yet")
check(revoke(dict(good, serial=int(_t.time()) + 3600), prev) == "", "an hour ahead (a clock a little fast): taken")
# a published site of the tool before revoked_serial (the first publish after it goes by it): taken as --previous,
# never as a site of its own (a review, 2026-11-21: the first publish refused it)
pix = os.path.join(prev, "index.json"); was_ix = open(pix, "rb").read()
d = json.loads(was_ix); del d["revoked_serial"]; open(pix, "wb").write(index.dump(d)); index.sign(root, prev, os.path.join(top, "index.key"))
was_before = index.OLD_FORM_BEFORE; index.OLD_FORM_BEFORE = d["serial"] + 1
check(revoke(good, prev) == "" and "another revocation list" in refused(index.verify, prev, os.path.join(top, "index.pub")),
      "a published site made before revoked_serial: taken as the one before (it was refused), and still no site of its own")
index.OLD_FORM_BEFORE = d["serial"]
check("another revocation list" in revoke(good, prev),
      "one without it from the time the tool names the list on: refused (the exception held for every publish: a review, 2026-11-21)")
index.OLD_FORM_BEFORE = was_before
d["revoked_serial"] = good["serial"] - 1; open(pix, "wb").write(index.dump(d)); index.sign(root, prev, os.path.join(top, "index.key"))
check("another revocation list" in revoke(good, prev), "one that names another list than the one beside it: refused as before")
open(pix, "wb").write(was_ix); index.sign(root, prev, os.path.join(top, "index.key"))
open(os.path.join(prev, "revoked.json"), "w").write(json.dumps({"revoked": 1, "serial": 0, "entries": []}))
check("not one the index key signed" in revoke(good, prev), "a published list that was changed is none to go by")
shutil.rmtree(os.path.join(root, "plugins"))
check("plugins/" in refused(index.load, root), "no plugins folder: refused, said so")
os.mkdir(os.path.join(root, "plugins"))

# ---- the page for people (tools/page.py): written with the site, from the same data, every text escaped
import page as pagemod
# (the manifest's name the entry's: a build holds them to each other)
pq, dq = package(1, name='Test plugin & "co"'); pkq = os.path.join(top, "pkgs-page"); os.mkdir(pkq)
open(os.path.join(pkq, "testplug-1.hmp"), "wb").write(pq)
put(entry([(1, dq)], name='Test plugin & "co"'), good)
index.build(root, pkq, site(1041), 400, K)
html = open(os.path.join(site(1041), "index.html"), encoding="utf-8").read()
ix = json.load(open(os.path.join(site(1041), "index.json")))
v1 = ix["plugins"][0]["versions"][0]
check('href="packages/testplug-1.hmp"' in html and v1["sha256"] in html, "the page offers the package the index lists, with its SHA-256")
check("Browse plugins" in html, "and says that an Echo reads the list itself")
check("Test plugin &amp; &quot;co&quot;" in html, "an entry's text is escaped")
evil = copy.deepcopy(ix); evil["plugins"][0]["description"] = "A stand-in </script><img src=x onerror=alert(1)>."
evil["plugins"][0]["versions"][0]["_page"] = {"license": "<b>MIT</b>", "file_labels": ["<i>models</i>"]}
t = pagemod.page(evil, {"entries": []})
check("<img src=x" not in t and "<b>MIT" not in t and t.count("</script>") == 1 and "&lt;img src=x" in t,
      "and what the entry rules would refuse too, should one get by: no tag of it reaches the page")
key = entry([])["author_key"]
check(pagemod.fingerprint(key) == plugcheck.fingerprint(bytes.fromhex(key)) and pagemod.fingerprint(key) in html,
      "the author key's fingerprint, as the Echo and plugcheck.py show it")
check("Keeps up to 4 kB of its own data on this Echo" in html and "keeps up to 4 kb of its own data" in html, "a capability in the words the Echo's dialog uses")
check("_page" not in json.dumps(ix), "index.json carries nothing that is the page's alone")
ext = set(re.findall(r'(?:href|src)="(https?://[^"]+)"', html))
check(all(u.startswith(("https://github.com/Gamer92000/", index.OFFICIAL_SOURCE)) for u in ext) and not re.search(r'<(script|link|img)[^>]+(src|href)="https?:', html),
      f"nothing loaded from elsewhere; links only to the project and the source: {sorted(ext)}")
gone = pagemod.page(copy.deepcopy(ix), {"entries": [{"id": "testplug", "upto": 1, "reason": "sends what it hears"}]})
check("Withdrawn:" in gone and "sends what it hears" in gone and 'href="packages/testplug-1.hmp"' not in gone, "a withdrawn version: said why, no download")
need = copy.deepcopy(ix); need["plugins"][0]["versions"][0]["requires"] = {"core": 1, "wake": 1, "files": 1, "<b>": 2}
check("Speaks core 1, storage 1" in html and "Speaks core 1, wake 1, files 1, &lt;b&gt; 2" in pagemod.page(need, {"entries": []}),
      "what each version speaks (its requires), in the manifest's order, escaped")
empty = copy.deepcopy(ix); empty["plugins"][0]["versions"] = []
check("No released version yet" in pagemod.page(empty, {"entries": []}), "a plugin without a version: said so, nothing to download")

# ---- the index and its revocation list are of one time: index.json names the list it was made with and leaves out
# what that list withdraws (an Echo takes it only beside a list at least that new: a review, 2026-11-21, had a new
# index served beside an old revocation list, and a withdrawn version offered and installed)
put(entry([(1, d1), (2, d2)]), {"serial": 1700000000, "entries": [{"id": "testplug", "upto": 1, "reason": "leaks"}]})
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", pkgs, site(4000), "--serial", "1700000100", "--key", K, "--root", root], capture_output=True, text=True)
ix = json.load(open(os.path.join(site(4000), "index.json")))
check(r.returncode == 0 and ix["revoked_serial"] == 1700000000 and [v["version"] for v in ix["plugins"][0]["versions"]] == [2] and "version 1 is withdrawn (leaks): left out" in r.stdout
      and list(ix)[:3] == ["index", "serial", "revoked_serial"], "index.json names the revocation list's serial, and a version it withdraws is left out")
put(entry([(1, d1), (2, d2)]), {"serial": 1700000000, "entries": [{"author_key": entry([])["author_key"], "reason": "key taken"}]})
index.build(root, pkgs, site(4001), 1700000100, K)
check(json.load(open(os.path.join(site(4001), "index.json")))["plugins"] == [], "a plugin all of whose versions are withdrawn (its author's key): not offered at all")
index.sign(root, site(4000), K)
rv0 = open(os.path.join(site(4000), "revoked.json"), "rb").read()
open(os.path.join(site(4000), "revoked.json"), "wb").write(index.revoked_bytes({"serial": 1600000000, "entries": []}))
index.sign(root, site(4000), K)
check("made with another revocation list" in refused(index.verify, site(4000), os.path.join(top, "index.pub")), "a site whose revocation list is not the one its index was made with: does not verify")
open(os.path.join(site(4000), "revoked.json"), "wb").write(rv0); index.sign(root, site(4000), K)

# ---- every bound an Echo has, held here before anything is published (BOUNDS; hassmic's plugin_index.h)
B = index.BOUNDS
put(entry([(v, d1) for v in range(1, 18)]))
check("at most 16 versions" in refused(index.load, root), "more versions of a plugin than an Echo reads (17): refused")
put(entry([(v, d1) for v in range(1, 17)]))
check(refused(index.load, root) == "", "16: taken")
check("source is" in entry_bad("", source=index.OFFICIAL_SOURCE + "x" * 200), "a source longer than an Echo keeps: refused (no GitHub repository's name is that long)")
check("bytes" in entry_bad("", description="é" * 121), "a description of 121 characters of two bytes each (242): refused, an Echo counts bytes")
many = [{"id": f"p{i:05d}", "reason": "r"} for i in range(B["REVOCATIONS"] + 1)]
check("more than 2048 entries" in revoke({"serial": 1, "entries": many}), "a revocation list longer than an Echo reads (2049 entries): refused, never published (an Echo would refuse it whole)")
check(revoke({"serial": 1, "entries": many[:-1]}) == "", "2048: taken")
check("over 512 kB" in revoke({"serial": 1, "entries": [{"id": f"p{i:05d}", "upto": 999999999, "reason": "\u00e9" * 100} for i in range(B["REVOCATIONS"])]}),
      "a revocation list over 512 kB as published (2048 entries with reasons of 200 bytes): refused")
check("bytes" in revoke({"serial": 1, "entries": [{"id": "abc", "reason": "é" * 101}]}), "a reason over 200 bytes: refused")
was_b = dict(B)
B["INDEX_MAX"] = 500
put(entry([(1, d1), (2, d2)]))
check("over the" in refused(index.build, root, pkgs, site(4010), 200, K) and not os.path.exists(os.path.join(site(4010), "index.json")), "an index.json over what an Echo reads: the build fails, nothing written")
B.update(was_b); B["PLUGINS_MAX"] = 0
check("more than 0 plugins" in refused(index.load, root), "more plugins than an Echo reads: refused")
B.update(was_b)
# a capability's name: none the index lists in "capabilities" or "broad" is over CAP_NAME_MAX bytes (an Echo refuses
# the whole index for one in "broad": K7 of a review of hassmic a30d6ed); CAP takes none longer, BROAD has none
check(all(len(c) <= B["CAP_NAME_MAX"] for c in index.BROAD + index.CAPS) and index.CAP.fullmatch("a" * index.CAP_LONGEST)
      and not index.CAP.fullmatch("a" * (B["CAP_NAME_MAX"] + 1)) and index.CAP_LONGEST <= B["CAP_NAME_MAX"],
      "capability names: every one the index knows, and the longest a manifest may have, under an Echo's CAP_NAME_MAX")
# held to hassmic's own numbers where its tree is beside this one
hdr = os.path.join(hassmic, "src/hassmic/plugin_index.h")
if os.path.isfile(hdr):
    defs = {}
    for m_ in re.finditer(r"^#define PI_([A-Z_]+)\s+\(?(\d+)u?(?:\s*<<\s*(\d+))?\)?", open(hdr).read(), re.M):
        defs[m_.group(1)] = int(m_.group(2)) << int(m_.group(3) or 0)
    want = {"INDEX_MAX": "INDEX_MAX", "REVOKED_MAX": "REVOKED_MAX", "PLUGINS_MAX": "PLUGINS_MAX", "VERSIONS": "VERSIONS", "REVOCATIONS": "REVOCATIONS", "NAME_MAX": "NAME_MAX",
            "AUTHOR_MAX": "AUTHOR_MAX", "DESCRIPTION_MAX": "DESCRIPTION_MAX", "SOURCE_MAX": "SOURCE_MAX", "VERSION_NAME_MAX": "VERSION_NAME_MAX",
            "REASON_MAX": "REASON_MAX", "AHEAD_S": "AHEAD_S", "BROAD_MAX": "BROAD_MAX", "CAP_NAME_MAX": "CAP_NAME_MAX"}
    diff = {k: (B[k], defs.get(v)) for k, v in want.items() if B[k] != defs.get(v)}
    check(not diff and set(B) == set(want), f"BOUNDS are hassmic's plugin_index.h's, number for number ({hdr}): {diff or 'the same'}")
else:
    print(f"note: BOUNDS not held to hassmic's plugin_index.h: no hassmic tree at {hassmic}")

# SCOPES is hassmic's: messages.def's scope lines (name and version, in their order) and plugmsg.h's PM_SCOPE_VERSION_*
mdef, pmh = os.path.join(hassmic, "sdk/messages.def"), os.path.join(hassmic, "sdk/plugmsg.h")
if os.path.isfile(mdef) and os.path.isfile(pmh):
    lines_ = re.findall(r"^scope ([a-z0-9._]+) (\d+) ", open(mdef).read(), re.M)
    vers_ = dict(re.findall(r"PM_SCOPE_VERSION_([A-Z_]+) = (\d+)", open(pmh).read()))
    check([(k, int(v)) for k, v in lines_] == list(index.SCOPES.items())
          and {k.replace(".", "_").upper(): v for k, v in index.SCOPES.items()} == {k: int(v) for k, v in vers_.items()},
          f"SCOPES are hassmic's scopes at their versions, in messages.def's order and as plugmsg.h has them: {dict((k, int(v)) for k, v in lines_)}")
else:
    print(f"note: SCOPES not held to hassmic's messages.def and plugmsg.h: no hassmic tree at {hassmic}")

# KEYS is hassmic's too: messages.def's keys lines (each context's keys, the scope and the version that brought them),
# line for line; and the harness knows the scopes SCOPES names
import harness
check(tuple(index.SCOPES) == harness.SCOPES_KNOWN, f"the harness's scopes are SCOPES: {harness.SCOPES_KNOWN}")
if os.path.isfile(mdef):
    def key_lines(text):
        out = {}
        for c, sc, ks in re.findall(r"^keys\s+(\S+)\s+(\S+)\s+(.*)$", text, re.M):
            n, _, v = sc.partition("@")
            for k in ks.split(): out[(c, k)] = (n, int(v or 1))
        return out
    keys_ = key_lines(open(mdef).read())
    check(keys_ == index.KEYS, f"KEYS are messages.def's keys lines, key for key ({len(keys_)}): {set(keys_.items()) ^ set(index.KEYS.items()) or 'the same'}")
else:
    print(f"note: KEYS not held to hassmic's messages.def: no hassmic tree at {hassmic}")

# ---- a key of a later version than the manifest requires (rule 17b) and a version that no build of this hassmic has
# yet: hassmic's code built as a later hassmic's would be (its tests/unit/scopes_demo.py: net.lan 2, whose entries'
# key "names" came with it, ha.entities 2 with a sensor's "precision"), and manifest_check with its tables as that
# hassmic's.  Both must take and refuse the same (finding 3 of a review of hassmic 4e0a202: neither knew a key's version)
demo_py = os.path.join(hassmic, "tests/unit/scopes_demo.py")
if cc and os.path.isfile(demo_py) and all(os.path.isfile(os.path.join(hassmic, f)) for f in sources + ["src/hassmic/plugin_store.c", "tools/mkplugmsg.py"]):
    sys.path.insert(0, os.path.dirname(demo_py))
    import scopes_demo
    dd = os.path.join(top, "demo"); os.mkdir(dd)
    subprocess.run([sys.executable, demo_py, os.path.join(dd, "messages.def")], check=True)
    subprocess.run([sys.executable, os.path.join(hassmic, "tools/mkplugmsg.py"), "--def", os.path.join(dd, "messages.def"), "--header", os.path.join(dd, "plugmsg.h")], check=True)
    open(os.path.join(dd, "echo.c"), "w").write(HARNESS)
    r = subprocess.run([cc, "-O1", "-w", "-I" + dd, "-I" + os.path.join(hassmic, "sdk"), "-I" + os.path.join(hassmic, "src/hassmic"), "-I" + os.path.join(hassmic, "src/include"),
                        os.path.join(dd, "echo.c")] + [os.path.join(hassmic, f) for f in sources] + ["-lm", "-lpthread", "-o", os.path.join(dd, "echo")], capture_output=True, text=True)
    check(r.returncode == 0, "hassmic's ps_manifest_parse built as the demo's later hassmic" + (": " + r.stderr[-600:] if r.returncode else ""))
    if r.returncode == 0:
        was = (index.SCOPES, index.KEYS)
        index.SCOPES = dict(index.SCOPES, **scopes_demo.SCOPES)
        index.KEYS = {**index.KEYS, **{(c, k): (sc, v) for c, k, sc, v in scopes_demo.KEYS}}
        demo_m = []
        for names in (None, True):
            for extra in (None, "tls"):
                for precision in (None, 2):
                    for kind in ("sensor", "switch"):
                        for rl in (1, 2, 3):
                            for rh in (1, 2):
                                lan = {"proto": "tcp", "ports": [80]}
                                if names: lan["names"] = names
                                if extra: lan[extra] = True
                                ent = {"name": "t", "kind": kind, "label": "T"}
                                if precision: ent["precision"] = precision
                                demo_m.append(dict(manifest, author_key="ab" * 32, digest="cd" * 32, requires={"core": 1, "net.lan": rl, "ha.entities": rh},
                                                   capabilities={"net.lan": [lan], "ha.entities": [ent]}, settings=[]))
        names_ = []
        for i, mm in enumerate(demo_m):
            names_.append(os.path.join(dd, f"m{i}")); open(names_[-1], "wb").write(json.dumps(mm).encode())
        got = subprocess.run([os.path.join(dd, "echo")] + names_, capture_output=True).stdout.decode(errors="replace").split("\n")
        own = {x.split(":")[0]: int(x.split(":")[1]) for x in got[0].split()[1:got[0].split().index("|")]}
        check(own == index.SCOPES, f"(the demo's build: {', '.join(f'{k} {v}' for k, v in own.items() if v > 1)})")
        differ, taken, keyed = [], 0, 0
        for mm, line in zip(demo_m, got[1:]):
            echo_ok = line.split(" ")[0] == "1"
            py = in_python(json.dumps(mm).encode(), "official", None)[0]
            taken += echo_ok
            keyed += "'s, and the manifest" in py
            if echo_ok != (not py): differ.append(f"the Echo: {line.split(' ', 5)[5][:120] or 'taken'}; here: {py or 'taken'}: {json.dumps(mm)[:200]}")
        check(not differ and taken >= 8 and keyed >= 16, f"{len(demo_m)} manifests with a later version's keys and requires: the demo's Echo and manifest_check take ({taken}) and refuse "
              f"({len(demo_m) - taken}, {keyed} of them for a key of a later version than required) the same" + "".join("\n     " + x for x in differ[:20]))
        index.SCOPES, index.KEYS = was
else:
    print(f"note: rule 17b not held to hassmic's code built as a later hassmic: no hassmic tree with tests/unit/scopes_demo.py at {hassmic}, or no C compiler")

# the harness's stand-in broker reads a HELLO as hassmic's sdk/vectors/HELLO.vec has it: every packet there, and
# none of the refused ones (cut short, a byte after it, over 255 scopes, a name over 24 bytes or with a NUL)
import harness
vec = os.path.join(hassmic, "sdk/vectors/HELLO.vec")
if os.path.isfile(vec):
    takes_, refuses_ = [], []
    for line in open(vec):
        w = line.split()
        if w[:1] == ["packet"]: takes_.append(bytes.fromhex(w[1]))
        if w[:1] == ["refuse"]: refuses_.append((w[1], bytes.fromhex(w[2])))
    def reads(d):
        try:
            return harness.hello_scopes(d) is not None or True
        except (ValueError, struct.error):
            return False
    check(len(takes_) == 4 and all(reads(d) for d in takes_) and harness.hello_scopes(takes_[0]) == {"name-4-é": 51552, "name-5-é": 27376},
          "the harness reads every HELLO of hassmic's vectors, the scopes as named")
    check(len(refuses_) >= 5 and not [w for w, d in refuses_ if reads(d)], f"and refuses each one the vectors refuse ({', '.join(w for w, _ in refuses_)})")
    hello = lambda *sc: struct.pack("<HHII", 1, 0, 1, 1) + struct.pack("<H", len(sc)) + b"".join(struct.pack("<H", len(n)) + n.encode() + struct.pack("<H", v) for n, v in sc)
    check(harness.hello_scopes(hello(("core", 1), ("core", 1))) is None and harness.hello_scopes(hello(("later", 1), ("later", 2))) == {"later": 2},
          "a scope it knows named twice: none (REFUSED, as hassmic's broker); a later SDK's scope twice is no word on what is spoken")
else:
    print(f"note: the harness's HELLO not held to hassmic's vectors: no hassmic tree at {hassmic}")

# ---- fetch: what the published site has is taken from there, the rest from each plugin's release; what cannot be
# had is left out, never the whole publish (a review, 2026-11-21: one plugin's release gone blocked every list,
# revocations included)
put(entry([(1, d1), (2, d2)]), {"serial": 1700000000, "entries": []})
pub = os.path.join(top, "pub"); index.build(root, pkgs, pub, 1700000200, K); index.sign(root, pub, K)
e3 = entry([(1, d1), (2, d2)]); e3["versions"].append({"version": 3, "commit": "c" * 40, "workflow": WF, "manifest": "0" * 64, "package": index.OFFICIAL_SOURCE + "testplug/releases/download/v3/testplug-3.hmp"})
put(e3, {"serial": 1700000001, "entries": [{"id": "testplug", "upto": 1, "reason": "leaks"}]})
got = os.path.join(top, "got")
import urllib.request as _ur
asked = []
def _fake(url, timeout=0): asked.append(url); raise OSError("no network in the test")
_was, _ur.urlopen = _ur.urlopen, _fake
try:
    missing = index.fetch(root, got, pub)
finally:
    _ur.urlopen = _was
g2 = open(os.path.join(got, "testplug-2.hmp"), "rb").read() if os.path.exists(os.path.join(got, "testplug-2.hmp")) else b""
check(missing == 1 and sorted(os.listdir(got)) == ["testplug-2.hmp", "testplug-2.hmp.sigstore.jsonl"] and g2 == p2 and asked == [e3["versions"][2]["package"]]
      and open(os.path.join(got, "testplug-2.hmp.sigstore.jsonl"), "rb").read() == open(os.path.join(pub, "packages", "testplug-2.hmp.sigstore.jsonl"), "rb").read(),
      f"fetch: version 2 from the published site, its listing taken off (the release's bytes again), with the site's attestation bundles beside it; version 1 withdrawn, not fetched; version 3 not had: one warning, nothing else ({missing}, {asked})")
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", got, site(4020), "--serial", "1700000300", "--key", K, "--root", root], capture_output=True, text=True)
ix = json.load(open(os.path.join(site(4020), "index.json"))) if r.returncode == 0 else {}
l2 = index.members(open(os.path.join(site(4020), "packages", "testplug-2.hmp"), "rb").read(), "l2") if r.returncode == 0 else {}
check(r.returncode == 0 and [v["version"] for v in ix["plugins"][0]["versions"]] == [2] and "warning: testplug version 3: no package" in r.stdout
      and plugcheck.listing_read(l2, json.loads(l2["manifest.json"]), KPUB) == ("official", 1700000300),
      "built from them: version 2 listed anew under the new serial, version 3 left out with a warning, the list published")

# ---- attestations (tools/attest.py; tests/test_attest.py has each of gh's ways): a version is listed only where its
# repository's GitHub Actions built it at the entry's commit; the published site keeps the bundles, the next build
# verifies them again without GitHub's API
GHLOG, GHCFG = os.path.join(top, "gh.log"), os.path.join(top, "gh.json")
def fake_gh(cfg):
    open(GHCFG, "w").write(json.dumps(dict(cfg, log=GHLOG)))
    os.environ["INDEX_FAKE_GH"] = GHCFG
    if os.path.exists(GHLOG):
        os.unlink(GHLOG)
def gh_asked():
    return [json.loads(l) for l in open(GHLOG).read().splitlines()] if os.path.exists(GHLOG) else []
put(entry([(1, d1), (2, d2)]))
fake_gh({hashlib.sha256(p2).hexdigest(): {}})
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", pkgs, site(5000), "--serial", "1700000400", "--key", K, "--root", root], capture_output=True, text=True)
ix = json.load(open(os.path.join(site(5000), "index.json"))) if r.returncode == 0 else {}
check(r.returncode == 0 and [x["version"] for x in ix["plugins"][0]["versions"]] == [2] and "warning: testplug version 1: not attested" in r.stdout
      and "no attestations found" in r.stdout and not os.path.exists(os.path.join(site(5000), "packages", "testplug-1.hmp")),
      "a package without an attestation (uploaded by hand, built elsewhere): left out with a warning, the rest listed (a publish)")
argv = gh_asked()
check(len(argv) == 2 and all(a[:2] == ["attestation", "verify"] and "--bundle" not in a and a[a.index("--repo") + 1] == "Gamer92000/testplug"
                             and a[a.index("--source-digest") + 1] == "c" * 40 for a in argv),
      "gh asked of GitHub's API for each (no bundle of its own yet), with the entry's repository and commit")
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", pkgs, site(5001), "--serial", "1700000400", "--key", K, "--root", root, "--strict"],
                   capture_output=True, text=True)
check(r.returncode != 0 and "not attested" in r.stderr and not os.path.exists(os.path.join(site(5001), "index.json")),
      f"with --strict (a pull request's check): an error, and nothing written ({r.stderr.strip()[-160:]})")
for what, facts in (("another repository", {"repo": "someone/testplug"}), ("another commit", {"commit": "d" * 40}), ("a self-hosted runner", {"runner": "self-hosted"}),
                    ("a workflow of another repository", {"signer_repo": "someone/actions"})):
    fake_gh({"*": facts, "mode": "lie"})
    got = refused(index.build, root, pkgs, site(5002 + len(what)), 1700000400, K, strict=True)
    check("not attested" in got, f"an attestation of {what} (gh lying it verified): refused ({got[-120:]})")
fake_gh({"*": {}})
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", pkgs, site(5010), "--serial", "1700000400", "--key", K, "--root", root, "--strict"],
                   capture_output=True, text=True)
index.sign(root, site(5010), K)
check(r.returncode == 0 and refused(index.verify, site(5010), os.path.join(top, "index.pub")) == "", "attested both: listed, signed, it verifies")
got2 = os.path.join(top, "got2")
check(index.fetch(root, got2, site(5010)) == 0 and sorted(os.listdir(got2)) == ["testplug-1.hmp", "testplug-1.hmp.sigstore.jsonl", "testplug-2.hmp", "testplug-2.hmp.sigstore.jsonl"],
      "fetched again from that site: both packages with their bundles")
fake_gh({})                                     # (GitHub's API has nothing now: only the bundles on file can say it)
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", got2, site(5011), "--serial", "1700000500", "--key", K, "--root", root, "--strict"],
                   capture_output=True, text=True)
argv = gh_asked()
check(r.returncode == 0 and len(argv) == 2 and all(a[-2] == "--bundle" and a[-1].endswith(".hmp.sigstore.jsonl") for a in argv),
      f"the next build verifies the published site's bundles again, without GitHub's API (--bundle) ({r.stderr.strip()[-160:]})")
bp = os.path.join(got2, "testplug-1.hmp.sigstore.jsonl")
other = open(bp, "rb").read().replace(b'"c' + b"c" * 39, b'"d' + b"d" * 39)       # (read before the file is opened to write)
open(bp, "wb").write(other)
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", got2, site(5012), "--serial", "1700000500", "--key", K, "--root", root, "--strict"],
                   capture_output=True, text=True)
check(r.returncode != 0 and "testplug version 1: not attested" in r.stderr and "SourceRepositoryDigest" in r.stderr,
      f"a bundle on file of another commit: refused, as of another commit ({r.stderr.strip()[-160:]})")
# the published site's own record: the bundles named by their SHA-256 under the index's signature, of the release's bytes
s10 = site(5010)
ixp, bpp = os.path.join(s10, "index.json"), os.path.join(s10, "packages", "testplug-1.hmp.sigstore.jsonl")
keep_ix, keep_b = open(ixp, "rb").read(), open(bpp, "rb").read()
open(bpp, "wb").write(open(os.path.join(s10, "packages", "testplug-2.hmp.sigstore.jsonl"), "rb").read())
check("not the bundles the index names" in refused(index.verify, s10, os.path.join(top, "index.pub")), "a site whose bundles were swapped: does not verify")
os.unlink(bpp)
check("no attestation bundles" in refused(index.verify, s10, os.path.join(top, "index.pub")), "nor one without them")
open(bpp, "wb").write(keep_b)
def resigned(change):
    ix_ = json.loads(keep_ix)
    change(ix_["plugins"][0]["versions"][0])
    open(ixp, "wb").write(index.dump(ix_))
    index.sign(root, s10, K)
    return refused(index.verify, s10, os.path.join(top, "index.pub"))
check("not the release the index names" in resigned(lambda v: v.update(release_sha256="0" * 64)), "an index (signed) naming another release's SHA-256: does not verify")
check("not the release the index names" in resigned(lambda v: v.update(attestation="packages/testplug-2.hmp.sigstore.jsonl")), "nor one naming another package's bundles")
def other_subject(line):
    import base64
    b_ = json.loads(line)
    st = json.loads(base64.b64decode(b_["dsseEnvelope"]["payload"]))
    st["subject"][0]["digest"]["sha256"] = "0" * 64
    b_["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(st).encode()).decode()
    return json.dumps(b_).encode() + b"\n"
bad_b = b"".join(other_subject(l) for l in keep_b.splitlines())
open(bpp, "wb").write(bad_b)
check("other files" in resigned(lambda v: v.update(attestation_sha256=hashlib.sha256(bad_b).hexdigest())), "nor one whose bundles name other files (signed as such)")
open(bpp, "wb").write(keep_b)
check(resigned(lambda v: None) == "", "(as built: it verifies)")
# packed as plugcheck.py packs: the listed package without its listing is the release's bytes, which the attestation names
f1_ = index.members(p1, "p1")
swapped = plugcheck.tar_bytes([(n, f1_[n]) for n in ("manifest.json", "manifest.sig", "LICENSE", "plugin")])
check("not packed as plugcheck.py pack packs" in build_with(swapped), "a package whose members are in another order (no other byte changed): refused")
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
    for n in ("manifest.json", "manifest.sig", "plugin", "LICENSE"):
        ti = tarfile.TarInfo(n); ti.size, ti.mtime, ti.mode = len(f1_[n]), 1700000000, 0o644
        t.addfile(ti, io.BytesIO(f1_[n]))
check("not packed as plugcheck.py pack packs" in build_with(buf.getvalue()), "a package with a time in its headers: refused")
put(entry([(1, d1), (2, d2)]))
open(os.path.join(pkgs, "testplug-1.hmp"), "wb").write(p1)
html = open(os.path.join(s10, "index.html")).read()
import html as _html
shown = _html.escape(attest.command("testplug-1.hmp", "Gamer92000/testplug", "c" * 40, WF, "v1", "testplug-1.hmp.sigstore.jsonl"))
check("GitHub Actions" in html and shown in html and "--source-ref refs/tags/v1 --cert-identity-regex" in shown and "<code>.github/workflows/release.yml</code>" in html
      and "packages/testplug-1.hmp.sigstore.jsonl" in html and hashlib.sha256(p1).hexdigest() in html,
      "the page: built by its repository's GitHub Actions at that commit in that workflow, attested, and how to verify it again: the very command the index runs, "
      "with the bundle (the release's SHA-256)")
fake_gh({"*": {}})

# ---- the workflow, the trigger and the tag: an attestation of the entry's workflow's own run for the push of the
# release's tag, nothing else (gh lying it verified: index.py build refuses it all the same)
put(entry([(1, d1), (2, d2)]))
for what, facts, said in (("a run started by hand (workflow_dispatch)", {"trigger": "workflow_dispatch"}, "workflow_dispatch"),
                          ("a branch's run", {"ref": "refs/heads/main"}, "refs/heads/main"),
                          ("another tag's run than the release asset's", {"ref": "refs/tags/v9"}, "not of the tag"),
                          ("another workflow of the same repository", {"workflow": ".github/workflows/x.yml"}, "signed by another workflow"),
                          ("the entry's workflow called by another", {"caller": ".github/workflows/caller.yml"}, "that calls the entry's")):
    fake_gh({"*": facts, "mode": "lie"})
    got = refused(index.build, root, pkgs, site(5100 + len(what)), 1700000400, K, strict=True)
    check("not attested" in got and said in got, f"an attestation of {what} (gh lying it verified): refused ({got[-140:]})")
fake_gh({"*": {}})
for what, bad_wf in (("no workflow", None), ("a workflow below .github/workflows/", ".github/workflows/sub/r.yml"), ("one elsewhere", "ci/release.yml")):
    e_ = entry([(1, d1)])
    if bad_wf is None:
        del e_["versions"][0]["workflow"]
    else:
        e_["versions"][0]["workflow"] = bad_wf
    put(e_)
    got = refused(index.load, root)
    check(("workflow" in got or "fields" in got) and got, f"an entry's version with {what}: refused ({got[-120:]})")
put(entry([(1, d1), (2, d2)]))
e_ = entry([(1, d1)]); e_["versions"][0]["workflow"] = ".github/workflows/publish.yaml"
put(e_)
fake_gh({"*": {}, "log": GHLOG, "api": {"files": {".github/workflows/publish.yaml": "on:\n  push:\njobs:\n  r:\n    steps:\n      - run: make\n"}}})
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", pkgs, site(5150), "--serial", "1700000400", "--key", K, "--root", root, "--strict"],
                   capture_output=True, text=True)
argv = gh_asked()
ix = json.load(open(os.path.join(site(5150), "index.json"))) if r.returncode == 0 else {}
check(r.returncode == 0 and argv and r"\.github/workflows/publish\.yaml@refs/tags/v1$" in argv[0][argv[0].index("--cert-identity-regex") + 1]
      and ix["plugins"][0]["versions"][0]["workflow"] == ".github/workflows/publish.yaml",
      "another name the entry gives its release workflow: gh asked for that one, and index.json names it")
put(entry([(1, d1), (2, d2)]))

# ---- no verdict (attest.Unavailable: gh missing, Sigstore or GitHub's API out of reach) against a verdict
# (attest.Refused): an outage never takes a listed version off the index; a new one waits for a later publish
got3 = os.path.join(top, "got3")
check(index.fetch(root, got3, site(5010)) == 0 and os.path.exists(os.path.join(got3, "testplug-1.hmp.sigstore.jsonl")),
      "(versions 1 and 2 from the published site, with its bundles)")
SIGSTORE = "error creating Sigstore verifier: no valid Sigstore verifiers could be initialized"


def build_prev(n, cfg, *extra, pkgdir=got3):
    fake_gh(cfg)
    return subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", pkgdir, site(n), "--serial", "1700000600", "--key", K, "--root", root,
                           "--previous", site(5010), *extra], capture_output=True, text=True)


for n, what, cfg in ((6000, "Sigstore's trust root out of reach", {"fail": SIGSTORE}), (6001, "gh failing otherwise", {"fail": "Error: unexpected EOF"}),
                     (6002, "gh's answer no JSON", {"raw": "<html>"})):
    r = build_prev(n, cfg)
    check(r.returncode != 0 and "which the published site lists" in r.stderr and "no verdict" in r.stderr and not os.path.exists(site(n)),
          f"{what}, for versions the published site lists: the build fails, nothing is written (never an index without them, rc 0) ({r.stderr.strip()[-120:]})")
    # (every such version asked and named, the build failing once: not one person's round per version; a review of 17c2e8c)
    check("2 versions which the published site lists" in r.stderr and "testplug version 1: " in r.stderr and "testplug version 2: " in r.stderr,
          f"{what}: both listed versions named in the one failure ({r.stderr.strip()[-200:]})")
os.environ["INDEX_GH"] = os.path.join(top, "no-such-gh")
r = build_prev(6003, {})
os.environ["INDEX_GH"] = os.path.join(HERE, "fake_gh.py")
check(r.returncode != 0 and "no verdict" in r.stderr and "no " in r.stderr and not os.path.exists(site(6003)), f"no gh at all: the same ({r.stderr.strip()[-120:]})")
r = build_prev(6004, {})
check(r.returncode == 0 and [x["version"] for x in json.load(open(os.path.join(site(6004), "index.json")))["plugins"][0]["versions"]] == [1, 2],
      f"gh answering again: both listed again, from the site's bundles ({r.stderr.strip()[-120:]})")
# gh's no to the very bundle the site kept, which held when the versions were listed, for the very bytes it held
# for: gh, Sigstore's trust root or this reading changed, not the release.  No verdict: the build fails, nothing is
# written (never a version taken off the index unasked, rc 0); a person withdraws it or mends the check (a review of
# c61a1a5)
for n, what, line in ((6005, "the identity or a signature", 'Error: verifying with issuer "sigstore.dev"'),
                      (6006, "no attestation", "Error: no attestations found"), (6007, "a field", "Error: expected SourceRepositoryRef to be refs/tags/v1, got refs/tags/v2")):
    r = build_prev(n, {"fail": line})
    check(r.returncode != 0 and "which the published site lists" in r.stderr and "no verdict" in r.stderr and "the site's own bundle" in r.stderr
          and "withdraw it" in r.stderr and "left out from now on" not in r.stdout + r.stderr and not os.path.exists(site(n)),
          f"gh refusing the bundle the site keeps for versions it lists ({what}): no verdict, the build fails, nothing written ({r.stderr.strip()[-160:]})")
    check(r.stderr.count("the site's own bundle") == 2 and "testplug version 1: " in r.stderr and "testplug version 2: " in r.stderr,
          f"({what}: both versions' bundles refused, both named in the one failure)")
# a version the site does not list yet: a publish leaves it out (no verdict, said as such), a pull request's check fails
p3, d3 = package(3)
newpk = os.path.join(top, "newpk")
shutil.copytree(got3, newpk)
open(os.path.join(newpk, "testplug-3.hmp"), "wb").write(p3)
put(entry([(1, d1), (2, d2), (3, d3)]))
cfg = {"fail": "Error: HTTP 503: Service Unavailable"}
r = build_prev(6010, {"*": {}}, pkgdir=newpk)           # (the honest answer first: all three)
check(r.returncode == 0 and [x["version"] for x in json.load(open(os.path.join(site(6010), "index.json")))["plugins"][0]["versions"]] == [1, 2, 3],
      "(a new version 3 beside the two listed: all three listed when gh answers)")
# GitHub's API down for the new one alone: the stand-in fails only without --bundle (the listed ones' path; its
# --version passed on, which attest.gh_checked asks first)
fake_wrap = os.path.join(top, "gh-api-down.py")
open(fake_wrap, "w").write(f"#!{sys.executable}\nimport os, sys\nif '--bundle' not in sys.argv and '--version' not in sys.argv:\n    sys.stderr.write('Error: HTTP 503: Service Unavailable\\n'); sys.exit(1)\n"
                           f"os.execv(sys.executable, [sys.executable, {os.path.join(HERE, 'fake_gh.py')!r}] + sys.argv[1:])\n")
os.chmod(fake_wrap, 0o755)
os.environ["INDEX_GH"] = fake_wrap
r = build_prev(6011, {}, pkgdir=newpk)
ix = json.load(open(os.path.join(site(6011), "index.json"))) if r.returncode == 0 else {}
check(r.returncode == 0 and [x["version"] for x in ix["plugins"][0]["versions"]] == [1, 2] and "testplug version 3: its attestation could not be verified now (no verdict" in r.stdout,
      f"GitHub's API down for a version not listed yet: a publish leaves it out, said as no verdict, the listed ones and the rest published ({r.stdout.strip()[-200:]})")
r = build_prev(6012, {}, "--strict", pkgdir=newpk)
check(r.returncode != 0 and "testplug version 3: its attestation could not be verified now (no verdict" in r.stderr and not os.path.exists(site(6012)),
      f"and a pull request's check (--strict) fails ({r.stderr.strip()[-120:]})")
# (--strict names every version left out, failing once: one round of the author's per pull request, not per version)
empty = os.path.join(top, "nopk")
os.makedirs(empty)
r = build_prev(6013, {"*": {}}, "--strict", pkgdir=empty)
check(r.returncode != 0 and "3 versions left out (--strict" in r.stderr and all(f"testplug version {n}: no package" in r.stderr for n in (1, 2, 3)),
      f"--strict with three versions left out: all three named in the one failure ({r.stderr.strip()[-200:]})")
# a verdict on a version not listed yet is still one: left out of a publish, the listed ones published from their
# bundles; an error in a pull request's check
open(fake_wrap, "w").write(f"#!{sys.executable}\nimport os, sys\nif '--bundle' not in sys.argv and '--version' not in sys.argv:\n    sys.stderr.write('Error: no attestations found\\n'); sys.exit(1)\n"
                           f"os.execv(sys.executable, [sys.executable, {os.path.join(HERE, 'fake_gh.py')!r}] + sys.argv[1:])\n")
r = build_prev(6013, {}, pkgdir=newpk)
ix = json.load(open(os.path.join(site(6013), "index.json"))) if r.returncode == 0 else {}
check(r.returncode == 0 and [x["version"] for x in ix["plugins"][0]["versions"]] == [1, 2] and "testplug version 3: not attested" in r.stdout
      and "left out from now on" not in r.stdout,
      f"gh's verdict on a version not listed yet (no attestation): left out, the listed ones published ({r.stdout.strip()[-160:]})")
r = build_prev(6014, {}, "--strict", pkgdir=newpk)
check(r.returncode != 0 and "testplug version 3: not attested" in r.stderr and not os.path.exists(site(6014)),
      f"and a pull request's check (--strict) fails ({r.stderr.strip()[-120:]})")
os.environ["INDEX_GH"] = os.path.join(HERE, "fake_gh.py")

# ---- the bundle kept: one, and one a site keeps (a larger one is left out at the build, never a site the signing
# refuses: that would hold back every publish, revocations included)
put(entry([(1, d1), (2, d2)]))
fake_gh({"*": [{}, {}]})
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", pkgs, site(6100), "--serial", "1700000400", "--key", K, "--root", root],
                   capture_output=True, text=True)
check(r.returncode == 0 and all(open(os.path.join(site(6100), "packages", f"testplug-{n}.hmp.sigstore.jsonl"), "rb").read().count(b"\n") == 1 for n in (1, 2)),
      "two attestations that hold: one bundle kept per package")
fake_gh({hashlib.sha256(p1).hexdigest(): {"pad": "x" * (attest.BUNDLE_MAX + 1)}, hashlib.sha256(p2).hexdigest(): {}})
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", pkgs, site(6101), "--serial", "1700000400", "--key", K, "--root", root],
                   capture_output=True, text=True)
ix = json.load(open(os.path.join(site(6101), "index.json"))) if r.returncode == 0 else {}
index.sign(root, site(6101), K) if r.returncode == 0 else None
check(r.returncode == 0 and [x["version"] for x in ix["plugins"][0]["versions"]] == [2] and "larger than the 4 MB" in r.stdout
      and refused(index.verify, site(6101), os.path.join(top, "index.pub")) == "",
      f"an attestation larger than a site keeps: that version left out at the build, the rest listed, and the site signs and verifies ({r.stdout.strip()[-160:]})")

# ---- fetch: the site's bundle only for the commit and the workflow it listed the version with
class _Resp:
    def __init__(self, data): self.data = data
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self, n=-1): return self.data


fake_gh({"*": {}})
got4 = os.path.join(top, "got4")
for what, change in (("another commit", lambda v: v.update(commit="d" * 40)), ("another workflow", lambda v: v.update(workflow=".github/workflows/other.yml"))):
    e_ = entry([(1, d1), (2, d2)])
    change(e_["versions"][0])
    put(e_)
    asked = []
    _was = _ur.urlopen
    _ur.urlopen = lambda url, timeout=None: (asked.append(url), _Resp(p1))[1]
    try:
        shutil.rmtree(got4, ignore_errors=True)
        index.fetch(root, got4, site(5010))
    finally:
        _ur.urlopen = _was
    check(asked == [e_["versions"][0]["package"]] and sorted(os.listdir(got4)) == ["testplug-1.hmp", "testplug-2.hmp", "testplug-2.hmp.sigstore.jsonl"],
          f"the entry names {what} than the site listed version 1 with: fetched from its release again, no bundle of the site's beside it ({asked})")
    # (the other workflow is there, at the commit: what it uses is held as any workflow's)
    fake_gh({"*": {}, "api": {"files": {".github/workflows/other.yml": "on:\n  push:\njobs:\n  r:\n    runs-on: x\n    steps:\n      - run: make\n"}}})
    r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", got4, site(6200 + len(what)), "--serial", "1700000600", "--key", K, "--root", root,
                        "--previous", site(5010)], capture_output=True, text=True)
    argv = gh_asked()
    v1 = [a for a in argv if a[2].endswith("testplug-1.hmp")]
    check(r.returncode == 0 and v1 and "--bundle" not in v1[0], f"and its attestation asked of GitHub's API, for the entry's {what} ({r.stderr.strip()[-120:]})")
put(entry([(1, d1), (2, d2)]))

# ---- what the workflow uses (tools/workflow.py; tests/test_references.py has each form): asked right after an
# attestation asked of GitHub's API, never beside the site's own bundle; a refusal a verdict, GitHub's API out of
# reach none (a review of dc75e14: an impostor commit of a fork, pinned, runs under the original's name)
APILOG = os.path.join(top, "api.log")
FORK = "6" * 40
IMPOSTOR = {"files": {WF: "on:\n  push:\njobs:\n  r:\n    steps:\n      - uses: actions/checkout@" + FORK + "\n"}, "log": APILOG}
def api_asked():
    return open(APILOG).read().splitlines() if os.path.exists(APILOG) else []
def build_api(n, api, *extra, pkgdir=pkgs, previous=None):
    fake_gh({"*": {}, "api": api})
    if os.path.exists(APILOG):
        os.unlink(APILOG)
    return subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", pkgdir, site(n), "--serial", "1700000600", "--key", K, "--root", root,
                           *(["--previous", previous] if previous else []), *extra], capture_output=True, text=True)
put(entry([(1, d1), (2, d2)]))
r = build_api(7000, {"log": APILOG})
check(r.returncode == 0 and [x["version"] for x in json.load(open(os.path.join(site(7000), "index.json")))["plugins"][0]["versions"]] == [1, 2]
      and f"repos/Gamer92000/testplug/contents/{WF}?ref={'c' * 40}" in api_asked(),
      "attested of GitHub's API: the entry's workflow read at its commit, its actions by their own commits: listed")
r = build_api(7001, IMPOSTOR)
ix = json.load(open(os.path.join(site(7001), "index.json"))) if r.returncode == 0 else {}
check(r.returncode == 0 and ix["plugins"][0]["versions"] == [] and "warning: testplug version 1: not attested as its repository's CI's build: its workflow at cccccccccccc runs what its commit does not fix" in r.stdout
      and "a commit of a fork" in r.stdout,
      f"an action pinned by a commit of a fork only (an impostor commit): a verdict, left out of a publish, said why ({r.stdout.strip()[-200:]})")
r = build_api(7002, IMPOSTOR, "--strict")
check(r.returncode != 0 and "a commit of a fork" in r.stderr and not os.path.exists(site(7002)), f"and a pull request's check (--strict) fails ({r.stderr.strip()[-120:]})")
r = build_api(7003, {"status": {"/tags": 403}, "log": APILOG})
ix = json.load(open(os.path.join(site(7003), "index.json"))) if r.returncode == 0 else {}
check(r.returncode == 0 and ix["plugins"][0]["versions"] == [] and "no verdict: testplug version 1: its workflow's references could not be checked now" in r.stdout
      and "testplug version 2: its attestation could not be verified now (no verdict" in r.stdout,
      f"GitHub's API answering 403 for the actions' refs: no verdict, a new version left out of a publish and said so as found ({r.stdout.strip()[-200:]})")
r = build_api(7004, {"status": {"/tags": 403}}, "--strict")
check(r.returncode != 0 and "could not be checked now" in r.stderr, f"and a pull request's check (--strict) fails ({r.stderr.strip()[-120:]})")
# the published site's own bundle: not asked again, GitHub's API down or not (s10: versions 1 and 2, listed)
got5 = os.path.join(top, "got5")
index.fetch(root, got5, site(5010))
r = build_api(7005, {"fail": "error connecting to api.github.com", "log": APILOG}, pkgdir=got5, previous=site(5010))
check(r.returncode == 0 and [x["version"] for x in json.load(open(os.path.join(site(7005), "index.json")))["plugins"][0]["versions"]] == [1, 2] and api_asked() == [],
      f"versions the published site lists, verified with its own bundles: their references not asked again (held when listed; the commit's files do not change), "
      f"so GitHub's API out of reach holds back neither them nor the revocation list ({r.stderr.strip()[-120:]})")
# a listed version the entry now names with another commit: asked of the API again, its refusal a verdict as the attestation's
e_ = entry([(1, d1), (2, d2)])
e_["versions"][0]["commit"] = "d" * 40
put(e_)
got6 = os.path.join(top, "got6")
_was, _ur.urlopen = _ur.urlopen, lambda url, timeout=None: _Resp(p1)
try:
    index.fetch(root, got6, site(5010))
finally:
    _ur.urlopen = _was
fake_gh({"*": {"commit": "d" * 40}, "api": IMPOSTOR})
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", got6, site(7006), "--serial", "1700000600", "--key", K, "--root", root,
                    "--previous", site(5010)], capture_output=True, text=True)
check(r.returncode != 0 and not os.path.exists(site(7006)) and "a commit of a fork" in r.stderr and "testplug version 1: listed, and its workflow" in r.stderr
      and "no verdict on a version the site lists" in r.stderr and "left out from now on" not in r.stdout,
      f"a listed version the entry names with another commit, whose workflow there uses an impostor commit: no verdict (a check that may answer "
      f"otherwise one day, an action's repository gone since: never a version taken off unasked), the build fails naming it ({r.stderr.strip()[-200:]})")
# GitHub's API stalling for a version asked of it holds back no version the site lists (a review of 810b9e9: one
# stalled call made every later gh call no verdict, the --bundle verifications of listed versions too, and every
# publish failed, the revocation list with it): the versions with the site's bundle are asked first, and a stall of
# the API's is not one of the bundles'.  Version 1 named with another commit (asked of the API, listed: no verdict
# fails the build), version 2 with the site's bundle, version 3 new; in the entry's order 1 comes first
p3, d3 = package(3)
got7 = os.path.join(top, "got7")
shutil.copytree(got6, got7)
open(os.path.join(got7, "testplug-3.hmp"), "wb").write(p3)
e_ = entry([(1, d1), (2, d2), (3, d3)])
e_["versions"][0]["commit"] = "d" * 40
put(e_)
fake_gh({"*": {}, "sleep_api": 3})
import contextlib, io as _io, time, workflow
_was = (attest.SECONDS, workflow.SECONDS)
attest.SECONDS = workflow.SECONDS = 1
attest._stalled.clear()
out = _io.StringIO()
t0 = time.monotonic()
try:
    with contextlib.redirect_stdout(out):
        index.build(root, got7, site(7007), 1700000600, K, previous=site(5010))
    got = "built"
except index.Bad as x:
    got = str(x)
attest.SECONDS, workflow.SECONDS = _was
attest._stalled.clear()
argv = gh_asked()
said = out.getvalue()
bundled = [a for a in argv if a[2].endswith("testplug-2.hmp") and "--bundle" in a]
check(bundled and argv.index(bundled[0]) == 0 and "no verdict: testplug version 2" not in said and "testplug version 2" not in got
      and "1 version which the published site lists" in got and "testplug version 1:" in got and "took more than 1 s" in got
      and "no verdict: testplug version 3: not asked" in said and time.monotonic() - t0 < 8,
      f"GitHub's API stalling (version 1, asked of it): version 2 verified with the site's bundle first and held, only version 1 named "
      f"in the failure, version 3 not asked (no verdict at once) ({[a[2][-14:] + (' --bundle' if '--bundle' in a else '') for a in argv]}; {got[-160:]})")
fake_gh({"*": {}})
# and the listed versions asked of GitHub's API before the new ones, whatever the entries' order (a review of
# 5a3035d: they were in the entries' order, and a new version's stall before a listed one made that one no verdict,
# which fails the build).  A site that lists versions 2 and 3; the entry adds version 1 and names version 3 with
# another commit: version 2 with the site's bundle, version 3 of the API, version 1 (new, of the API) stalls last
put(entry([(2, d2), (3, d3)]))
pk8, got8 = os.path.join(top, "pk8"), os.path.join(top, "got8")
os.makedirs(pk8)
open(os.path.join(pk8, "testplug-2.hmp"), "wb").write(p2)
open(os.path.join(pk8, "testplug-3.hmp"), "wb").write(p3)
with contextlib.redirect_stdout(_io.StringIO()):
    index.build(root, pk8, site(7010), 1700000500, K)
index.sign(root, site(7010), K)
e_ = entry([(1, d1), (2, d2), (3, d3)])
e_["versions"][2]["commit"] = "d" * 40
put(e_)
_was, _ur.urlopen = _ur.urlopen, lambda url, timeout=None: _Resp(p1 if url.endswith("-1.hmp") else p3)
try:
    with contextlib.redirect_stdout(_io.StringIO()):
        index.fetch(root, got8, site(7010))
finally:
    _ur.urlopen = _was
fake_gh({"*": {}, "sleep_for": {hashlib.sha256(p1).hexdigest(): 3}})
_was = (attest.SECONDS, workflow.SECONDS)
attest.SECONDS = workflow.SECONDS = 1
attest._stalled.clear()
out = _io.StringIO()
try:
    with contextlib.redirect_stdout(out):
        index.build(root, got8, site(7011), 1700000600, K, previous=site(7010))
    got = "built"
except index.Bad as x:
    got = str(x)
attest.SECONDS, workflow.SECONDS = _was
attest._stalled.clear()
said = out.getvalue()
argv = [a[2][-14:] + (" --bundle" if "--bundle" in a else "") for a in gh_asked()]
ix = json.load(open(os.path.join(site(7011), "index.json"))) if got == "built" else {}
check(got == "built" and argv == ["testplug-2.hmp --bundle", "testplug-3.hmp", "testplug-1.hmp"] and [x["version"] for x in ix["plugins"][0]["versions"]] == [2, 3]
      and "no verdict: testplug version 1" in said and "warning: testplug version 1: its attestation could not be verified now" in said,
      f"the listed versions asked of GitHub's API before the new ones: version 3 (listed, another commit) asked and held before version 1 (new) "
      f"stalled, which is left out of a publish and said ({argv}; {got[-160:]})")
fake_gh({"*": {}})
# make site PACKAGES=<dir>: a version the site does not list, with a bundle beside it (a person's own) is no site's
# bundle: what its workflow runs is asked all the same (a review of 5a3035d: it was skipped wherever a bundle was)
put(entry([(1, d1), (2, d2)]))
r = build_api(7012, IMPOSTOR, pkgdir=got5)
ix = json.load(open(os.path.join(site(7012), "index.json"))) if r.returncode == 0 else {}
check(r.returncode == 0 and ix["plugins"][0]["versions"] == [] and "a commit of a fork" in r.stdout and api_asked(),
      f"a bundle beside a version no published site lists (PACKAGES=<dir>): its workflow's references asked all the same, the impostor a verdict "
      f"({r.stdout.strip()[-160:]})")
put(entry([(1, d1), (2, d2)]))
# a package that is not its entry's beside a version whose attestation would have no verdict: every package is held to
# its entry before any attestation is asked (they are asked in parallel since a review of 9b02fdb, 8), so the build
# fails on it at once, gh not asked for any version (it named the versions without a verdict asked before it)
open(os.path.join(pkgs, "testplug-2.hmp"), "wb").write(p1)
r = build_api(7008, {"fail": "error connecting to api.github.com"}, "--strict", pkgdir=pkgs)
open(os.path.join(pkgs, "testplug-2.hmp"), "wb").write(p2)
check(r.returncode != 0 and "testplug version 2: its manifest is not the one the entry names" in r.stderr and "no verdict" not in r.stdout + r.stderr,
      f"a package not its entry's (an error of its own) beside a version without a verdict: the build fails on it before gh is asked ({r.stderr.strip()[-240:]})")
# the attestations verified ATTEST_WORKERS at a time (a review of 9b02fdb, 8: one by one, every listed version again
# at every publish, and the job's time bounded how many the index could list): six versions whose verification takes
# a second each, three at a time, take two seconds and some, neither six (one by one) nor one (unbounded)
pkp = os.path.join(top, "pkgs-par"); os.mkdir(pkp); vers = []
for n in range(1, 7):
    pn, dn = package(n); vers.append((n, dn))
    open(os.path.join(pkp, f"testplug-{n}.hmp"), "wb").write(pn)
put(entry(vers))
fake_gh({"*": {}, "sleep_for": {hashlib.sha256(open(os.path.join(pkp, f"testplug-{n}.hmp"), "rb").read()).hexdigest(): 1 for n in range(1, 7)}})
_was = index.ATTEST_WORKERS
index.ATTEST_WORKERS = 3
t0 = time.monotonic()
try:
    with contextlib.redirect_stdout(_io.StringIO()):
        index.build(root, pkp, site(7020), 1700000700, K)
    took, got = time.monotonic() - t0, json.load(open(os.path.join(site(7020), "index.json")))
finally:
    index.ATTEST_WORKERS = _was
verified = [a for a in gh_asked() if a[:2] == ["attestation", "verify"]]
check([x["version"] for x in got["plugins"][0]["versions"]] == [1, 2, 3, 4, 5, 6] and len(verified) == 6 and 1.8 < took < 4.5,
      f"six versions of a second each, three at a time: listed in their order, in {took:.1f} s (one by one: 6 s and more; all at once: 1 s)")
fake_gh({"*": {}})
fake_gh({"*": {}})

# ---- this repository's own tree keeps its rules, and the command line says so
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "check"], capture_output=True, text=True)
check(r.returncode == 0, f"this repository: {(r.stdout + r.stderr).strip()}")
put(entry([(1, d1)], tier="best"))
r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "check", "--root", root], capture_output=True, text=True)
check(r.returncode == 1 and r.stderr.startswith("index: plugins/testplug.json"), f"the command line fails with the reason: {r.stderr.strip()}")

r = subprocess.run([sys.executable, os.path.join(TOOLS, "index.py"), "build", pkgs, site(1040), "--serial", "\u00b2", "--key", K, "--root", root], capture_output=True, text=True)
check(r.returncode != 0 and "Traceback" not in r.stderr, "a serial that is no number: refused without a traceback")
shutil.rmtree(top)
print("index: " + ("FAILED" if failed else "all passed"))
sys.exit(1 if failed else 0)
