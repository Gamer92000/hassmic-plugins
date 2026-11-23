#!/usr/bin/env python3
"""The index of hassmic's plugins (hassmic's docs/plugins.md 5.3, 5.6): from this repository's entries and the
packages they name to the files that are published, Python's standard library only.

  index.py check [--previous SITE]            every entry (plugins/<id>.json) and revoked.json keep the rules
        (--previous: the published site, which fetch and build read)
  index.py fetch DIR [--previous SITE]        each entered version's package into DIR/<id>-<version>.hmp: from the
        published site where it has that version (the same manifest and release, its size and SHA-256 as its index
        names; the index's listing taken off again, which gives back the release's bytes: a package is packed as
        plugcheck.py packs it) with the attestation bundle the site keeps for it (DIR/<id>-<version>.hmp.sigstore.jsonl)
        where the site listed it with the commit and workflow the entry names (else its attestation is GitHub's API's again),
        else from the plugin's own release (its repository's release asset, the entry's `package`: official and
        community alike).  One that cannot be had is warned of and left out (build then lists the rest): one plugin's
        release that is gone keeps no other plugin, and no revocation, from being published.  Withdrawn versions are
        not fetched
  index.py build DIR SITE --serial N --key SECRET [--commit C] [--previous SITE [--bump]] [--arch x86_64] [--strict]
        checks each package in DIR against its entry, as an Echo will and more (the manifest is the one the entry
        names, signed by the entry's author key, and one an Echo takes: manifest_check; the program is the
        manifest's and keeps the rules a file shows; no listing in it yet), then its attestation (tools/attest.py: a
        GitHub artifact attestation that the plugin's own repository's GitHub Actions built these bytes at the
        entry's commit on a GitHub-hosted runner, in the entry's workflow, that file's own run for the push of the
        tag the release asset is under; asked of gh, its JSON read again here; with the site's bundle where fetch
        took the version from there, else of GitHub's API),
        adds the listing that makes it the index's (signed with SECRET: the index key, or a throwaway one for a build
        that only checks), and writes SITE: index.json, revoked.json, packages/ (the packages as listed, each with
        the bundle of the attestation that held beside it), and index.html (tools/page.py: the same list for
        people).  A version whose package is not in DIR, or whose attestation does not hold, is warned of and left
        out (--strict: an error; a pull request's check).  Where gh gives no verdict (attest.Unavailable: gh missing,
        not tools/gh.sh's version, the network, Sigstore, GitHub's API), a version the published site lists fails the
        build (an outage never takes a version off the index), a new one is left out (--strict: an error); the
        site's own bundle of a version it lists refused again is no verdict either (KeptRefused: the build fails),
        nor is the check of what a listed version's workflow runs (tools/workflow.py), where it is asked.  Every
        version is asked first (those with the site's bundle, then the listed ones asked of GitHub's API, then the
        new ones: a stalled API call holds back no listed version), and the one failure names each that failed it.  A version is listed with its
        manifest's "requires" (the least version of each scope it speaks): an Echo runs it where its own versions
        are at least those, and a manifest that requires a version no hassmic has (SCOPES) is refused.
        Nothing of a package is run.
        (--arch x86_64: the PC's test plugins, for hassmic's own tests; never for the published site)
        index.json names the revocation list it was made with ("revoked_serial") and leaves out every version that
        list withdraws (a plugin all of whose versions it withdraws with them): an Echo takes the index only beside
        a revocation list at least that new.  Nothing is written that an Echo would refuse: every bound of BOUNDS
        holds, or the build fails.
        --commit C: the commit of this tree the site is built from (make site: git rev-parse HEAD), written into
        built-from.txt (signed by `sign`): the published site says which commit made it.
        --bump: where N is not higher than the published serial and the published site was built from this same
        commit C (its signed built-from.txt), the published one if the site is the same, else one more (a second
        site of one commit: a publish run again); the same where it was built from a commit C descends from (git
        merge-base --is-ancestor in this tree: a commit whose time is not above the published serial).  Never over
        another commit's site: an older commit's tree built after a newer one's was published is refused, as without
        --bump (it would put back what the newer one took out, under a higher serial); so is one where git cannot say
        (a shallow clone: index.yml fetches the whole history)
  index.py smoke DIR [--previous SITE] [--qemu QEMU]
        each community version's package in DIR (fetch's) that the published site does not have, its program run in
        the harness (tools/harness.py: under qemu-arm in bubblewrap, tools/sandbox.py, every system call judged by
        the sandbox's own table; a smoke test, not a wall, and never a build).  A pull request's job without secrets
        runs it; publishing does not (it runs nothing of a package).  Any that does not pass is an error
  index.py entry PACKAGE                      a community version's fields as an entry takes them (the manifest's
                                              digest, the author's signature, the LICENSE's SHA-256, the
                                              capabilities), from the package its author's CI released
  index.py sign SITE SECRET                   index.json.sig, revoked.json.sig (and built-from.txt.sig), by the index
                                              key (keys/index.pub)
  index.py verify SITE [--pub KEY]            what a reader of the site checks: both signatures, every package and
                                              its listing

  --previous SITE   the site as it is published now (an empty folder: none yet).  It has to be one the index key
                    signed (or, while the key changes, the previous one: keys/index-previous.pub, README "A new
                    index key"); serials only grow against it, and an official plugin it lists keeps its entry.  One the
                    tool made before index.json named its revocation list (no "revoked_serial", an index serial
                    under OLD_FORM_BEFORE) is taken as it is; a newer one without it is refused
  --root DIR        another tree than this file's (the tests)

Signatures are hassmic's (otatool.py: Monocypher's EdDSA with BLAKE2b, not RFC 8032's Ed25519), 64 bytes each, over
a text that starts with its purpose, so that none passes for another:
  index.json.sig     over "hassmic plugin index 1\\n" + index.json's bytes
  revoked.json.sig   over "hassmic plugin revoked 1\\n" + revoked.json's bytes
  built-from.txt.sig over "hassmic plugin index built from 1\\n" + built-from.txt's bytes ("commit <C>\\nindex.json
                     <its SHA-256>\\n": which commit made the index beside it; for this tool's --bump, read by no Echo)
  listing.sig        in each package: its hex, then the text it signs, "hassmic plugin listing 2\\nid <id>\\nversion <n>\\n
                     tier <official|community>\\nmanifest <digest>\\nserial <the index's>\\n" (plugcheck.listing).  What an
                     Echo takes it for: an official listing makes updates by the pinned author that ask for nothing new
                     install without the action button, and lets the plugin be copied between Echos (hassmic's
                     docs/SECURITY.md "Plugins")

Both serials are times: the index's the time of the commit it is built from, the revocation list's the time of its
last change (written by hand: date +%s; the publish that switches the index's key raises it by one where the list is
unchanged, README "A new index key", and the same list is then published under the published serial whatever
revoked.json says).  Each only grows against the published site, and neither may be more than a
day ahead of now: an Echo with its clock set refuses one further ahead, and one that took it would hold every honest
list to it (hassmic's plugin_index.c pi_floor)."""
import math, hashlib, io, json, os, re, shutil, sys, tarfile, time, unicodedata, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import attest, harness, otatool, page, plugcheck, sandbox, workflow

SIGN_INDEX, SIGN_REVOKED = b"hassmic plugin index 1\n", b"hassmic plugin revoked 1\n"
SIGN_BUILT = b"hassmic plugin index built from 1\n"
COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
# An official plugin's source is the project's own.  Every package, official and community alike, is its own
# repository's release asset: <source>/releases/download/<tag>/<id>-<version>.hmp, as the plugin's GitHub Actions
# built, attested and published it (tools/attest.py), signed by the author and listed by nobody yet; the listing is
# this index's, added by build.  Every source is a GitHub repository (attest.repo_of): the attestation is GitHub's.
# A fork with an index of its own changes OFFICIAL_SOURCE.
OFFICIAL_SOURCE = "https://github.com/Gamer92000/"
TAG = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}")
VERSION_MAX = 1000000000                        # as the Echo's (plugin_store.c)
# What an Echo reads of the published lists, in one place: hassmic's src/hassmic/plugin_index.h, PI_* of the same
# names (tests/test_index.py reads that file where hassmic's tree is beside this one and fails where they differ).
# Past any of them an Echo refuses the list whole (the revocation list) or leaves the rest out (the index's plugins
# and versions): the build refuses to publish either
BOUNDS = {
    "INDEX_MAX": 1 << 20,           # index.json, bytes
    "REVOKED_MAX": 512 << 10,       # revoked.json, bytes
    "PLUGINS_MAX": 4096,            # plugins in index.json
    "VERSIONS": 16,                 # versions of one plugin in index.json
    "REVOCATIONS": 2048,            # entries of revoked.json
    "NAME_MAX": 48, "AUTHOR_MAX": 48, "DESCRIPTION_MAX": 240, "SOURCE_MAX": 200,   # an entry's texts, bytes of UTF-8
    "VERSION_NAME_MAX": 24, "REASON_MAX": 200,
    "AHEAD_S": 86400,               # how far past now a serial may be
    "BROAD_MAX": 32,                # names in a community version's "broad"
    "CAP_NAME_MAX": 31,             # a capability's name in a version's "capabilities" and "broad", bytes: an Echo
                                    # refuses the whole index for a longer one in "broad" (plugin_index.c version_parse)
}
HEX32, HEX20, SIG = re.compile(r"[0-9a-f]{64}"), re.compile(r"[0-9a-f]{40}"), re.compile(rb"[0-9a-f]{128}")
# a URL of plain path parts: no "..", no escapes, no query, which a prefix check would let lead elsewhere
URL = re.compile(r"https://[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+(/[A-Za-z0-9_~-][A-Za-z0-9._~-]*|/[A-Za-z0-9._~-]*[A-Za-z0-9_~-][A-Za-z0-9._~-]*)+")
CAP = re.compile(r"[a-z][a-z.]{0,23}")
SCOPE = re.compile(r"[a-z0-9._]{1,24}")         # a scope's name as requires_parse takes one (PS_SCOPE_NAME, plugin_store.h)
CAP_LONGEST = 24                                # CAP's: under BOUNDS["CAP_NAME_MAX"] (asserted below, beside CAPS)
# A plugin's id as the Echo takes one (ps_id_ok, plugin_store.c:126 at 3feeda2): 3 to 24 of a-z, 0-9 and -, no - at
# either end and none twice in a row (a package's file is <id>-<version>.hmp: "abc--1.hmp" was version 1 of "abc-"),
# and none of ROUTE_WORDS.
# The index's own, not plugcheck.ID: that file is a copy of hassmic's sdk/plugcheck.py, whose ID still takes "abc-"
# and "a--b".  ID_WAS is what builds before that commit took, and only a revocation goes by it: a plugin put on such
# an Echo from a file can have an id of the old form, and the list has to be able to name it
# The words of an Echo's settings page under /api/plugins/ and its Plugins page's sub page: no plugin is called one
# (ps_id_ok's ps_route_words, plugin_store.c: an id that is also a route word was a plugin's path and a route's at
# once, and by a substring a plugin called "chunk" or "upload" had every write of its taken for a piece of an upload,
# never kept over a restart; a review of hassmic 6631974, 2).  The same list as the Echo's, which make check holds
# (tests/test_index.py compiles hassmic's plugin_store.c and asks it)
ROUTE_WORDS = ("accept", "browse", "cancel", "check", "chunk", "community", "fetch", "index", "install", "resume", "revoked",
               "sync", "synced", "upload")
ID = re.compile(r"(?!(?:" + "|".join(ROUTE_WORDS) + r")\Z)(?=[a-z0-9-]{3,24}\Z)[a-z0-9]+(?:-[a-z0-9]+)*")
ID_WAS = re.compile(r"[a-z0-9][a-z0-9-]{2,23}")
ENTRY_KEYS = {"id", "name", "description", "author", "author_key", "tier", "source", "versions"}
VERSION_KEYS = {"version", "commit", "workflow", "manifest", "package"}
# A community plugin's version is a release asset too (its own CI built and attested it, README.md "Community
# plugins"), and its entry names more of it, so that the pull request shows the maintainer what the package is
# without opening it: the capabilities the owner is asked for (the package's manifest has to ask for exactly these),
# the author's signature over the manifest (the package's manifest.sig, byte for byte), and the SHA-256 of its LICENSE
# (the only member that neither the signature nor the manifest's program digest names).  With them every byte of
# the package is the entry's word, whatever the release asset is replaced with after the merge: the manifest by its
# digest, the program by the manifest's, the signature, the LICENSE
COMMUNITY_KEYS = {"version", "commit", "workflow", "manifest", "package", "signature", "license_sha256", "capabilities"}
# broad capabilities (hassmic's docs/plugins.md 5.3: net.lan with any port, net.internet, call, request.audio,
# request.text, log.read.full): flagged per community version in index.json ("broad"), by the build and on the page
BROAD = ("net.lan", "net.internet", "call", "request.audio", "request.text", "log.read.full")
assert len(BROAD) <= BOUNDS["BROAD_MAX"], "an Echo refuses an index whose broad lists more names than BROAD_MAX"
# and each name under CAP_NAME_MAX: one longer in "broad" makes every Echo refuse the whole index, older builds too
# (a review of hassmic a30d6ed, K7).  CAP (below) is what a version's capability names may be at all
assert all(len(c.encode()) <= BOUNDS["CAP_NAME_MAX"] for c in BROAD), "a broad name an Echo refuses: over CAP_NAME_MAX bytes"


class Bad(Exception):
    pass


def text_ok(s, most):
    """one line of text people read: nothing that steers a terminal (controls, direction marks, line separators),
    no < or >, and nothing that is no character at all.  A page that shows the index still escapes what it shows"""
    if not isinstance(s, str) or not 0 < len(s) <= most or s != s.strip():
        return False
    return not any(c in "<>" or unicodedata.category(c) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp") for c in s)


def text_bytes(s, most):
    """text_ok, and at most MOST bytes of UTF-8: what the Echo keeps (plugin_index.c text) is counted in bytes"""
    return text_ok(s, most) and len(s.encode("utf-8", "surrogatepass")) <= most


def plain(v, depth=0):
    """a manifest's value as the index repeats it: numbers, short texts, and lists and objects of them"""
    if v is None or type(v) is bool:
        return True
    if type(v) is int:
        return abs(v) <= VERSION_MAX
    # (a fraction: a number entity's limits and step, ha.entities; the Echo reads only the capabilities'
    # names of index.json, plugin_index.c version_parse, and its reader takes any number)
    if type(v) is float:
        return math.isfinite(v) and abs(v) <= VERSION_MAX
    if isinstance(v, str):
        return v == "" or text_ok(v, 200)
    # (five deep: an action's arguments, ha.actions, are objects in a list in an object in a list in
    # the capabilities)
    if depth < 5 and isinstance(v, list):
        return len(v) <= 64 and all(plain(x, depth + 1) for x in v)
    if depth < 5 and isinstance(v, dict):
        return len(v) <= 64 and all(text_ok(k, 48) and plain(x, depth + 1) for k, x in v.items())
    return False


def parse_json(data, what):
    try:
        return json.loads(data, object_pairs_hook=plugcheck.no_twice)
    except (ValueError, RecursionError) as e:
        raise Bad(f"{what}: {e}")


def load_json(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise Bad(f"{path}: {e}")
    return parse_json(data, path)


def entry_check(name, e):
    """one plugins/<id>.json"""
    def bad(why):
        raise Bad(f"plugins/{name}: {why}")
    if not isinstance(e, dict) or set(e) != ENTRY_KEYS:
        bad(f"its fields are {', '.join(sorted(ENTRY_KEYS))}, all of them and no other")
    if not isinstance(e["id"], str) or not ID.fullmatch(e["id"]) or name != e["id"] + ".json":
        bad("the id is 3 to 24 lower case letters, digits and - (not as its first or its last, and no two in a row), and names the file")
    if not text_bytes(e["name"], BOUNDS["NAME_MAX"]) or not text_bytes(e["author"], BOUNDS["AUTHOR_MAX"]) or not text_bytes(e["description"], BOUNDS["DESCRIPTION_MAX"]):
        bad(f"name and author are up to {BOUNDS['NAME_MAX']} bytes, the description up to {BOUNDS['DESCRIPTION_MAX']} (UTF-8), one line each")
    if not isinstance(e["author_key"], str) or not HEX32.fullmatch(e["author_key"]):
        bad("author_key is the author's public key: 64 hex digits, lower case")
    if otatool.weak(bytes.fromhex(e["author_key"])):
        bad("author_key is a key under which any signature holds (small order: all zero, the identity, ...) or no point at all: no author's key, and an Echo refuses it")
    if e["tier"] not in ("official", "community"):
        bad("tier is official or community")
    if not isinstance(e["source"], str) or not URL.fullmatch(e["source"]) or attest.repo_of(e["source"]) is None:
        bad("source is the plugin's GitHub repository, https://github.com/<owner>/<repository> and nothing after: its GitHub Actions "
            "build, attest and release the package (tools/attest.py)")
    if e["tier"] == "official" and not e["source"].startswith(OFFICIAL_SOURCE):
        bad(f"an official plugin's source is the project's own: {OFFICIAL_SOURCE}...")
    if len(e["source"]) > BOUNDS["SOURCE_MAX"]:
        bad(f"its source is up to {BOUNDS['SOURCE_MAX']} characters")
    if not isinstance(e["versions"], list):
        bad("versions is a list")
    if len(e["versions"]) > BOUNDS["VERSIONS"]:
        bad(f"at most {BOUNDS['VERSIONS']} versions: an Echo reads no more of a plugin (take the oldest out)")
    last = 0
    keys = VERSION_KEYS if e["tier"] == "official" else COMMUNITY_KEYS
    for v in e["versions"]:
        if not isinstance(v, dict) or set(v) != keys:
            bad(f"a{'n official' if e['tier'] == 'official' else ' community'} plugin's version has the fields {', '.join(sorted(keys))}")
        if type(v["version"]) is not int or not last < v["version"] <= VERSION_MAX:
            bad("versions are whole numbers from 1, each higher than the one before")
        last = v["version"]
        if not isinstance(v["commit"], str) or not HEX20.fullmatch(v["commit"]):
            bad(f"version {last}: commit is the source's commit it was built from, 40 hex digits")
        # the workflow that built and attested the release (attest.py: the attestation has to be that file's own
        # run for the tag's push, at that commit): the one the maintainer reads, with all it calls and runs
        if not isinstance(v["workflow"], str) or not attest.WORKFLOW.fullmatch(v["workflow"]):
            bad(f"version {last}: workflow is the path of the release workflow that built and attested the package, "
                ".github/workflows/<name>.yml (hassmic's template: .github/workflows/release.yml)")
        if not isinstance(v["manifest"], str) or not HEX32.fullmatch(v["manifest"]):
            bad(f"version {last}: manifest is the digest `plugcheck.py show` prints, 64 hex digits")
        if e["tier"] == "community":
            community_version_check(v, bad)
        # the plugin's own release asset and nothing else, official and community alike: a package from anywhere else
        # would be one its repository never published (and the index lists, with its key, what it fetched; the
        # attestation says that repository's CI built it, at the entry's commit)
        head, name = f"{e['source']}/releases/download/", f"/{e['id']}-{last}.hmp"
        if (not isinstance(v["package"], str) or not URL.fullmatch(v["package"]) or not v["package"].startswith(head) or not v["package"].endswith(name)
                or not TAG.fullmatch(v["package"][len(head):-len(name)])):
            bad(f"version {last}: the package is the plugin's own release asset: {head}<tag>{name}")


def release_tag(e, v):
    """the tag the release asset of version V of E is under (entry_check held its address to
    <source>/releases/download/<tag>/<id>-<version>.hmp): the attestation has to be of that tag's push"""
    head, name = f"{e['source']}/releases/download/", f"/{e['id']}-{v['version']}.hmp"
    return v["package"][len(head):-len(name)]


def community_version_check(v, bad):
    """a community version's own fields (entry_check has the rest): the author's signature, the LICENSE's SHA-256 and
    the capabilities it declares (refused here already where no package of it could be listed: 3.3's combinations,
    log.read.full, rule 48)"""
    n = v["version"]
    if not isinstance(v["signature"], str) or not re.fullmatch(r"[0-9a-f]{128}", v["signature"]):
        bad(f"version {n}: signature is the author's manifest.sig as hex, 128 digits (index.py entry <package> prints it)")
    if not isinstance(v["license_sha256"], str) or not HEX32.fullmatch(v["license_sha256"]):
        bad(f"version {n}: license_sha256 is the SHA-256 of the package's LICENSE, 64 hex digits (index.py entry <package> prints it)")
    caps = v["capabilities"]
    if not isinstance(caps, dict) or not all(isinstance(k, str) and k in CAPS for k in caps) or not plain(caps):
        bad(f"version {n}: capabilities is the manifest's \"capabilities\" as it is: an object of the capabilities hassmic knows")
    if "log.read.full" in caps:
        bad(f"version {n}: the whole log (\"log.read.full\") is for official plugins only")
    if "request.audio" in caps and "net.internet" in caps:
        bad(f"version {n}: a community plugin that hears every request (\"request.audio\") may not reach the internet (\"net.internet\"): it is not listed")
    if "wake" in caps and set(caps) - {"wake", "files", "storage"}:
        bad(f"version {n}: a plugin that hears the microphone all the time (\"wake\") may have only files and storage besides")


def revoked_check(r, now=None):
    """revoked.json: a serial (the time of its last change) and entries by plugin id (every version, or up to one) or
    by author key.  Any tier: the index key that makes a plugin official may withdraw it (as hassmic's builds since
    2026-11-21 take it), an official plugin's id and its author's key included"""
    def bad(why):
        raise Bad(f"revoked.json: {why}")
    now = time.time() if now is None else now
    if not isinstance(r, dict) or set(r) != {"serial", "entries"} or type(r["serial"]) is not int or r["serial"] < 0 or not isinstance(r["entries"], list):
        bad("a serial (the time of its last change, date +%s) and entries")
    # a serial set far ahead would be the one every later list has to beat: an Echo with its clock set refuses one,
    # and one that took it holds every honest list to it for as long as its floor allows (hassmic's pi_floor)
    if r["serial"] > now + BOUNDS["AHEAD_S"]:
        bad("its serial is a time more than a day after now: write the time of the change (date +%s)")
    if len(r["entries"]) > BOUNDS["REVOCATIONS"]:
        bad(f"more than {BOUNDS['REVOCATIONS']} entries: an Echo refuses the whole list (withdraw by author key where one author has many)")
    for x in r["entries"]:
        if not isinstance(x, dict) or not text_bytes(x.get("reason"), BOUNDS["REASON_MAX"]):
            bad(f"each entry has a reason, one line, up to {BOUNDS['REASON_MAX']} bytes")
        if set(x) == {"author_key", "reason"}:
            if not isinstance(x["author_key"], str) or not HEX32.fullmatch(x["author_key"]):
                bad("author_key: 64 hex digits, lower case")
        elif set(x) in ({"id", "reason"}, {"id", "upto", "reason"}):
            if not isinstance(x["id"], str) or not ID_WAS.fullmatch(x["id"]):
                bad("id: a plugin's id")
            if "upto" in x and (type(x["upto"]) is not int or not 1 <= x["upto"] <= VERSION_MAX):
                bad(f"{x['id']}: upto is the last version withdrawn")
        else:
            bad("an entry names an id (with upto, or every version) or an author_key, and a reason")
    if len(revoked_bytes(r)) > BOUNDS["REVOKED_MAX"]:
        bad(f"over {BOUNDS['REVOKED_MAX'] >> 10} kB as published: an Echo refuses it whole")


def withdrawn(revoked, pid, version, author_key):
    """the reason the revocation list REVOKED withdraws that version, or None (hassmic's pi_withdrawn)"""
    for x in revoked["entries"]:
        if ("author_key" in x and x["author_key"] == author_key) or (x.get("id") == pid and ("upto" not in x or version <= x["upto"])):
            return x["reason"]
    return None


def revoked_bytes(r):
    return dump({"revoked": 1, "serial": r["serial"], "entries": r["entries"]})


def index_keys(root):
    """the keys the published site is read with: keys/index.pub, and keys/index-previous.pub while the index's key
    changes (README "A new index key"): the site the last publish left is signed by the previous key until the first
    publish with the new one, which this tool then builds over (serials, official entries, --bump's built-from.txt,
    the packages fetch takes from it).  What it signs, and what sign and verify take, is keys/index.pub's alone.
    Neither may be a key under which any signature holds, nor one that is no point at all (otatool.weak: small order,
    and the encodings it does not read, six of which Monocypher reads as small order)"""
    keys = []
    for name in ("index.pub", "index-previous.pub"):
        p = os.path.join(root, "keys", name)
        if name == "index-previous.pub" and not os.path.exists(p):
            continue
        try:
            with open(p, "rb") as f:
                k = f.read(33)
        except OSError as x:
            raise Bad(f"keys/{name}: {x}")
        if len(k) != 32:
            raise Bad(f"keys/{name}: not a public key of 32 bytes")
        if otatool.weak(k):
            raise Bad(f"keys/{name}: a key under which any signature holds (small order) or no point at all: no key")
        keys.append(k)
    if len(keys) == 2 and keys[0] == keys[1]:
        raise Bad("keys/index-previous.pub is keys/index.pub: remove it once the published site is the new key's")
    return keys


def published(root, previous, by=None):
    """the site as it is published: its index and its revocation list, (None, None) when there is none yet (no
    folder given, or an empty one).  Anything else has to be a site the index key signed: an unsigned one would
    let whoever can write the published branch set the serials back, or forward for good.  During a change of the
    key, the previous key's too (index_keys); BY (a list) gets the key that signed it"""
    if not previous or (os.path.isdir(previous) and not [n for n in os.listdir(previous) if n != ".nojekyll"]):
        return None, None
    try:
        pk = verify(previous, index_keys(root), say=False, older=True)
    except Bad as e:
        raise Bad(f"the published site in {previous} is not one the index key signed: {e}")
    if by is not None:
        by.append(pk)
    ix, rv = load_json(os.path.join(previous, "index.json")), load_json(os.path.join(previous, "revoked.json"))
    if (not isinstance(ix, dict) or type(ix.get("serial")) is not int or not isinstance(ix.get("plugins"), list)
            or not all(isinstance(p, dict) for p in ix["plugins"])
            or not isinstance(rv, dict) or type(rv.get("serial")) is not int or not isinstance(rv.get("entries"), list)):
        raise Bad(f"the published site in {previous}: its index or its revocation list is none")
    return ix, rv


def load(root, previous=None):
    """the entries and the revocation list, checked, and the published index"""
    d = os.path.join(root, "plugins")
    try:
        names = sorted(os.listdir(d))
    except OSError as e:
        raise Bad(f"plugins/: {e}")
    entries = []
    for name in names:
        if not name.endswith(".json"):
            raise Bad(f"plugins/{name}: only <id>.json files belong here")
        e = load_json(os.path.join(d, name))
        entry_check(name, e)
        entries.append(e)
    by = []
    was, old = published(root, previous, by)
    # official: by the entries, and by what is published as official.  Without the second, taking an entry out and
    # withdrawing its plugin in one change would pass.  (What holds in the end is on the Echo: it takes no
    # revocation for a package this key listed as official.)
    # And an official plugin that is published keeps its entry and its key: taken out in one change, it could be
    # withdrawn in the next, which no single published site would show.
    now = {e["id"]: e for e in entries}
    for p in (was or {}).get("plugins", []):
        if p.get("tier") == "official" and (p.get("id") not in now or now[p["id"]]["tier"] != "official" or now[p["id"]]["author_key"] != p.get("author_key")):
            raise Bad(f"plugins/{p.get('id')}.json: published as official: its entry stays, with its tier and author key (versions may go, and the revocation list may withdraw it)")
    if len(entries) > BOUNDS["PLUGINS_MAX"]:
        raise Bad(f"plugins/: more than {BOUNDS['PLUGINS_MAX']} plugins: an Echo reads no more of the index")
    revoked = load_json(os.path.join(root, "revoked.json"))
    revoked_check(revoked)
    if old and revoked["entries"] == old["entries"] and revoked["serial"] <= old["serial"]:
        # The list as published: under the published serial, which may be higher than this file's (raised at a key's
        # switch, below).  A changed list still needs a higher serial than the published one, and none goes back
        revoked = dict(revoked, serial=old["serial"])
        if by and by[0] != index_keys(root)[0]:
            # The publish that switches the index's key (README "A new index key", step 2): the same list, signed
            # by the new key, under a serial one higher.  An Echo of both keys takes a list of the same serial as the
            # one it has as "the same" and kept the old key's signature on its flash; under hassmic's build of the new
            # key alone that file was no list, and what it withdrew ran until that Echo's next look at the site (a
            # review of hassmic 3c5d7ff, R1).  A newer list is taken, kept and handed on as the new key signed it.
            # One second on: the serial is a time, and the next change of revoked.json needs one above it
            revoked = dict(revoked, serial=old["serial"] + 1)
            print(f"revoked.json: serial {revoked['serial']}, one above the published list's, signed anew by the new index key")
    elif old and (revoked["serial"] < old["serial"] or (revoked["entries"] != old["entries"] and revoked["serial"] == old["serial"])):
        raise Bad(f"revoked.json: the published list has serial {old['serial']}: a changed list needs a higher one, and none goes back")
    return entries, revoked, was


# ---------------------------------------------------------------- the manifest, as an Echo reads it
MANIFEST_MAX = 32768                            # plugin_store.c:53
CAPS = ("storage", "files", "state", "log.read", "log.read.full", "net.server", "net.lan", "net.internet", "net.udp",
        "net.discover", "audio.music", "audio.volume", "call", "wake", "request.audio", "request.text", "ha.entities",
        "ha.actions", "button")                 # cap_names, plugin_store.c:76 (button: bit 18)
assert all(CAP.fullmatch(c) for c in CAPS) and CAP_LONGEST <= BOUNDS["CAP_NAME_MAX"] and not CAP.fullmatch("a" * (CAP_LONGEST + 1)), \
    "a capability's name an Echo keeps whole: CAP takes none over CAP_NAME_MAX bytes"
# capabilities that are a yes and nothing more: CAPS_PLAIN, plugin_store.c (ps_manifest_parse's)
CAPS_PLAIN = ("state", "log.read", "log.read.full", "audio.music", "audio.volume", "call", "wake", "request.audio", "request.text", "button")
# The scopes of the plugin protocol (hassmic's sdk/PROTOCOL.md "Versions", sdk/messages.def's scope lines, plugmsg.h
# PM_SCOPE_*): core, which every plugin speaks, and one per capability, each with the newest version any hassmic has.
# A manifest's "requires" names the least version of each scope it speaks (core and the scope of every capability it
# asks for, nothing else); an Echo runs it where each of its own versions is at least that (requires_parse, "needs a
# newer hassmic: ..."), and the index refuses one that requires a version no hassmic has yet: unmet() against this
# table.  A new version of a scope is added here when the hassmic that brings it is released; the tests hold the
# table to plugmsg.h's PM_SCOPE_VERSION_* (and the C harness to pm_scope_name, pm_scope_version)
SCOPES = {"core": 1, "storage": 1, "files": 1, "state": 1, "log.read": 1, "log.read.full": 1, "net.server": 1, "net.lan": 1,
          "net.internet": 1, "net.udp": 1, "net.discover": 1, "audio.music": 1, "audio.volume": 1, "call": 1, "wake": 1,
          "request.audio": 1, "request.text": 1, "ha.entities": 1, "ha.actions": 1, "button": 1}
assert set(SCOPES) == {"core", *CAPS} and all(SCOPE.fullmatch(x) for x in SCOPES), "a scope per capability, and core"
# The manifest's keys where they stand, with the scope and the version of it that brought each: hassmic's
# sdk/messages.def "keys" lines (plugmsg.h pm_key, plugin_store.c keys_versioned), line for line; the tests hold the
# two to each other.  A key of a later version than the manifest requires of its scope refuses it (rule 17b); a key
# not here refuses it where the context is strict (a capability's entries) and is left alone where not
KEY_LINES = (("manifest", "core", 1, "id name author version version_name source license description requires author_key digest memory_mb threads models capabilities settings"),
             ("setting", "core", 1, "name label type help unit min max options default item max_items fields catalog"),
             ("setting.item", "files", 1, "by files"),
             ("setting.item.file", "files", 1, "suffix as max_kb optional"),
             ("setting.field", "files", 1, "name label type min max step"),
             ("net.server", "net.server", 1, "setting proto ports"),
             ("net.discover", "net.discover", 1, "udp to"),
             ("net.lan", "net.lan", 1, "proto ports"),
             ("net.internet", "net.internet", 1, "proto ports"),
             ("ha.entities.binary_sensor", "ha.entities", 1, "name kind label icon page"),
             ("ha.entities.sensor", "ha.entities", 1, "name kind label icon page unit decimals"),
             ("ha.entities.text_sensor", "ha.entities", 1, "name kind label icon page"),
             ("ha.entities.switch", "ha.entities", 1, "name kind label icon page"),
             ("ha.entities.button", "ha.entities", 1, "name kind label icon page"),
             ("ha.entities.number", "ha.entities", 1, "name kind label icon page unit min max step"),
             ("ha.entities.select", "ha.entities", 1, "name kind label icon page options"),
             ("ha.entities.event", "ha.entities", 1, "name kind label icon page types"),
             ("ha.actions", "ha.actions", 1, "name label args page calls"),
             ("ha.actions.arg", "ha.actions", 1, "name type"))
KEYS = {(c, k): (sc, v) for c, sc, v, ks in KEY_LINES for k in ks.split()}
assert all(sc in SCOPES and 1 <= v <= SCOPES[sc] for sc, v in KEYS.values()), "each key of a scope at a version no hassmic lacks"
NET_MOST, PORTS_MOST = 4, 8                     # plugin_store.h PS_NET, PS_PORTS
DNS_PORTS = (53, 853)                           # plugin_store.h PS_PORT_RELAY: never net.lan's nor net.discover's
UDP_MOST, ENTITIES_MOST, ACTIONS_MOST, ARGS_MOST, TYPES_MOST = 4, 16, 8, 4, 8     # plugin_store.h PS_UDP_MAX, PS_ENTITIES, PS_ACTIONS, PS_ARGS, PS_TYPES
ENTITY_KINDS = ("binary_sensor", "sensor", "text_sensor", "switch", "button", "number", "select", "event")       # ps_entity_kind
# the kinds with a state ("page": true only there; each kind's keys: KEYS, "ha.entities.<kind>")
PAGE_KINDS = ("binary_sensor", "sensor", "text_sensor", "switch", "number", "select")
ICON = re.compile(r"mdi:[a-z0-9-]+")
GROUP = re.compile(r"(2(?:2[4-9]|3[0-9]))\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})")


SETTING_TYPES = ("bool", "int", "select", "text", "host", "secret", "files")    # plugin_store.c:461
FIELD_TYPES = ("text", "number", "int")         # plugin_store.c:545
SETTINGS_MOST, OPTIONS_MOST, FIELDS_MOST, ITEM_FILES_MOST, ITEMS_MOST = 32, 12, 8, 4, 64   # plugin_store.h PS_*
JSON_DEPTH, JSON_TEXT, JSON_NUM = 64, 1024, 40  # json.h; tstr's buffer (plugin_store.c:354); json_num's (json.c:217), form :328
LONG = 1 << 31                                  # an Echo's long and int: 32 bits
SETTING_NAME, HEX64 = re.compile(r"[a-z0-9_]{1,32}"), re.compile(r"[0-9a-fA-F]{64}")
SUFFIX, FILE_AS = re.compile(r"\.[A-Za-z0-9]{1,15}"), re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*")
MODEL = re.compile(r"[a-z][a-z0-9_-]{0,31}")
# host_name_ok, plugin_store.c:448: labels of ASCII letters, digits and hyphens, a dot between, none empty, no hyphen at an end
HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*")
STRING = re.compile(rb'"((?:[^"\\]|\\.)*)"', re.S)


class Written(str):
    """a text of the manifest with the bytes it is in the file, between its quotes"""
    raw = b""


class Whole(int):
    """a number of the manifest written as digits, with a sign at most, and the text it is written as"""
    raw = ""


class Frac(float):
    """a number of the manifest written with a fraction or an exponent, and the text it is written as"""
    raw = ""


def _number(kind):
    def read(s):
        if len(s) >= JSON_NUM:                              # (before Python reads it: it reads no int of over 4300 digits)
            raise ValueError(f"a number written with more than {JSON_NUM - 1} characters ({s[:24]}...)")
        v = kind(s)
        v.raw = s
        return v
    return read


def _no_word(s):
    raise ValueError(f"{s} is no JSON")


def as_written(v, raws, depth=0):
    """the parsed manifest again, each text (keys too) with what it is written as: RAWS are the file's strings in
    their order, which is the order of the parsed one's (no key is there twice).  ValueError for what the Echo's
    form() and json.c refuse, wherever in the text it is"""
    if depth > JSON_DEPTH:
        raise ValueError(f"nested more than {JSON_DEPTH} deep")
    if isinstance(v, str):
        s = Written(v)
        s.raw = next(raws, None)
        if s.raw is None:
            raise ValueError("its texts are not the ones of the bytes given")
        if any(ord(c) < 0x20 or ord(c) == 0x7f or 0xD800 <= ord(c) < 0xE000 for c in v):
            raise ValueError("a text with a control character or half a character")
        return s
    if isinstance(v, Frac) and not abs(v) <= 1.7e308:       # (not <=: NaN too)
        raise ValueError("a number past what a number holds")
    if isinstance(v, list):
        return [as_written(x, raws, depth + 1) for x in v]
    if isinstance(v, dict):
        d = {}
        for k, x in v.items():
            k = as_written(k, raws)
            if b"\\" in k.raw:
                raise ValueError(f"the key {str(k)[:24]!r} is written with an escape: the Echo does not find it")
            d[k] = as_written(x, raws, depth + 1)
        return d
    return v


def manifest_read(raw, what):
    """the manifest RAW as the Echo's reader and its form() take it, texts and numbers with what they are written
    as (Written, Whole, Frac).  Bad for a text that is not one JSON object written as the Echo reads it"""
    try:
        if len(raw) > MANIFEST_MAX:
            raise ValueError(f"over {MANIFEST_MAX} bytes")
        if raw[:1] != b"{" or b"\0" in raw:                 # (json.loads would take UTF-16 and a BOM too)
            raise ValueError("not one JSON object in UTF-8 and nothing else")
        if b"\x7f" in raw:
            raise ValueError("a control character (0x7f) in it")
        try:                                                # (json.loads would let half a surrogate pair by, as bytes)
            raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("not UTF-8: it has bytes that are no character")
        m = json.loads(raw, object_pairs_hook=plugcheck.no_twice, parse_int=_number(Whole), parse_float=_number(Frac), parse_constant=_no_word)
        raws = iter([x.group(1) for x in STRING.finditer(raw)])
        m = as_written(m, raws)
        if next(raws, None) is not None:
            raise ValueError("its texts are not the ones of the bytes given")
    except (ValueError, RecursionError) as e:
        raise Bad(f"{what}: the manifest is not JSON as the Echo reads it: {e}")
    return m


def shown(s, most):
    """text as the Echo keeps and shows it: at most MOST bytes of UTF-8, under 1024 as written, no control
    characters (manifest_read refused those already, however they are written)"""
    try:
        return isinstance(s, Written) and len(s.raw) < JSON_TEXT and len(s.encode()) <= most and not any(ord(c) < 0x20 or ord(c) == 0x7f for c in s)
    except UnicodeEncodeError:                              # half a character
        return False


def unmet(requires, table=None):
    """the versions REQUIRES (a manifest's "requires", as read) names that TABLE (a scope's name: its version; SCOPES
    when none) does not have, each "<scope> <version>", in the manifest's order; a name the table does not know among
    them (a scope of a later hassmic), as requires_parse says them"""
    table = SCOPES if table is None else table
    return [f"{k} {int(v)}" for k, v in requires.items() if v > table.get(k, 0)]


# The rules of utf8_ok, form, ps_manifest_parse, setting_parse, refs_ok and combination (hassmic's
# src/hassmic/plugin_store.c; json.c is its reader), one by one, each with the line it mirrors in hassmic at 3feeda2
# (which is past tools/VERSION, the commit the copied tools are of): when that file changes, this list says what to
# follow here.  The Echo reads a manifest as it is written or not at all, and so does this; "stricter" marks the one
# place where this refuses what that commit's code takes (rule 15), with its reason.  Where an earlier list said
# "stricter" (bytes that are no UTF-8, 0x7f as a byte in a text the Echo does not read, an api written with a sign, a
# space or a zero in front, a field's number of more than 39 bytes) the Echo's code refuses the same now.  Against
# 4d907f1, the list before this one: rule 9 (an id's hyphens) and rule 45 (the rows a capability names) are new in
# the Echo's code and here; nothing else of the manifest's reading changed (the accepted section's digest, which now
# covers description and source, is the Echo's own).  Since then (hassmic's working tree past 66eddb9, the protocol's
# versioned scopes): "api" is gone and "requires" in its place (rules 8, 11, 17a, 20a, 22d; requires_parse and
# ps_manifest_parse, cited by name: their lines are not yet a commit's).  And since hassmic's review of 4e0a202 (the
# keys by version): rule 17b, keys_versioned, in every object the Echo's reader walks, the net.server, net.discover,
# net.lan, net.internet, ha.entities and ha.actions entries' key lists now KEYS's (the same keys as before).
# tests/test_index.py holds the two to each other.
#
#   the text (utf8_ok, :154; json_parse, json.c:101; form, :313, over every token: also keys the Echo never asks for,
#   and catalogs)
#    1  :621      UTF-8 and nothing else, the whole text: no byte that begins no character, none cut short, none
#                 written longer than it needs, no half of a surrogate pair, nothing past U+10FFFF (utf8_ok: what
#                 Python's strict decoder takes, and no other)
#       :622      at most 32768 bytes, and JSON.  json.c:56 nesting at most 64 deep; json.c:88 no NaN or Infinity
#    2  :315      it starts with "{" (no white space, no BOM), has no NUL, and nothing but white space follows the
#                 object (json.c:108)
#    3  :623      the manifest is an object
#    4  :322-332  numbers are written as JSON writes them (num_form, :273: Python's reader takes no other), each in
#                 at most 39 characters, sign, fraction and exponent counted (:328: json_num, json.c:217, reads no
#                 more of one), wherever it is; and one with a fraction or an exponent is within +-1.7e308 (:332)
#    5  :319      no byte 0x7f anywhere in the text (inside a JSON text or not: outside one it is no JSON either)
#       :333      no text has a control character, 0x7f or half a surrogate pair written as an escape (str_form,
#                 :291: \b \f \n \r \t and \u0000 to \u001f among them); json.c:35 none has a byte under 0x20
#    6  :338      no key is written with an escape, in any object
#    7  :342      no key is twice in one object (plugcheck.no_twice, as the reader goes)
#   texts (tstr, :352; jstr, :361): text (no number, no null), at most cap - 1 bytes, under 1024 bytes as written
#   (escapes counted as written), none of rule 5's characters (text_ok, :150)
#   whole numbers (whole, :373; jwhole, :397): a number written as digits with a sign at most (no fraction, no
#   exponent, no text, no true or null), within 32 bits, and not -0 (:379: one value written two ways); where one may
#   be left out, the default counts
#   the plugin
#    8  :625-628  needed: id (24 bytes), name (48), author (48); when there: version_name (24),
#                 source (200), license (32), description (240) (core 1's texts: read by every build, before requires)
#    9  :629      id: 3 to 24 of a-z, 0-9 and -; no - first, none last and no two in a row (ps_id_ok, :126, the
#                 last two new at 3feeda2: a package's file is <id>-<version>.hmp).  ID above, which entry_check
#                 holds an entry's id to as well, and verify a published package's
#   10  :630      name and author are not empty
#   12  :632      version: a whole number, 1 to 1000000000
#   11  requires_parse (asked by ps_manifest_parse right after version, before author_key and everything a scope's
#                 version may bring): "requires" is an object (else "the manifest has no \"requires\": ..."); each
#                 key, in the order written, a scope's name of 1 to 24 of a-z, 0-9, . and _ as written (rule 6: no
#                 escape), each value a whole number 1 to 65535 (not -0, no fraction or exponent, no text, no true);
#                 then every name this hassmic does not have at that version (a scope it does not know among them)
#                 is one for a newer hassmic: the Echo says "needs a newer hassmic: <scope> <n>, ..." and stops;
#                 the index refuses a version no hassmic has (SCOPES, unmet: "no hassmic has ... yet").  Then core
#                 has to be there
#   13  :633-636  author_key and digest: needed, 64 hex digits (either case, as isxdigit)
#   14  :637-640  memory_mb 8 to 96 (32 when left out), threads 1 to 16 (4 when left out)
#   15  :641-648  models: left out (every model), or a list (jlist, :415) of names, each a text of 1 to 32 bytes,
#                 that has "*" or the Echo's model.  MODEL=None, the index's case: stricter, "*" or at least one
#                 name a model could have (which models there are is not this tool's to know, but a list no Echo
#                 can be in is no plugin to list)
#   capabilities
#   16  :650-651  capabilities: needed, an object
#   17  :655-657  each key is one of the 19 names (CAPS)
#   18  :658      none twice (rule 7 refused it before)
#   19  :659      no false and no null as a value: left out instead
#   20  :660      one without parameters (CAPS_PLAIN, :612) is true
#   20a ps_manifest_parse: each capability's scope is in "requires" (what of the protocol it speaks is the
#                 manifest's word, never the build's guess)
#   17a ps_manifest_parse, after the capabilities: "requires" names core and those scopes and nothing else (a
#                 version of a scope it does not ask for is a version of nothing it may use)
#   17b keys_versioned (hassmic's messages.def "keys" lines, KEYS here): in the manifest itself (after requires), each
#                 setting, a file list's item, its files and its fields, and each capability's entries (as each is
#                 read), a key that a later version of its scope brought than the manifest requires of it, or one of
#                 a scope it does not require, refuses the manifest; a key no version has is refused in a
#                 capability's entries (net.server, net.discover, net.lan, net.internet, ha.entities by kind,
#                 ha.actions and their args: strict) and left alone elsewhere
#   21  :662      storage: a whole number, 1 to 1024 (kB)
#   22  :663      files: a whole number, 1 to 64 (MB)
#   22a net_parse net.server (net.server 1): a list of 1 to 4 objects, each with exactly the keys setting, proto and ports:
#                 setting a text naming a row of type host; proto "tcp" or "udp"; ports a list of 1 to 8 whole
#                 numbers, 1 to 65535 and never 5555, or a text "setting:<row>" (40 bytes at most) naming a row of
#                 type int whose min is 1 or more and whose max 65535 or less; neither row an entry names (the host
#                 row, the port row) has a default: the server and its port are the owner's to enter (net_parse,
#                 a review of hassmic 08399dc: a default reached the author's server with nothing typed).  Asked
#                 after rule 45
#   22b ps_manifest_parse net.udp (net.udp 1): a whole number, 1 to 4 (its ports of its own)
#   22c discover_parse net.discover (net.discover 1): an object of exactly udp and to: udp a whole number 1 to 65535, not 5555,
#                 not 2330 and not 28928 to 28999 (hassmic's own ports: a broadcast comes back to the Echo's own
#                 sockets; a review of hassmic efde36e, A1), not DNS's 53 or 853 (DNS_PORTS: the router's forwarder
#                 asks the internet; hassmic PS_PORT_RELAY, a review of 7be9343); to "broadcast" or a multicast
#                 group, a.b.c.d with a 224 to 239, each part 0 to 255 written without a zero in front (a text of at
#                 most 15 bytes)
#   22d entities_parse ha.entities (ha.entities 1): a list of 1 to 16 objects, each with kind (one of ENTITY_KINDS) and
#                 only the keys of its kind (KEYS "ha.entities.<kind>", rule 17b): name 1 to 32 of a-z, 0-9 and
#                 _, none twice; label a text of 1 to 64 bytes, none twice (Home Assistant keeps an entity by its name:
#                 a review of hassmic efde36e, H3); icon "mdi:" and a-z, 0-9, - (64 bytes); unit 12 bytes;
#                 decimals 0 to 6; a number's min, max, step numbers (0, 100, 1 when left out), min below max, step
#                 above 0, within a billion; a select's options and an event's types a list of 1 to 12 (8) texts of 1
#                 to 32 bytes (a type also a name as an entity's), none twice.
#                 page (entities_parse, ha.entities 1): on any kind, true or false, and true only on a kind with a
#                 state, not a button or an event (PAGE_KINDS)
#   22e actions_parse ha.actions (ha.actions 1): a list of 1 to 8 objects of the keys name, label, args, page, calls: name
#                 and label as an entity's, neither twice; page true or false; calls true or false, true
#                 only with the capability call; args left out or a list of at most 4 objects of exactly name and
#                 type ("string", "int"), no name twice; page true only without args
#   22f reach_parse net.lan, net.internet (net.lan 1, net.internet 1): a list of 1 to 4 objects of exactly proto and ports: proto
#                 "tcp" or "udp"; ports a list of 1 to 8 whole numbers, 1 to 65535 and never 5555, or the text "any";
#                 net.lan's never 53 or 853 (DNS_PORTS: a way to the internet through the home's router; hassmic
#                 PS_PORT_RELAY, a review of 7be9343; under "any" the Echo refuses them at CONNECT)
#   settings
#   23  :666-669  left out, or a list of at most 32
#   24  :671      no name twice
#   25  :464      a setting is an object
#   26  :465-467  needed: name (32 bytes), label (64), type (15); when there: help (240), unit (12)
#   27  :468      name: 1 to 32 of a-z, 0-9 and _                        (name_ok, :142)
#   28  :469-470  type: bool, int, select, text, host, secret, files
#   29  :471-473  min, max, on a setting of any type: whole numbers (0 and, for an int, 1000000 when left out; -0 is
#                 none); an int's min is not over its max
#   30  :474-487  select: options, a list of 1 to 12, each a text of 1 to 32 bytes or a whole number written in at
#                 most 32 (digits, :387: kept as its text; -0 is none, :392), under 33 bytes as written; none twice
#                 (5 and "5" are one)
#   31  :491-509  default, when there, is of the setting's kind: bool true or false; int a whole number (not -0)
#                 within min and max; select one of its options (a number as it is written, not -0); text and secret
#                 a text of at most 64 bytes; host a text of at most 64 bytes that is a host name or an IPv4 address
#                 as one is written (host_name_ok, :448): labels of letters, digits and hyphens with dots between,
#                 none empty (so not "", no dot first or last, no two in a row), none beginning or ending in a
#                 hyphen; a file list has none
#   32  :512      type files needs the capability "files"
#   33  :515      files: item is an object, item.by is "stem"
#   34  :516-521, :535  files: item.files, a list of 1 to 4 objects, each with suffix (needed, 16 bytes) and as
#                 (32, may be left out)
#   35  :522      files: max_kb, a whole number, 1 to 16384 (needed: 0 when left out, which is refused)
#   36  :525      files: optional, when there, is true or false
#   37  :527-528  files: suffix is a dot and 1 to 15 letters and digits
#   38  :529-531  files: as ("file" + suffix when left out or empty): letters, digits, . _ -, the first no dot, and
#                 not fields, title or checked (the item's own files)
#   39  :532      files: no suffix and no as twice in an item
#   40  :536      files: max_items 1 to 64 (16 when left out)
#   41  :538-545  files: fields, left out or a list of at most 8 objects, each with name (as a setting's), label
#                 (64 bytes), type (text, number or int)
#   42  :546      fields: no name twice
#   43  :548      fields: min, max, step are numbers when there (jnumber, :404; -0 is one here; each of at most 39
#                 characters by rule 4, so json_num reads all of it)
#   44  :549      fields: min (0 when left out) is not over max (1e9)
#                 (catalog, :552, is the page's: only rules 1 to 7 hold for it)
#   the rows a capability names (refs_ok, :582, new at 3feeda2; asked at :675, after the settings, over the whole of
#   "capabilities", however deep: lists and objects walked, the keys of an object not read as texts)
#   45  :590      a text anywhere in a capability's value that begins "setting:" (by what it says: written with an
#                 escape it is one too, json_str) names, after the colon, a setting the manifest has that is no
#                 file list (row_named, :577)
#       :601      and a key "setting", in any object there, has such a row's name as its value: a text (tstr: a
#                 number, true, null, a list or an object is refused), and that row is there
#   combinations (combination, :722; asked by runnable, :740, for a package, ps_stage_check :1332, and at each start,
#   ps_scan :1554, after the listing said the tier; ps_scan, :1535, reads the manifest with the same
#   ps_manifest_parse and lists one it refuses as a plugin that cannot run)
#   46  :724      wake: besides it only files and storage (button among what it may not have: when a person
#                 is at the Echo is a way out; plugin_store.c:1033, the same set)
#   47  :727      log.read.full: official plugins only
#   48            the index's own, stricter than any Echo (hassmic's docs/plugins.md 3.3, 5.3): a community plugin with
#                 request.audio (it hears every request) and net.internet together is not listed.  An Echo takes such a package where it is official, after two presses of
#                 its action button (plugin_store.c ps_second); the rule is the index's for good.
#                 With net.lan, net.server, net.udp or net.discover it is listed, and flagged on the page (page.py:
#                 the Echo asks for its button twice, the second time on a screen of its own, plugin_store.c ps_second)
# Not here: what one build lacks (requires_parse against the build's own versions, "needs a newer hassmic"; the
# index refuses only what no hassmic has, rule 11, and lists the version's "requires"), what an Echo holds against a
# package because of what it has (the author key it pinned, the version installed, 16 plugins, 32 MB of programs:
# ps_stage_check, :1277), and official_least (:58, :1333), which is each build's.
def manifest_check(raw, what, tier, model=None):
    """the bytes RAW are a manifest an Echo installs: of the model MODEL (its codename), None for any.  The manifest
    as manifest_read gives it; Bad with the reason, in the Echo's words where it has them"""
    def bad(why):
        raise Bad(f"{what}: {why}")

    def text(o, key, most, need=True, of="the manifest's"):
        if key not in o:
            if need:
                bad(f"{of} \"{key}\" is missing")
            return ""
        if not shown(o[key], most):
            bad(f"{of} \"{key}\" is not text of at most {most} bytes")
        return o[key]

    def versioned(o, ctx, strict):                                                                 # 17b
        """O's keys in context CTX as hassmic's keys_versioned reads them: one of KEYS from a later version of its
        scope than the manifest requires (or of a scope it does not require) refuses it; one KEYS lacks: False where
        STRICT (the caller says it in its words), left alone where not"""
        for k in o:
            at = KEYS.get((ctx, str(k))) if shown(k, 24) else None
            if at is None:
                if strict:
                    return False
                continue
            sc, since = at
            if req.get(sc, 0) < since:
                bad(f"\"{ctx}\": the key \"{k}\" is {sc} {since}'s, and the manifest " + (f"requires {sc} {int(req[sc])}" if req.get(sc) else f"does not require {sc}"))
        return True

    def whole(o, key, default, low, high, why):
        v = o.get(key, default)
        if type(v) not in (Whole, int) or getattr(v, "raw", "") == "-0" or not max(low, -LONG) <= v <= min(high, LONG - 1):
            bad(why)
        return int(v)

    m = manifest_read(raw, what)                                                                    # 1, 2, 4-7
    if not isinstance(m, dict):                                                                     # 3
        bad("the manifest is not an object")
    for key, most, need in (("id", 24, True), ("name", 48, True), ("author", 48, True),            # 8
                            ("version_name", 24, False), ("source", 200, False), ("license", 32, False), ("description", 240, False)):
        text(m, key, most, need)
    if not ID.fullmatch(m["id"]):                                                                   # 9
        bad("the plugin's id: 3 to 24 lower case letters, digits and - (none first, last or twice in a row)")
    if not m["name"] or not m["author"]:                                                            # 10
        bad("the manifest names no plugin or no author")
    whole(m, "version", 0, 1, VERSION_MAX, "the manifest's version: a whole number from 1")         # 12
    req = m.get("requires")                                                                         # 11
    if not isinstance(req, dict):
        bad("the manifest has no \"requires\": the least version of each scope it speaks, {\"core\": 1, ...}")
    for name, v in req.items():
        if not SCOPE.fullmatch(name):
            bad("\"requires\": a scope's name is 1 to 24 of a-z, 0-9, . and _")
        if type(v) not in (Whole, int) or not 1 <= v <= 65535:                   # (-0 is 0: under 1)
            bad(f"\"requires\": \"{name}\": a version, a whole number from 1")
    if unmet(req):
        bad(f"no hassmic has {', '.join(unmet(req))} yet")
    if "core" not in req:
        bad("\"requires\" names no version of core, which every plugin speaks")
    versioned(m, "manifest", False)                                                                 # 17b
    for key in ("author_key", "digest"):                                                            # 13
        if not HEX64.fullmatch(text(m, key, 79)):
            bad(f"the manifest's {key}: 64 hex digits")
    whole(m, "memory_mb", 32, 8, 96, "the manifest's limits: memory_mb is 8 to 96 (MB), a whole number")        # 14
    whole(m, "threads", 4, 1, 16, "the manifest's limits: threads is 1 to 16, a whole number")
    if "models" in m:                                                                               # 15
        names = m["models"]
        if not isinstance(names, list) or not all(shown(x, 32) and x for x in names):
            bad("the manifest's models are a list of names, each of 1 to 32 bytes")
        if model is None and not any(x == "*" or MODEL.fullmatch(x) for x in names):
            bad("the manifest's models name no model an Echo could be (\"*\": every model)")
        if model is not None and "*" not in names and model not in names:
            bad(f"the manifest's models: this plugin is not for this model ({model})")

    caps = m.get("capabilities")
    if not isinstance(caps, dict):                                                                  # 16
        bad("the manifest has no \"capabilities\"")
    for name, v in caps.items():
        if name not in CAPS:                                                                        # 17 (18: rule 7)
            bad(f"capabilities: the manifest asks for {str(name)[:24]!r}, which no Echo knows")
        if v is False or v is None:                                                                 # 19
            bad(f"capabilities: \"{name}\": leave it out instead of false")
        if name in CAPS_PLAIN and v is not True:                                                    # 20
            bad(f"capabilities: \"{name}\": true, or left out (it has no parameters)")
        if name not in req:                                                                         # 20a
            bad(f"capability \"{name}\": its scope is not in \"requires\" (\"{name}\": the least version it speaks)")
    if "storage" in caps:                                                                           # 21
        whole(caps, "storage", 0, 1, 1024, "capabilities: \"storage\" is 1 to 1024 (kB), a whole number")
    if "net.udp" in caps:                                                                           # 22b
        whole(caps, "net.udp", 0, 1, UDP_MOST, f"\"net.udp\": 1 to {UDP_MOST} ports, a whole number")
    if "files" in caps:                                                                             # 22
        whole(caps, "files", 0, 1, 64, "capabilities: \"files\" is 1 to 64 (MB), a whole number")
    for name in req:                                                                                # 17a
        if name != "core" and name not in caps:
            bad(f"\"requires\" names {name}, which the manifest does not ask for")

    settings = m.get("settings", [])
    if not isinstance(settings, list):                                                              # 23
        bad("the manifest's settings are a list")
    if len(settings) > SETTINGS_MOST:
        bad(f"more than {SETTINGS_MOST} settings")
    seen = set()
    for s in settings:
        if not isinstance(s, dict):                                                                 # 25
            bad("a setting is not an object")
        versioned(s, "setting", False)                                                              # 17b
        for key, most, need in (("name", 32, True), ("label", 64, True), ("type", 15, True), ("help", 240, False), ("unit", 12, False)):   # 26
            text(s, key, most, need, "a setting's")
        name, kind = s["name"], s["type"]
        if not SETTING_NAME.fullmatch(name):                                                        # 27
            bad(f"a setting's name {str(name)!r}: lower case letters, digits and _")
        if kind not in SETTING_TYPES:                                                               # 28
            bad(f"setting {name}: no type {str(kind)!r}")
        low = whole(s, "min", 0, -LONG, LONG, f"setting {name}: min is a whole number")              # 29
        high = whole(s, "max", 1000000 if kind == "int" else 0, -LONG, LONG, f"setting {name}: max is a whole number")
        if kind == "int" and low > high:
            bad(f"setting {name}: min over max")
        options = []
        if kind == "select":                                                                        # 30
            if not isinstance(s.get("options"), list) or not s["options"]:
                bad(f"setting {name}: a select without options (a list)")
            for o in s["options"]:
                # as the Echo keeps it: a text, or a whole number as it is written
                if len(options) == OPTIONS_MOST or not ((type(o) is Whole and o.raw != "-0" and len(o.raw) < 33) or (shown(o, 32) and o and len(o.raw) < 33)):
                    bad(f"setting {name}: its options: at most {OPTIONS_MOST}, each a text of 1 to 32 bytes as written")
                o = o.raw if type(o) is Whole else str(o)
                if o in options:
                    bad(f"setting {name}: the option {o!r} twice")
                options.append(o)
        if "default" in s:                                                                          # 31
            d = s["default"]
            if not {"bool": lambda: type(d) is bool,
                    "int": lambda: type(d) is Whole and d.raw != "-0" and max(low, -LONG) <= d <= min(high, LONG - 1),
                    "select": lambda: (d.raw if type(d) is Whole and d.raw != "-0" else str(d) if shown(d, 32) else None) in options,
                    "text": lambda: shown(d, 64), "secret": lambda: shown(d, 64),
                    "host": lambda: shown(d, 64) and HOST.fullmatch(d) is not None,
                    "files": lambda: False}[kind]():
                bad(f"setting {name}: its default is " + {"bool": "true or false", "int": "a whole number within min and max", "select": "one of its options",
                                                           "host": "a host name or an address of at most 64 bytes", "files": "not there: a file list has none"}.get(kind, "text of at most 64 bytes"))
        if kind == "files":
            if "files" not in caps:                                                                 # 32
                bad(f"setting {name} is a file list, and the manifest does not ask for \"files\"")
            item = s["item"] if isinstance(s.get("item"), dict) else {}
            if not shown(item.get("by"), 7) or item["by"] != "stem":                                # 33
                bad(f"setting {name}: items are grouped \"by\": \"stem\"")
            versioned(item, "setting.item", False)                                                  # 17b
            files = item.get("files")
            if not isinstance(files, list) or not files:                                            # 34
                bad(f"setting {name}: an item has no files (a list)")
            if len(files) > ITEM_FILES_MOST:
                bad(f"setting {name}: more than {ITEM_FILES_MOST} files an item")
            had = []
            for f in files:
                if not isinstance(f, dict):
                    bad(f"setting {name}: a file of an item is not an object")
                versioned(f, "setting.item.file", False)                                            # 17b
                suffix = text(f, "suffix", 16, True, f"setting {name}: a file's")
                kept = text(f, "as", 32, False, f"setting {name}: a file's") or "file" + suffix
                whole(f, "max_kb", 0, 1, 16384, f"setting {name}: a file's size: max_kb is 1 to 16384, a whole number")   # 35
                if type(f.get("optional", False)) is not bool:                                      # 36
                    bad(f"setting {name}: a file's optional is true or false")
                if not SUFFIX.fullmatch(suffix):                                                    # 37
                    bad(f"setting {name}: a file's suffix: a dot and up to 15 letters and digits")
                if not FILE_AS.fullmatch(kept) or kept in ("fields", "title", "checked"):           # 38
                    bad(f"setting {name}: a file's name (as)")
                if any(suffix == a or kept == b for a, b in had):                                   # 39
                    bad(f"setting {name}: a file twice")
                had.append((str(suffix), str(kept)))
            whole(s, "max_items", 16, 1, ITEMS_MOST, f"setting {name}: max_items 1..{ITEMS_MOST}")   # 40
            fields = s.get("fields", [])
            if not isinstance(fields, list):                                                        # 41
                bad(f"setting {name}: its fields are a list")
            if len(fields) > FIELDS_MOST:
                bad(f"setting {name}: more than {FIELDS_MOST} fields")
            names = set()
            for f in fields:
                if not isinstance(f, dict):
                    bad(f"setting {name}: a field is not an object")
                versioned(f, "setting.field", False)                                                # 17b
                for key, most in (("name", 32), ("label", 64), ("type", 7)):
                    text(f, key, most, True, f"setting {name}: a field's")
                if not SETTING_NAME.fullmatch(f["name"]) or f["type"] not in FIELD_TYPES:
                    bad(f"setting {name}: field {str(f['name'])!r}: its name or its type (text, number, int)")
                if f["name"] in names:                                                              # 42
                    bad(f"setting {name}: field {f['name']} twice")
                names.add(str(f["name"]))
                if not all(type(f[k]) in (Whole, Frac) for k in ("min", "max", "step") if k in f):  # 43
                    bad(f"setting {name}: field {f['name']}: min, max and step are numbers")
                if float(f.get("min", 0)) > float(f.get("max", 1e9)):                               # 44
                    bad(f"setting {name}: field {f['name']}: min over max")
        if name in seen:                                                                            # 24
            bad(f"setting {name} twice")
        seen.add(str(name))

    rows = {str(s["name"]) for s in settings if s["type"] != "files"}
    kinds = {str(s["name"]): (s["type"], whole(s, "min", 0, -LONG, LONG, ""), whole(s, "max", 1000000 if s["type"] == "int" else 0, -LONG, LONG, "")) for s in settings}
    rows_by = {str(s["name"]): s for s in settings}

    def refs(v):                                                                                    # 45
        if isinstance(v, list):
            for x in v:
                refs(x)
        elif isinstance(v, str):
            if v.startswith("setting:") and v[8:] not in rows:
                bad(f"a capability names the setting {str(v[8:])[:32]!r}, and the manifest has no such row")
        elif isinstance(v, dict):
            for k, x in v.items():
                if k == "setting" and not (shown(x, 33) and x in rows):
                    bad(f"a capability names a setting (\"setting\": {str(x)[:32]!r}), and the manifest has no such row")
                refs(x)
    refs(caps)

    if "net.server" in caps:                                                                        # 22a
        v = caps["net.server"]
        if not isinstance(v, list):
            bad("\"net.server\" is a list of servers: {\"setting\", \"proto\", \"ports\"} each")
        if len(v) > NET_MOST:
            bad(f"\"net.server\": {NET_MOST} servers at most")
        if not v:
            bad("\"net.server\" names no server")
        for e in v:
            if not isinstance(e, dict):
                bad("\"net.server\": an entry is an object")
            if not versioned(e, "net.server", True):
                bad("\"net.server\": an entry has a key this version does not read (setting, proto and ports are all it has)")
            s = e.get("setting")
            if not (shown(s, 32) and kinds.get(str(s), ("",))[0] == "host"):
                bad("\"net.server\": an entry's \"setting\" names a row of type host, where the owner enters the server")
            if "default" in rows_by.get(str(s), {}):
                bad(f"\"net.server\": the row {s}, where the owner enters the server, has a default: the server is the owner's to enter, never the plugin's")
            if not (shown(e.get("proto"), 7) and e["proto"] in ("tcp", "udp")):
                bad("\"net.server\": an entry's \"proto\" is \"tcp\" or \"udp\"")
            ports = e.get("ports")
            if isinstance(ports, list):
                if not ports:
                    bad("\"net.server\": an entry names no port")
                if len(ports) > PORTS_MOST:
                    bad(f"\"net.server\": {PORTS_MOST} ports an entry at most")
                for q in ports:
                    if not (type(q) is Whole and q.raw != "-0" and 1 <= q <= 65535 and q != 5555):
                        bad("\"net.server\": a port is a whole number from 1 to 65535, not 5555")
            elif shown(ports, 40) and ports.startswith("setting:"):
                k = kinds.get(ports[8:])
                if not k or k[0] != "int" or k[1] < 1 or k[2] > 65535:
                    bad("\"net.server\": an entry's \"ports\" is a list of ports, or \"setting:<row>\" naming a row of type int from 1 to 65535 at most")
                if "default" in rows_by.get(ports[8:], {}):
                    bad(f"\"net.server\": the row {ports[8:]}, where the owner enters the port, has a default: the port is the owner's to enter")
            else:
                bad("\"net.server\": an entry's \"ports\" is a list of ports, or \"setting:<row>\"")

    def number(o, key, default):
        v = o.get(key, default)
        if key in o and type(v) not in (Whole, Frac):
            return None
        return float(v)

    if "net.discover" in caps:                                                                      # 22c
        v = caps["net.discover"]
        if not isinstance(v, dict) or not versioned(v, "net.discover", True):
            bad("\"net.discover\" is {\"udp\": <port>, \"to\": \"broadcast\" or a multicast group}, and nothing else")
        u = v.get("udp")
        if not (type(u) is Whole and u.raw != "-0" and 1 <= u <= 65535 and u != 5555):
            bad("\"net.discover\": udp is a port, 1 to 65535, not 5555")
        if u == 2330 or 28928 <= u <= 28999:
            bad("\"net.discover\": udp is none of hassmic's own ports (2330, 28928 to 28999)")
        if u in DNS_PORTS:
            bad(f"\"net.discover\": udp is not port {u}: a device on the network answers there by asking the internet (DNS)")
        to = v.get("to")
        if not shown(to, 15):
            bad("\"net.discover\": to is \"broadcast\" or a multicast group")
        g = GROUP.fullmatch(to) if to != "broadcast" else None
        if to != "broadcast" and not (g and all(int(x) < 256 for x in g.groups())):
            bad("\"net.discover\": to is \"broadcast\" or a multicast group (224.0.0.0 to 239.255.255.255)")
        if g and ".".join(str(int(x)) for x in g.groups()) != to:
            bad("\"net.discover\": the group is written a.b.c.d, without zeros in front")

    for name in ("net.lan", "net.internet"):                                                        # 22f
        if name not in caps:
            continue
        v = caps[name]
        if not isinstance(v, list):
            bad(f"\"{name}\" is a list of {{\"proto\", \"ports\"}}")
        if len(v) > NET_MOST:
            bad(f"\"{name}\": {NET_MOST} entries at most")
        for e in v:
            if not isinstance(e, dict) or not versioned(e, name, True):
                bad(f"\"{name}\": an entry is {{\"proto\": \"tcp\" or \"udp\", \"ports\": [...] or \"any\"}}, and nothing else")
            if not (shown(e.get("proto"), 7) and e["proto"] in ("tcp", "udp")):
                bad(f"\"{name}\": an entry's \"proto\" is \"tcp\" or \"udp\"")
            ports = e.get("ports")
            if isinstance(ports, list):
                if len(ports) > PORTS_MOST:
                    bad(f"\"{name}\": {PORTS_MOST} ports an entry at most")
                for q in ports:
                    if not (type(q) is Whole and q.raw != "-0" and 1 <= q <= 65535 and q != 5555):
                        bad(f"\"{name}\": a port is a whole number from 1 to 65535, not 5555")
                    if name == "net.lan" and q in DNS_PORTS:
                        bad(f"\"{name}\": not port {q}: a device on the network answers there by asking the internet (DNS), and \"{name}\" is the network's only")
                if not ports:
                    bad(f"\"{name}\": an entry names no port")
            elif not (shown(ports, 7) and ports == "any"):
                bad(f"\"{name}\": an entry's \"ports\" is a list of ports, or \"any\"")
        if not v:
            bad(f"\"{name}\" has no entry")

    if "ha.entities" in caps:                                                                       # 22d
        v = caps["ha.entities"]
        if not isinstance(v, list):
            bad("\"ha.entities\" is a list of entities")
        names, labels = set(), set()
        for i, e in enumerate(v):
            if i == ENTITIES_MOST:
                bad(f"\"ha.entities\": {ENTITIES_MOST} at most")
            if not isinstance(e, dict) or not shown(e.get("kind"), 15):
                bad("\"ha.entities\": an entity is an object with a kind")
            kind = e["kind"]
            if kind not in ENTITY_KINDS:
                bad(f"\"ha.entities\": no kind {str(kind)!r}")
            if not versioned(e, f"ha.entities.{kind}", True):
                bad(f"\"ha.entities\": a {kind} has a key this version does not read")
            name = e.get("name")
            if not (shown(name, 32) and SETTING_NAME.fullmatch(name)):
                bad("\"ha.entities\": a name is 1 to 32 of a-z, 0-9 and _")
            if not (shown(e.get("label"), 64) and e["label"]):
                bad(f"\"ha.entities\": {name}: its label is text of 1 to 64 bytes")
            if "icon" in e and not (shown(e["icon"], 64) and ICON.fullmatch(e["icon"])):
                bad(f"\"ha.entities\": {name}: an icon is \"mdi:<name>\"")
            if "unit" in e and not shown(e["unit"], 12):
                bad(f"\"ha.entities\": {name}: its unit is text of at most 12 bytes")
            whole(e, "decimals", 0, 0, 6, f"\"ha.entities\": {name}: decimals 0 to 6")
            if "page" in e:                                                                         # 22d
                if type(e["page"]) is not bool:
                    bad(f"\"ha.entities\": {name}: page is true or false")
                if e["page"] is True and kind not in PAGE_KINDS:
                    bad(f"\"ha.entities\": {name}: a {kind} has no state to show on the card (\"page\")")
            if kind == "number":
                lo, hi, step = number(e, "min", 0), number(e, "max", 100), number(e, "step", 1)
                if lo is None or hi is None or step is None or not (lo < hi) or not (step > 0) or lo < -1e9 or hi > 1e9:
                    bad(f"\"ha.entities\": {name}: min below max, a step above 0, within a billion")
            if kind in ("select", "event"):
                key, most = ("options", OPTIONS_MOST) if kind == "select" else ("types", TYPES_MOST)
                words = e.get(key)
                if not isinstance(words, list):
                    bad(f"\"ha.entities\": {name}: its {key} are a list")
                had = []
                for w in words:
                    if len(had) == most or not (shown(w, 32) and w) or (kind == "event" and not SETTING_NAME.fullmatch(w)):
                        bad(f"\"ha.entities\": {name}: " + ("options: 1 to 12 texts of 1 to 32 bytes" if kind == "select" else "types: 1 to 8 names of a-z, 0-9 and _"))
                    if w in had:
                        bad(f"\"ha.entities\": {name}: {w!r} twice")
                    had.append(str(w))
                if not had:
                    bad(f"\"ha.entities\": {name}: an empty list")
            if name in names:
                bad(f"\"ha.entities\": {name} twice")
            names.add(str(name))
            if e["label"] in labels:
                bad(f"\"ha.entities\": two are labelled {json.dumps(e['label'], ensure_ascii=False)}")
            labels.add(e["label"])
        if not v:
            bad("\"ha.entities\" names no entity")

    if "ha.actions" in caps:                                                                        # 22e
        v = caps["ha.actions"]
        if not isinstance(v, list):
            bad("\"ha.actions\" is a list of actions")
        names, labels = set(), set()
        for i, a in enumerate(v):
            if i == ACTIONS_MOST:
                bad(f"\"ha.actions\": {ACTIONS_MOST} at most")
            if not isinstance(a, dict) or not versioned(a, "ha.actions", True):
                bad("\"ha.actions\": an action is {\"name\", \"label\", \"args\", \"page\", \"calls\"} and nothing else")
            name = a.get("name")
            if not (shown(name, 32) and SETTING_NAME.fullmatch(name)):
                bad("\"ha.actions\": a name is 1 to 32 of a-z, 0-9 and _")
            if not (shown(a.get("label"), 64) and a["label"]):
                bad(f"\"ha.actions\": {name}: its label is text of 1 to 64 bytes")
            if "page" in a and type(a["page"]) is not bool:
                bad(f"\"ha.actions\": {name}: page is true or false")
            if "calls" in a and type(a["calls"]) is not bool:
                bad(f"\"ha.actions\": {name}: calls is true or false")
            if a.get("calls") is True and "call" not in caps:
                bad(f"\"ha.actions\": {name}: an action that places calls (\"calls\") needs the capability \"call\"")
            args = a.get("args", [])
            if not isinstance(args, list):
                bad(f"\"ha.actions\": {name}: its args are a list")
            arg_names = []
            for x in args:
                if len(arg_names) == ARGS_MOST:
                    bad(f"\"ha.actions\": {name}: {ARGS_MOST} arguments at most")
                if not (isinstance(x, dict) and versioned(x, "ha.actions.arg", True) and shown(x.get("name"), 32) and SETTING_NAME.fullmatch(x["name"])
                        and shown(x.get("type"), 7) and x["type"] in ("string", "int")):
                    bad(f"\"ha.actions\": {name}: an argument is {{\"name\", \"type\": \"string\" or \"int\"}}")
                if x["name"] in arg_names:
                    bad(f"\"ha.actions\": {name}: an argument twice")
                arg_names.append(str(x["name"]))
            if a.get("page") is True and arg_names:
                bad(f"\"ha.actions\": {name}: a button on the card is for an action without arguments")
            if name in names:
                bad(f"\"ha.actions\": {name} twice")
            names.add(str(name))
            if a["label"] in labels:
                bad(f"\"ha.actions\": two are labelled {json.dumps(a['label'], ensure_ascii=False)}")
            labels.add(a["label"])
        if not v:
            bad("\"ha.actions\" names no action")

    if "wake" in caps and set(caps) - {"wake", "files", "storage"}:                                 # 46
        bad("a plugin that hears the microphone all the time (\"wake\") may have only files and storage besides: this one asks for a way out")
    if "log.read.full" in caps and tier != "official":                                              # 47
        bad("the whole log (\"log.read.full\") is for official plugins only")
    if "request.audio" in caps and "net.internet" in caps and tier != "official":                     # 48
        bad("a community plugin that hears every request (\"request.audio\") may not reach the internet (\"net.internet\"): it is not listed")
    return m


def members(data, what):
    """a package's files by name.  A plain tar as plugcheck.py writes it and the Echo reads it: the five names,
    each once and within its size, one header each (no pax or GNU extras, which the Echo refuses), nothing after"""
    f, at = {}, 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as t:
            for ti in t:
                # (the size as plain octal digits: the Echo's strtoul stops at GNU's base-256 form)
                if (ti.type != tarfile.REGTYPE or ti.offset != at or ti.pax_headers or ti.name not in plugcheck.MEMBERS
                        or ti.name in f or ti.size > plugcheck.MEMBERS[ti.name] or not re.fullmatch(rb"[0-7]{1,11}[ \0]*", data[at + 124:at + 136])):
                    raise Bad(f"{what}: \"{ti.name[:40]!r}\" does not belong in a package, is there twice, is too large or is no plain file")
                f[ti.name] = t.extractfile(ti).read()
                at += 512 + (ti.size + 511) // 512 * 512
    except (tarfile.TarError, EOFError, ValueError, OSError) as e:
        raise Bad(f"{what}: no package: {e}")
    if not f or any(data[at:]):
        raise Bad(f"{what}: no package, or something follows its last file")
    return f


def package_check(e, v, data, arch="arm"):
    """the manifest of the package DATA when it is the one entry E lists as version V"""
    what = f"{e['id']} version {v['version']}"
    if len(data) > plugcheck.PACKAGE_MAX:
        raise Bad(f"{what}: larger than {plugcheck.PACKAGE_MAX >> 20} MB")
    f = members(data, what)
    for need in ("manifest.json", "manifest.sig", "plugin", "LICENSE"):
        if need not in f:
            raise Bad(f"{what}: no {need} in the package")
    if hashlib.blake2b(f["manifest.json"], digest_size=32).hexdigest() != v["manifest"]:
        raise Bad(f"{what}: its manifest is not the one the entry names")
    if f["manifest.json"][:1] != b"{":                      # UTF-8, as the Echo reads it: json.loads would take UTF-16 and a BOM too
        raise Bad(f"{what}: its manifest is no JSON object in UTF-8")
    m = parse_json(f["manifest.json"], f"{what}: its manifest")
    if not isinstance(m, dict) or type(m.get("version")) is not int or m.get("id") != e["id"] or m["version"] != v["version"] or m.get("author_key") != e["author_key"]:
        raise Bad(f"{what}: the manifest's id, version or author key is not the entry's")
    manifest_check(f["manifest.json"], what, e["tier"])      # what no Echo installs is not listed
    # a community version: what the package asks for is what the entry declares (the maintainer read those), value for
    # value and of the same kinds (1 is not true), and its source is the entry's (its CI built it there, the
    # attestation says; the Echo's card shows the manifest's)
    if "capabilities" in v and json.dumps(m.get("capabilities"), sort_keys=True) != json.dumps(v["capabilities"], sort_keys=True):
        raise Bad(f"{what}: the built manifest asks for other capabilities than the entry declares: "
                  f"{json.dumps(m.get('capabilities'), sort_keys=True)[:300]} against {json.dumps(v['capabilities'], sort_keys=True)[:300]}")
    if e["tier"] == "community" and "source" in e and m.get("source") != e["source"]:
        raise Bad(f"{what}: the manifest's source ({str(m.get('source'))[:200]}) is not the entry's ({e['source']})")
    # a community version's LICENSE and signature are the ones the entry names: with them every byte of the package is
    # the entry's word (the manifest by its digest, the program by the manifest's digest)
    if "license_sha256" in v and hashlib.sha256(f["LICENSE"]).hexdigest() != v["license_sha256"]:
        raise Bad(f"{what}: its LICENSE is not the one the entry names (SHA-256 {hashlib.sha256(f['LICENSE']).hexdigest()}, the entry {v['license_sha256']})")
    if "signature" in v and f["manifest.sig"].hex() != v["signature"]:
        raise Bad(f"{what}: its manifest.sig is not the signature the entry names")
    # what the index repeats of the manifest under its own signature: of the kinds the manifest has them
    if (not text_bytes(m.get("name"), BOUNDS["NAME_MAX"]) or not text_bytes(m.get("author"), BOUNDS["AUTHOR_MAX"])
            or not isinstance(m.get("requires"), dict) or not all(isinstance(k, str) and SCOPE.fullmatch(k) and type(x) in (Whole, int) for k, x in m["requires"].items())
            or not isinstance(m.get("capabilities"), dict) or not all(isinstance(k, str) and CAP.fullmatch(k) for k in m["capabilities"]) or not plain(m["capabilities"])
            or not isinstance(m.get("models", ["*"]), list) or not all(text_ok(x, 32) for x in m.get("models", ["*"])) or len(m.get("models", ["*"])) > 32
            or not text_bytes(m.get("version_name", str(v["version"])), BOUNDS["VERSION_NAME_MAX"])):
        raise Bad(f"{what}: the manifest's name, author, requires, capabilities, models or version_name")
    # what an Echo shows of the plugin is the manifest's (the install's dialog, its card) and the entry's (the browse
    # page's row, index.json): the same words, exactly, so the entry's, which the maintainer read, are what the plugin
    # says it is.  A community package called itself "microWakeWord" by "hassmic" under an entry that said otherwise
    # (a review of 9b02fdb, 4).  A manifest without a description has none to match: an entry has one
    for k in ("name", "author", "description"):
        if m.get(k) != e[k]:
            raise Bad(f"{what}: the manifest's {k} ({str(m.get(k))[:120]!r}) is not the entry's ({e[k][:120]!r}): what an Echo shows is the "
                      "manifest's, and the entry says what that is")
    if not otatool.check(f["manifest.sig"], bytes.fromhex(e["author_key"]), plugcheck.SIGN_MANIFEST + f["manifest.json"]):
        raise Bad(f"{what}: the manifest is not signed by the entry's author key")
    if hashlib.blake2b(f["plugin"], digest_size=32).hexdigest() != m.get("digest"):
        raise Bad(f"{what}: the program is not the one its manifest names")
    wrong = plugcheck.elf_check(f["plugin"], arch)
    if wrong:
        raise Bad(f"{what}: the program: {wrong}")
    # the author's package as the plugin's repository published it: the listing is this index's to add, and one in
    # it already is somebody else's word (a package from before the index listed, or one made to look listed)
    if "listing.sig" in f:
        raise Bad(f"{what}: the package carries a listing already: the index adds it, nobody else")
    # packed as plugcheck.py packs it (its members in that order, no machine's names or times in the headers): then the
    # listed package without its listing is the release's bytes again, whose SHA-256 the attestation names, so that
    # anyone, and the next build from the published site, can verify it again (fetch takes it from there so)
    if plugcheck.tar_bytes([(n, f[n]) for n in ("manifest.json", "manifest.sig", "plugin", "LICENSE")]) != data:
        raise Bad(f"{what}: not packed as plugcheck.py pack packs a package (the members in its order, its plain headers): "
                  "the listed package would not give back the bytes the attestation names")
    return m, f


def released(f):
    """the package as its repository released it, from the members of the listed one (the listing taken off)"""
    return plugcheck.tar_bytes([(n, f[n]) for n in ("manifest.json", "manifest.sig", "plugin", "LICENSE") if n in f])


def spit(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def dump(obj):
    return json.dumps(obj, indent=1, ensure_ascii=False).encode() + b"\n"


def built_from_bytes(commit, index):
    """built-from.txt: the commit a site was built from, and the index.json it made (by its SHA-256)"""
    return f"commit {commit}\nindex.json {hashlib.sha256(index).hexdigest()}\n".encode()


def built_from(site, pk):
    """the commit SITE's index was built from, by its built-from.txt: None where it has none (a site of the tool
    before it, or built without --commit); Bad where one is there and the index key did not sign it, or it names
    another index.json than the one beside it.  PK: the key, or a list of keys (index_keys: during a change of the
    key, the published site is the previous one's)"""
    try:
        with open(os.path.join(site, "built-from.txt"), "rb") as f:
            data = f.read(4096)
    except FileNotFoundError:
        return None
    except OSError as x:
        raise Bad(f"{site}/built-from.txt: {x}")
    try:
        with open(os.path.join(site, "built-from.txt.sig"), "rb") as f:
            sig = f.read(4096)
        with open(os.path.join(site, "index.json"), "rb") as f:
            index = f.read()
    except OSError as x:
        raise Bad(f"{site}: {x}")
    if not any(otatool.check(sig, k, SIGN_BUILT + data) for k in (pk if isinstance(pk, list) else [pk])):
        raise Bad(f"{site}/built-from.txt: not signed by the index key")
    m = re.fullmatch(rb"commit ([0-9a-f]{40}|[0-9a-f]{64})\nindex\.json ([0-9a-f]{64})\n", data)
    if not m or m.group(2).decode() != hashlib.sha256(index).hexdigest():
        raise Bad(f"{site}/built-from.txt: not the record of the index.json beside it")
    return m.group(1).decode()


def descends(root, old, new):
    """whether commit NEW of the repository ROOT descends from OLD (git merge-base --is-ancestor; OLD the commit a
    published site's signed built-from.txt names): True, False, or why it cannot be said (a commit that is not in
    this clone: a shallow checkout; no git)"""
    import subprocess
    try:
        r = subprocess.run(["git", "-C", root, "merge-base", "--is-ancestor", old, new], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as x:
        return f"git: {x}"
    if r.returncode in (0, 1):
        return r.returncode == 0
    return "git merge-base: " + (r.stderr.strip().splitlines() or [f"status {r.returncode}"])[-1][:200]


# The attestations verified at once (gh runs, each its own process; a bundle's verification asks Sigstore's trust root
# and nothing of GitHub's API, an API's own reads are bounded by attest.SECONDS and workflow.SECONDS).  index.yml's
# publish job has its timeout from this: about (versions / ATTEST_WORKERS) x a gh run's time, which was seconds a
# bundle, plus the rest of the build
ATTEST_WORKERS = 6


class KeptRefused(attest.Unavailable):
    """the published site's own bundle of a version it lists, refused now (attested); or, for a version the site
    lists whose attestation was asked of GitHub's API (no bundle of the site's for it), its references refused now
    (tools/workflow.py: an action's repository gone or made private since is a 404, a verdict of that check's own,
    which answers otherwise one day; a review of 810b9e9)"""


def attested(e, v, data, pkgdir, name, listed, as_listed=False):
    """the bundle (one JSON line) of an attestation that holds for the package DATA of version V of E: its own
    repository's GitHub Actions built it at the entry's commit, in the entry's workflow, for the push of the tag its
    release asset is under (tools/attest.py).  The file gh is asked about is
    written from DATA itself, the bytes that are listed; the site's bundles (PKGDIR/NAME.sigstore.jsonl, where fetch
    took the version from the published site) are verified again instead of asking GitHub's API.  attest.Refused (a
    verdict), attest.Unavailable (none).
    LISTED: the published site lists the version.  Its own bundle, which held when it was listed, refused now of the
    very bytes it held for (fetch took both from the site: its size and SHA-256 as index.json names them) is no
    verdict on the plugin: what changed is gh, Sigstore's trust root or this reading, and none of that takes a version
    off the index unasked (Unavailable: the build fails, nothing is published).  Taking it off is a person's step: the
    revocation list, or the entry without that version.
    Where the attestation is asked of GitHub's API (no bundle of the site's: a version not listed yet, or listed with
    another commit, workflow or release than the entry names now), every action the entry's workflow uses at that
    commit, and every action and workflow those use in turn, has to be pinned by a commit of the action's own
    repository (tools/workflow.py: an impostor commit of a fork runs under the original's name), and that is asked
    right after: its Refused a verdict for a version not listed yet, its Unavailable none, as the attestation's; for a
    version the site lists its Refused is none either (KeptRefused: an action's repository gone since answers 404,
    and no check that answers otherwise one day takes a listed version off).  With the site's bundle it is not asked
    again: the site lists no version whose references did not hold when it was listed, and neither the commit's
    files nor what they pin change since (fetch takes the bundle only where the entry names the commit and the
    workflow the site listed the version with), so GitHub's API out of reach holds back no listed version, nor the
    revocation list.  AS_LISTED: the site lists it with the commit and the workflow the entry names.  A bundle beside
    a version the site does not list so (make site PACKAGES=<dir>: a person's own packages and bundles, fetch's
    rule not asked) is no such bundle: there the check is asked all the same (a review of 5a3035d)"""
    import tempfile
    bundle = os.path.join(pkgdir, name + attest.SUFFIX)
    kept = os.path.isfile(bundle)
    with tempfile.TemporaryDirectory(prefix="attest-") as t:
        path = os.path.join(t, name)
        spit(path, data)
        try:
            got = attest.verify(path, e["source"], v["commit"], hashlib.sha256(data).hexdigest(), v["workflow"], release_tag(e, v),
                                bundle if kept else None)
        except attest.Refused as x:
            if listed and kept:
                raise KeptRefused(f"the site's own bundle, which held when the version was listed, refused now ({x}): "
                                         "gh, Sigstore or this check changed, not the release. To take the version off, withdraw it "
                                         "(revoked.json) or take it out of the entry")
            raise
    if not (kept and as_listed):
        try:
            workflow.check(e["source"], v["commit"], v["workflow"])
        except attest.Refused as x:
            if listed:
                # (a version the site lists, taken off by a check that may answer otherwise one day: no verdict, as
                # the site's own bundle refused again is none; the build fails, and a person takes it off, or not)
                raise KeptRefused(f"listed, and its workflow at {v['commit'][:12]} now refused by the index's check of what it runs ({x}): "
                                  "no verdict on a version the site lists. To take the version off, withdraw it (revoked.json) or "
                                  "take it out of the entry")
            raise attest.Refused(f"its workflow at {v['commit'][:12]} runs what its commit does not fix: {x}")
        except attest.Unavailable as x:
            raise attest.Unavailable(f"its workflow's references could not be checked now: {x}")
    return got


def build(root, pkgdir, site, serial, key, previous=None, arch="arm", bump=False, commit=None, strict=False):
    entries, revoked, was = load(root, previous)
    if commit is not None and not COMMIT.fullmatch(commit):
        raise Bad(f"--commit {commit[:80]!r}: a commit's id (40 or 64 hex digits)")
    # the commit's time: one from a clock set ahead would be the serial every later index has to beat
    if not 0 < serial <= time.time() + 86400:
        raise Bad(f"serial {serial}: not a time up to now")
    if os.path.exists(site) and os.listdir(site):
        raise Bad(f"{site}: not empty (the site is written whole, into a new folder)")
    try:
        with open(key, "rb") as f:
            sk = f.read()
    except OSError as x:
        raise Bad(str(x))
    pk = index_keys(root)[0]
    if len(sk) != 64:
        raise Bad(f"{key}: not a signing key (otatool.py keygen makes one)")
    if arch not in plugcheck.ARCH:
        raise Bad(f"--arch {arch}: one of {', '.join(plugcheck.ARCH)}")

    strict_errors = []

    def left_out(why):
        # (a pull request's check, --strict: an error, each named and the check failing once after all were asked.
        # A publish: said, and the rest is listed and the revocation list published all the same: one plugin's
        # release, or GitHub's attestations, out of reach blocks nothing)
        if strict:
            strict_errors.append(why)
            print(f"error: {why}", flush=True)
        else:
            print(f"warning: {why}: left out of index.json", flush=True)

    # Every version checked once (assemble runs twice with --bump): its package as the entry names it, then its
    # attestation.  Nothing of a package is run, here or anywhere in the build
    checked, unverdicted = {}, []
    listed = {(p["id"], x["version"]): (x.get("commit"), x.get("workflow")) for p in (was or {}).get("plugins", [])
              if isinstance(p, dict) and isinstance(p.get("versions"), list) for x in p["versions"] if isinstance(x, dict)}
    # The versions whose bundle the published site keeps first, then the listed ones asked of GitHub's API (the entry
    # names another commit, workflow or release, or the site's copy was not usable), then the new ones: a gh call of
    # the API that took its whole time makes every later one no verdict at once (attest.not_stalled), and a listed
    # version's verification with its bundle asks no API (a stall of its own kind), so no stall of a new version's
    # holds back a listed one, nor the revocation list (a review of 810b9e9; a review of 5a3035d: a listed version
    # asked of the API sat among the new ones, in the entries' order, and a new one's stall before it failed the build)
    order = [(e, v) for e in entries for v in e["versions"]]
    group = lambda ev: (not os.path.isfile(os.path.join(pkgdir, f"{ev[0]['id']}-{ev[1]['version']}.hmp" + attest.SUFFIX)),
                        (ev[0]["id"], ev[1]["version"]) not in listed)
    order.sort(key=group)
    # Each package read and held to its entry first, in that order (no gh, no network: an error of its own ends the
    # build at once, as before); then the attestations, ATTEST_WORKERS at a time within each group of the order above
    # and the groups one after the other, so that no version of a later group is asked before every one of an earlier
    # group was (a stall of a new version's never holds back a listed one).  One by one, every version of the index
    # was asked again at every publish, a gh run each (bundles: Sigstore's trust root and the check, seconds; API:
    # more), and the publish job's time was a bound on how many versions the index could list (a review of 9b02fdb, 8).
    # In parallel the job's time grows with the versions over ATTEST_WORKERS (index.yml's timeout says how far)
    ready = []
    for e, v in order:
        name = f"{e['id']}-{v['version']}.hmp"
        if withdrawn(revoked, e["id"], v["version"], e["author_key"]) is not None:
            continue
        try:
            with open(os.path.join(pkgdir, name), "rb") as f:
                data = f.read(plugcheck.PACKAGE_MAX + 1)
        except OSError as x:
            # (fetch could not have it: its release is gone, or the site is out of reach)
            left_out(f"{e['id']} version {v['version']}: no package ({x.strerror or x})")
            continue
        try:
            m, f = package_check(e, v, data, arch)
        except Bad as x:
            # (an error of its own, the build ends here; what was found before it is not lost with it)
            raise Bad(str(x) + "".join("\n  and before it: " + w for w in unverdicted + strict_errors))
        ready.append((e, v, name, data, m, f))

    def verify_one(item):
        e, v, name, data, _, _ = item
        try:
            return attested(e, v, data, pkgdir, name, (e["id"], v["version"]) in listed,
                            listed.get((e["id"], v["version"])) == (v["commit"], v["workflow"])), None
        except (attest.Refused, attest.Unavailable) as x:
            return None, x

    def answers():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, ATTEST_WORKERS)) as pool:
            for g in sorted({group(x[:2]) for x in ready}):
                # (map: each answer in the order asked, handed on as soon as it and those before it are in, so that a
                # job ended at its time limit still names what was found; the next group only after this one's last)
                items = [x for x in ready if group(x[:2]) == g]
                yield from zip(items, pool.map(verify_one, items))
    for (e, v, name, data, m, f), (bundles, failed) in answers():
        try:
            if failed is not None:
                raise failed
        except attest.Refused as x:
            # (a verdict: a new version, or one the site lists that the entry now names with another commit,
            # workflow or release, asked of GitHub's API; the site's own bundle refused again is none, attested, and
            # so is a listed version's workflow refused by tools/workflow.py: KeptRefused both)
            left_out(f"{e['id']} version {v['version']}: not attested as its repository's CI's build: {x}"
                     + (" (the published site lists it: left out from now on)" if (e["id"], v["version"]) in listed else ""))
            continue
        except attest.Unavailable as x:
            # no verdict (gh, the network, Sigstore, GitHub's API): never a reason to take a version off the
            # index, so a version the published site lists fails the build (nothing is published; run it again);
            # the site's own bundle refused again (KeptRefused) the same, until a person withdraws the version or
            # the check is mended; a new one is left out of a publish (a later one lists it: one release's
            # attestations out of reach hold back neither the rest nor the revocation list) and fails a pull
            # request's check (--strict)
            # (each such version is named, and the build fails once after all were asked: a new gh or Sigstore
            # trust root can refuse every kept bundle at once, and one round of a person's per version, with no
            # revocation list published meanwhile, is too slow a way to learn which; a review of 17c2e8c)
            # (each said as it is found: a job that ends at its time limit, gh too slow, still names those found
            # before; attest.not_stalled makes every one of its kind after a gh that took its whole time no verdict at
            # once, and named; a review of dc75e14; the listed versions, with their bundles, are asked first)
            print(f"no verdict: {e['id']} version {v['version']}: {x}", flush=True)
            if (e["id"], v["version"]) in listed:
                unverdicted.append(f"{e['id']} version {v['version']}: {x}"
                                   + ("" if isinstance(x, KeptRefused) else " (run it again once gh can answer)"))
                continue
            left_out(f"{e['id']} version {v['version']}: its attestation could not be verified now (no verdict, not listed yet: "
                     f"a later publish lists it): {x}")
            continue
        checked[(e["id"], v["version"])] = (m, f, data, bundles)
    if unverdicted or strict_errors:
        raise Bad("\n".join(([f"{len(unverdicted)} version{'s' if len(unverdicted) > 1 else ''} which the published site lists: the attestation "
                               "could not be verified, and that is no verdict. Nothing is built:\n  " + "\n  ".join(unverdicted)] if unverdicted else [])
                             + ([f"{len(strict_errors)} version{'s' if len(strict_errors) > 1 else ''} left out (--strict: each an error):\n  "
                                 + "\n  ".join(strict_errors)] if strict_errors else [])))

    def assemble(serial, say):
        """index.json, the packages listed (with their bundles), the page and the plugins, for SERIAL"""
        plugins, packages, shown_extra = [], [], {}
        for e in entries:
            versions = []
            for v in e["versions"]:
                name = f"{e['id']}-{v['version']}.hmp"
                gone = withdrawn(revoked, e["id"], v["version"], e["author_key"])
                if gone is not None:
                    say(f"note: {e['id']} version {v['version']} is withdrawn ({gone}): left out of index.json")
                    continue
                if (e["id"], v["version"]) not in checked:
                    continue
                m, f, released_data, bundles = checked[(e["id"], v["version"])]
                f = dict(f)
                # the index's listing, in the package (5.3): what an Echo takes as this key's word that the plugin is
                # listed, and in which tier.  Over the index's serial too, the time of this build
                f["listing.sig"] = plugcheck.listing(m, f["manifest.json"], key, e["tier"], serial)
                data = plugcheck.tar_bytes([(n, f[n]) for n in ("manifest.json", "manifest.sig", "plugin", "LICENSE", "listing.sig") if n in f])
                if len(data) > plugcheck.PACKAGE_MAX:
                    raise Bad(f"{e['id']} version {v['version']}: larger than {plugcheck.PACKAGE_MAX >> 20} MB with its listing")
                packages.append((name, data))
                packages.append((name + attest.SUFFIX, bundles))
                versions.append({"version": v["version"], "version_name": m.get("version_name", str(v["version"])), "requires": m["requires"],
                                 "models": m.get("models", ["*"]), "capabilities": m["capabilities"],
                                 # (a community version's own: the broad capabilities it asks for)
                                 **({"broad": broad(m["capabilities"])} if e["tier"] == "community" else {}), "commit": v["commit"], "workflow": v["workflow"],
                                 "manifest": v["manifest"], "package": "packages/" + name, "size": len(data),
                                 "sha256": hashlib.sha256(data).hexdigest(),
                                 # (where it came from, for anyone to verify again: the release asset as its CI made
                                 # it, by its SHA-256, which the attestations' bundles beside the package name)
                                 "release": v["package"], "release_sha256": hashlib.sha256(released_data).hexdigest(),
                                 "attestation": "packages/" + name + attest.SUFFIX, "attestation_sha256": hashlib.sha256(bundles).hexdigest()})
                # for the page only (index.json does not carry them): what the Echo's dialog fills into its lines
                shown_extra[(e["id"], v["version"])] = {"license": m.get("license"), "memory_mb": m.get("memory_mb"),
                                                       "file_labels": [s.get("label") for s in m.get("settings", []) if s.get("type") == "files"]}
            # a plugin all of whose versions are withdrawn is not offered at all; one with none released yet is
            if versions or not e["versions"] or any(withdrawn(revoked, e["id"], v["version"], e["author_key"]) is None for v in e["versions"]):
                plugins.append({**{k: e[k] for k in ("id", "name", "description", "author", "author_key", "tier", "source")}, "versions": versions})
        # The revocation list it was made with: an Echo takes this index only beside one at least that new (hassmic's
        # plugin_fetch.c), so that a site whose files are of two times (a new index, an old revocation list) offers
        # nothing the newer list withdrew; and the index itself leaves out what this list withdraws
        index = dump({"index": 1, "serial": serial, "revoked_serial": revoked["serial"], "plugins": plugins})
        if len(index) > BOUNDS["INDEX_MAX"]:
            raise Bad(f"index.json would be {len(index) >> 10} kB, over the {BOUNDS['INDEX_MAX'] >> 10} kB an Echo reads: take old versions out")
        for_page = json.loads(index)
        for p in for_page["plugins"]:
            for v in p["versions"]:
                v["_page"] = shown_extra[(p["id"], v["version"])]
        html_page = page.page(for_page, {"entries": revoked["entries"]}).encode()
        return index, packages, html_page, plugins

    made = built_from(previous, index_keys(root)) if bump and was else None
    after = None if commit is None or made is None or made == commit else descends(root, made, commit)
    if bump and was and serial <= was["serial"] and (commit is None or (made != commit and after is not True)):
        # (only over a site of this very commit, or of one this commit descends from: an older commit's tree built
        # after a newer one's was published, a run of an older commit that publishes late, would otherwise put back
        # what the newer one took out under a higher serial.  Refused below as without --bump)
        print(f"note: no --bump: the published index was built from {'commit ' + made if made else 'no commit it names'}, "
              f"neither this one ({commit or 'none given'}) nor one it descends from"
              + (f" ({after})" if isinstance(after, str) else ""))
    elif bump and was and serial <= was["serial"]:
        # (a second site of one commit: the published serial where nothing is new, else one more, so that the serial
        # still only grows.  A publish of the same commit run again (a version left out the first time, its release or
        # GitHub's attestations out of reach then).
        # Or a later commit whose time is not above the published serial (a committer's clock behind, or within a
        # second of a serial bumped as above): the site it builds on is its own history's, so what that took out
        # stays out, and a revocation in it goes out now rather than at the next commit)
        same = assemble(was["serial"], lambda *a: None)[0] == dump(was)
        serial = was["serial"] if same else was["serial"] + 1
        print(f"serial {serial}: " + ("the published one: nothing is new" if same else "one more than the published one"))
        if not serial <= time.time() + 86400:
            raise Bad(f"serial {serial}: more than a day ahead of now")
    index, packages, html_page, plugins = assemble(serial, print)
    if was and (serial < was["serial"] or (serial == was["serial"] and index != dump(was))):
        raise Bad(f"serial {serial}: the published index has {was['serial']}: another index needs a higher one, and none goes back")
    for name, data in packages:                             # nothing is written before everything was checked
        spit(os.path.join(site, "packages", name), data)
    spit(os.path.join(site, "index.json"), index)
    spit(os.path.join(site, "revoked.json"), revoked_bytes(revoked))
    spit(os.path.join(site, "index.html"), html_page)            # for people: tools/page.py, from the same data
    if commit:
        spit(os.path.join(site, "built-from.txt"), built_from_bytes(commit, index))
    print(f"{site}: serial {serial}, {len(plugins)} plugins, {sum(n.endswith('.hmp') for n, _ in packages)} packages; "
          f"revocations: serial {revoked['serial']}, {len(revoked['entries'])} entries")
    if sk[32:] != pk:
        print(f"note: listed with a key that is not keys/index.pub's ({key}): a site to check, not one to publish (sign refuses it, Echos too)")


def broad(capabilities):
    """the broad capabilities of a manifest (BROAD), in the Echo's order: net.lan only with an entry of any port (5.3;
    its form: {"proto", "ports": [...] or "any"})"""
    def lan_any(v): return not isinstance(v, list) or any(not isinstance(e, dict) or e.get("ports") == "any" for e in v)
    return [c for c in CAPS if c in capabilities and c in BROAD and (c != "net.lan" or lan_any(capabilities[c]))]


def fetch(root, pkgdir, previous=None):
    """each entered version's package into PKGDIR, as its author's CI released it (no listing).  From the published
    site PREVIOUS where that has the version under the manifest and the release the entry names (the site verified as
    a whole by published(): the index key's signatures, each package's size, SHA-256, listing and bundles), the
    listing taken off again, so that build lists it under the new serial, and the site's bundles of its attestations
    beside it (PKGDIR/<name>.sigstore.jsonl: build verifies them again, without GitHub's API); else from the plugin's
    own release, official and community alike.  Not had either way: warned of, not written, and build leaves it out.
    Withdrawn versions: not fetched.  The count of those not had"""
    entries, revoked, was = load(root, previous)
    os.makedirs(pkgdir, exist_ok=True)
    have = {}
    for p in (was or {}).get("plugins", []):
        for v in p.get("versions", []) if isinstance(p.get("versions"), list) else []:
            if isinstance(v, dict) and isinstance(p.get("id"), str) and type(v.get("version")) is int:
                have[(p["id"], v["version"])] = v
    missing = 0
    for e in entries:
        for v in e["versions"]:
            name = f"{e['id']}-{v['version']}.hmp"
            if withdrawn(revoked, e["id"], v["version"], e["author_key"]) is not None:
                continue
            old = have.get((e["id"], v["version"]))
            # (the site's bundle is of the attestation the site took: for the commit, the workflow and the release
            # (its tag) the entry names now, or it is asked of GitHub's API again: a corrected commit or workflow
            # never rides on the site's old bundle)
            same = old and old.get("manifest") == v["manifest"] and old.get("package") == "packages/" + name and old.get("release") == v["package"]
            if same and (old.get("commit") != v["commit"] or old.get("workflow") != v["workflow"]):
                print(f"{name}: the entry names another commit or workflow than the published site's listing: fetched from its release again, "
                      "its attestation asked of GitHub's API")
                same = False
            if same:
                try:
                    with open(os.path.join(previous, "packages", name), "rb") as f:
                        data = f.read(plugcheck.PACKAGE_MAX + 1)
                    with open(os.path.join(previous, "packages", name + attest.SUFFIX), "rb") as f:
                        bundles = f.read(attest.BUNDLE_MAX + 1)
                    if len(data) == old.get("size") and hashlib.sha256(data).hexdigest() == old.get("sha256") and len(bundles) <= attest.BUNDLE_MAX:
                        spit(os.path.join(pkgdir, name), released(members(data, name)))
                        spit(os.path.join(pkgdir, name + attest.SUFFIX), bundles)
                        print(f"{name}: as published")
                        continue
                except (OSError, Bad) as x:
                    print(f"warning: {name}: the published one is not usable ({x}): fetched again")
            try:                                            # https only (entry_check), and no more than a package may have
                with urllib.request.urlopen(v["package"], timeout=60) as r:
                    data = r.read(plugcheck.PACKAGE_MAX + 1)
                spit(os.path.join(pkgdir, name), data)
                print(f"{name}: {len(data)} bytes")
            except Exception as x:                          # urllib's, http.client's and the socket's own: all one answer
                print(f"warning: {e['id']} version {v['version']}: {v['package']}: {x!r}: not had, left out of the index")
                missing += 1
    return missing


def smoke(root, pkgdir, previous=None, qemu=None, seconds=3):
    """each community version's package in PKGDIR (fetch's) that the published site PREVIOUS does not have as entered,
    its program run in the harness (tools/harness.py, in tools/sandbox.py's sandbox, every system call judged by the
    sandbox's own table): a smoke test of a stranger's program before it is listed, in a pull request's job without
    secrets.  Nothing is built.  Where there is anything to run and no sandbox can be had (sandbox.sandbox_works):
    Bad.  -> the count of those that did not pass (a version without its package is fetch's warning, not counted)"""
    import tempfile
    entries, revoked, was = load(root, previous)
    have = {(p.get("id"), x.get("version")): x for p in (was or {}).get("plugins", []) if isinstance(p.get("versions"), list)
            for x in p["versions"] if isinstance(x, dict)}
    todo = []
    for e in entries:
        for v in e["versions"] if e["tier"] == "community" else []:
            name = f"{e['id']}-{v['version']}.hmp"
            old = have.get((e["id"], v["version"]))
            if withdrawn(revoked, e["id"], v["version"], e["author_key"]) is not None:
                continue
            if old and old.get("manifest") == v["manifest"] and old.get("package") == "packages/" + name:
                print(f"{name}: published already")
                continue
            if not os.path.isfile(os.path.join(pkgdir, name)):
                print(f"warning: {name}: no package (fetch's warning above): not run")
                continue
            todo.append((e, v, name))
    if not todo:
        print("smoke: nothing to run")
        return 0
    qemu, bwrap = harness.find_qemu(qemu), sandbox.find_bwrap()
    if not qemu or not bwrap:
        raise Bad("smoke: " + " and ".join(w for w, have_ in (("no qemu-arm (qemu-user; --qemu, INDEX_QEMU)", qemu),
                                                                ("no bwrap (bubblewrap; INDEX_BWRAP): a stranger's program runs only in its sandbox", bwrap)) if not have_))
    work = tempfile.mkdtemp(prefix="smoke-", dir=os.path.join(root, "build") if os.path.isdir(os.path.join(root, "build")) else None)
    try:
        why = sandbox.sandbox_works(bwrap, work)
        if why:
            raise Bad(f"smoke: no program can be run here: {why}")
        failed = 0
        for e, v, name in todo:
            what = f"{e['id']} version {v['version']}"
            try:
                with open(os.path.join(pkgdir, name), "rb") as f:
                    data = f.read(plugcheck.PACKAGE_MAX + 1)
                m, f = package_check(e, v, data)                # (the rules first: an ARM program, the entry's)
                run = os.path.join(work, name[:-4])
                os.makedirs(run)
                program = os.path.join(run, "plugin")
                spit(program, f["plugin"])
                os.chmod(program, 0o755)
                # (its /tmp in the run's folder where bubblewrap cannot bound a tmpfs)
                rep = harness.run(program, m, qemu, seconds, prefix=sandbox.sandbox(bwrap, [run], [qemu], scratch=os.path.join(run, "scratch")), work=run)
            except Bad as x:
                print(f"error: {x}")
                failed += 1
                continue
            except Exception as x:                      # (whatever a stranger's program finds: that version's)
                print(f"error: {what}: not run, in a way this tool does not know: {x!r}"[:2000])
                failed += 1
                continue
            if not rep.ok:
                print(f"error: {what}: in the harness: {rep}")
                failed += 1
                continue
            print(f"{name}: the harness passed (a smoke test: the Echo's seccomp filter is the boundary)")
            print("  " + str(rep).replace("\n", "\n  "))
            flags = broad(m["capabilities"])
            if flags:
                print(f"  flag: broad capabilities: {', '.join(flags)}")
        return failed
    finally:
        shutil.rmtree(work, ignore_errors=True)


def entry_fields(package):
    """what a community entry's version takes from the package its author's CI released (built from the commit it
    names): the manifest's digest, the signature, the LICENSE's SHA-256, the capabilities; the commit and the
    release asset's address are the author's to fill in"""
    with open(package, "rb") as f:
        data = f.read(plugcheck.PACKAGE_MAX + 1)
    f = members(data, package)
    if "manifest.json" not in f or "manifest.sig" not in f:
        raise Bad(f"{package}: no manifest or no signature in it")
    m = parse_json(f["manifest.json"], package)
    if "LICENSE" not in f:
        raise Bad(f"{package}: no LICENSE in it")
    return {"version": m.get("version"), "commit": "<the commit its release was built from: 40 hex digits>",
            "workflow": "<the workflow that built and attested it: .github/workflows/release.yml in hassmic's template>",
            "manifest": hashlib.blake2b(f["manifest.json"], digest_size=32).hexdigest(),
            "package": f"{m.get('source', '<source>')}/releases/download/<tag>/{m.get('id')}-{m.get('version')}.hmp",
            "signature": f["manifest.sig"].hex(), "license_sha256": hashlib.sha256(f["LICENSE"]).hexdigest(),
            "capabilities": m.get("capabilities")}


def sign(root, site, secret):
    try:
        with open(secret, "rb") as f:
            sk = f.read()
        with open(os.path.join(root, "keys", "index.pub"), "rb") as f:
            pk = f.read()
        files = [(name, purpose, open(os.path.join(site, name), "rb").read()) for name, purpose in (("index.json", SIGN_INDEX), ("revoked.json", SIGN_REVOKED))
                 + ((("built-from.txt", SIGN_BUILT),) if os.path.exists(os.path.join(site, "built-from.txt")) else ())]
    except OSError as x:
        raise Bad(str(x))
    if len(sk) != 64 or sk[32:] != pk:
        raise Bad(f"{secret} is not the key of keys/index.pub: Echos would refuse what it signs")
    for name, purpose, data in files:
        spit(os.path.join(site, name + ".sig"), otatool.sign(sk, purpose + data))
    print(f"{site}: signed")


# The time from which this tool names the revocation list in index.json (revoked_serial; a3cbbc5's commit, whose time
# every index it made since has as its serial or later).  A published site without it, as --previous, is one of the
# tool before only with an index serial under this: the one exception is the first publish after the change; any
# later site lacking it is none this tool made (a review, 2026-11-21: the exception held for every publish, and a
# published branch put back to an old form had its two files taken as of one time whatever their times).  An old
# site of before is still taken with whatever revocation list beside it: before, nothing tied the two
OLD_FORM_BEFORE = 1795217133


def verify(site, pub, say=True, older=False):
    """OLDER: the published site the next build goes by (--previous), which the tool from before revoked_serial may
    have made (an index serial under OLD_FORM_BEFORE): its index then names no revocation list, and is taken
    without; one that names another than the list beside it, or names none and is newer, is refused.  PUB: the
    key's file, or a list of keys (index_keys); the site is one key's, the one that signed index.json: the revocation
    list, built-from.txt and every listing are held to that key"""
    try:
        if isinstance(pub, list):
            pks = pub
        else:
            with open(pub, "rb") as f:
                pks = [f.read()]
        pk = None
        for name, purpose in (("index.json", SIGN_INDEX), ("revoked.json", SIGN_REVOKED)):
            with open(os.path.join(site, name), "rb") as f, open(os.path.join(site, name + ".sig"), "rb") as g:
                text, sig = purpose + f.read(), g.read()
                if pk is None:
                    pk = next((k for k in pks if otatool.check(sig, k, text)), None)
                if pk is None or not otatool.check(sig, pk, text):
                    raise Bad(f"{site}/{name}: not signed by the index key")
    except OSError as x:
        raise Bad(f"{site}: {x}")
    built_from(site, pk)                                    # (where there is one: signed, and this index's)
    n = 0
    ix = load_json(os.path.join(site, "index.json"))
    rv = load_json(os.path.join(site, "revoked.json"))
    # one site, one time: the index names the revocation list it was made with, and that is the one beside it (an
    # Echo takes an index only beside a list at least that new)
    before = older and isinstance(ix, dict) and "revoked_serial" not in ix and type(ix.get("serial")) is int and ix["serial"] < OLD_FORM_BEFORE
    if not isinstance(ix, dict) or not isinstance(rv, dict) or (ix.get("revoked_serial") != rv.get("serial") and not before):
        raise Bad(f"{site}/index.json: made with another revocation list (serial {ix.get('revoked_serial') if isinstance(ix, dict) else None}) than the one beside it")
    try:
        listed = [(v["package"], v["size"], v["sha256"], v["manifest"], p["id"], v["version"], p["tier"], v["release_sha256"], v["attestation"],
                   v["attestation_sha256"]) for p in ix["plugins"] for v in p["versions"]]
    except (KeyError, TypeError) as x:
        raise Bad(f"{site}/index.json: no index: {x!r}")
    for package, size, sha, manifest, pid, version, tier, rsha, att, asha in listed:
        if package != f"packages/{pid}-{version}.hmp" or not isinstance(pid, str) or not ID.fullmatch(pid) or type(version) is not int:
            raise Bad(f"{site}/index.json: a package's path is not its plugin's and version's")
        try:
            with open(os.path.join(site, package), "rb") as f:
                data = f.read(plugcheck.PACKAGE_MAX + 1)
        except OSError as x:
            raise Bad(f"{site}: {x}")
        if len(data) != size or hashlib.sha256(data).hexdigest() != sha:
            raise Bad(f"{site}/{package}: not the package the index names")
        f = members(data, package)
        if hashlib.blake2b(f.get("manifest.json", b""), digest_size=32).hexdigest() != manifest:
            raise Bad(f"{site}/{package}: not the manifest the index names")
        try:
            m = json.loads(f["manifest.json"])
        except ValueError as x:
            raise Bad(f"{site}/{package}: its manifest: {x}")
        if plugcheck.listing_read(f, m, pk) != (tier, ix["serial"]):
            raise Bad(f"{site}/{package}: no listing by the index key for it, as {tier} and under this index's serial")
        # the attestations' bundles beside it, which name the release's bytes: the listed package without its listing
        # (their signatures are gh's to check, by anyone, against the release asset: build did, before it listed it)
        if att != package + attest.SUFFIX or not isinstance(rsha, str) or hashlib.sha256(released(f)).hexdigest() != rsha:
            raise Bad(f"{site}/{package}: not the release the index names (its attestation's file, or the SHA-256 of the package without its listing)")
        try:
            with open(os.path.join(site, att), "rb") as g:
                bundles = g.read(attest.BUNDLE_MAX + 1)
            named = attest.subjects(bundles)
        except (OSError, ValueError, RecursionError) as x:
            raise Bad(f"{site}/{att}: no attestation bundles: {str(x)[:160]}")
        if hashlib.sha256(bundles).hexdigest() != asha:
            raise Bad(f"{site}/{att}: not the bundles the index names (their SHA-256)")
        if rsha not in named:
            raise Bad(f"{site}/{att}: its attestations are of other files than the release of {package}")
        n += 1
    if say:
        print(f"{site}: both signatures hold, {n} packages as listed")
    return pk


def main():
    a = sys.argv[1:]
    opt = {}
    for name in ("--root", "--previous", "--serial", "--pub", "--key", "--arch", "--qemu", "--commit"):
        if name in a:
            i = a.index(name)
            if i + 1 >= len(a):
                sys.exit(__doc__)
            opt[name] = a[i + 1]
            del a[i:i + 2]
    for name in ("--bump", "--strict"):
        if name in a:
            a.remove(name)
            opt[name] = True
    root = opt.get("--root", os.path.dirname(HERE))
    try:
        if a == ["check"]:
            entries, revoked, was = load(root, opt.get("--previous"))
            print(f"{len(entries)} plugins, {sum(len(e['versions']) for e in entries)} versions; revocations: serial {revoked['serial']}, {len(revoked['entries'])} entries")
        elif len(a) == 2 and a[0] == "fetch":
            fetch(root, a[1], opt.get("--previous"))
        elif len(a) == 2 and a[0] == "smoke":
            if smoke(root, a[1], opt.get("--previous"), opt.get("--qemu")):
                sys.exit("index: smoke: a version did not pass the harness (above)")
        elif len(a) == 2 and a[0] == "entry":
            print(json.dumps(entry_fields(a[1]), indent=2, ensure_ascii=False))
        elif len(a) == 3 and a[0] == "build" and re.fullmatch(r"[0-9]{1,12}", opt.get("--serial", "")) and "--key" in opt:
            build(root, a[1], a[2], int(opt["--serial"]), opt["--key"], opt.get("--previous"), opt.get("--arch", "arm"), opt.get("--bump", False),
                  opt.get("--commit"), opt.get("--strict", False))
        elif len(a) == 3 and a[0] == "sign":
            sign(root, a[1], a[2])
        elif len(a) == 2 and a[0] == "verify":
            verify(a[1], opt.get("--pub", os.path.join(root, "keys", "index.pub")))
        else:
            sys.exit(__doc__)
    except Bad as e:
        sys.exit(f"index: {e}")
    except Exception as e:                                  # whatever was not thought of is a refusal too, and says so
        sys.exit(f"index: refused, and not in a way this tool knows: {e!r}")


if __name__ == "__main__":
    main()
