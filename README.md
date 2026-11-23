# hassmic plugin index

The list of plugins for [hassmic](https://github.com/Gamer92000/echo-dot-assist), which turns Amazon Echos into
Home Assistant voice satellites. A plugin is a program of its own beside hassmic, in a sandbox, with only the
powers its owner accepted with the Echo's action button.

This repository holds one small file per plugin and makes from them what is published: a signed list, the
packages it names (each with this index's listing in it), and a signed list of what was withdrawn. It is the one
place for plugins: every hassmic carries its public key (as hassmic's `keys/plugins.pub`) and reads its site
itself, on the settings page's "Browse plugins". It is a repository of its own so that nothing in it can touch a
release of hassmic: its key signs the lists and the listings, and nothing of hassmic's.

**State (2026-11-23):** the index lists, signs and verifies, and hassmic reads what it publishes (its tests build
their stand-in site with this repository's `tools/index.py`). It builds nothing: every package, official and
community alike, is its plugin's own release asset, built by that repository's GitHub Actions and attested so, and
the index verifies the attestation before it lists a version (below, "Where a package comes from"). One plugin is
entered and has no released version yet. Nothing is published, and the workflow has not run on GitHub yet. hassmic's
plugin system itself is experimental and unreleased.

## Plugins

| Plugin | What it is | Tier | Source |
|---|---|---|---|
| microWakeWord | The open wake word engine of ESPHome's voice satellites, with models you add | official | [hassmic-plugin-microwakeword](https://github.com/Gamer92000/hassmic-plugin-microwakeword) |

## Tiers

- **Official**: the project's own, in a repository of their own each, looked at by the maintainer, expected to
  work with every hassmic release. What makes a package official is the listing this index adds to it, signed by
  the index key, over the digest of the manifest that was looked at (the entry names it) and the tier. An Echo
  installs an update of an official plugin by the author key it pinned, that asks for nothing new and comes from
  this index as official, without its action button, and copies an official plugin between Echos of one
  household; a first install always waits for the button (hassmic's `docs/SECURITY.md` "Plugins"). So the index
  key is a key to keep as hassmic's release key is kept. Official plugins can be withdrawn here like any other
  (below): the revocation list takes their ids and author keys, and Echos apply it to every tier. Each hassmic
  build also carries the least version of an official plugin it runs, a floor of its own beside the list.
- **Community**: anyone's. Listed once the maintainer merged its entry, after a look that the entry is what it
  says, asks for what it declares, and that the release workflow its entry names (and all that workflow calls and
  runs) builds the package from the repository's own source for a tag's push: no review of the code is promised, and the page says "Not reviewed". Its package is what its author's own
  GitHub Actions built from the commit the entry names, and attested so (below); the index checks that and lists it.
  Its listing says `tier community`: an Echo takes it only once its owner switched community plugins on (its Plugins
  page), a first install waits for the button, an update by the author key the Echo pinned that asks for nothing new
  installs without it (as an official one's does), and it is never copied to another Echo without the button
  (hassmic's `plugin_store.c` `ps_stage_check`, `docs/SECURITY.md` "Plugins"). Refused for a community plugin,
  whatever else it is: `log.read.full` (official only), `request.audio` (it hears every request) together with
  `net.internet` (rule 48 of `tools/index.py`, the index's own, stricter than any Echo), and what 3.3's combinations
  refuse for anyone (`wake` with a way out). Flagged, in `index.json` (`broad`) and on the page: `net.lan` with any
  port, `net.internet`, `call`, `request.audio`, `request.text`, `log.read.full`; and the page flags a version with
  `request.audio` and any `net.*` (the Echo asks for its button twice for it). A plugin by anyone also installs from
  a file, as a sideload, without this index.

## An entry

`plugins/<id>.json`:

```json
{
  "id": "microwakeword",
  "name": "microWakeWord",
  "description": "One line, up to 240 characters.",
  "author": "hassmic",
  "author_key": "<the author's public key, 64 hex digits>",
  "tier": "official",
  "source": "https://github.com/Gamer92000/hassmic-plugin-microwakeword",
  "versions": [
    { "version": 1,
      "commit": "<the source's commit it was built from>",
      "workflow": ".github/workflows/release.yml",
      "manifest": "<the manifest's digest, as `plugcheck.py show` prints it>",
      "package": "https://github.com/Gamer92000/hassmic-plugin-microwakeword/releases/download/<tag>/microwakeword-1.hmp" }
  ]
}
```

A version is listed only when its package is the one the entry names: the manifest with that digest, signed by
the entry's author key and one an Echo takes (`manifest_check` in `tools/index.py` has the Echo's own rules,
each with the line of hassmic's `plugin_store.c` it follows, and `make check` holds the two to each other where
hassmic's tree is beside this one, `HASSMIC=<tree>` for another), a program that is the manifest's and keeps the
rules a file shows (32-bit ARM, static, no executable stack), packed as `plugcheck.py pack` packs it, with no listing
in it yet; and only when its attestation holds (below).  The entry's `name`, `author` and `description` are the
manifest's, character for character: an Echo shows the manifest's on its card and in the install's dialog and the
entry's in its list, and a package that calls itself something its entry does not is refused (so a manifest without a
description is never listed).  The `id` is none of the words of an Echo's settings page under `/api/plugins/`
(`ROUTE_WORDS`: `upload`, `install`, `chunk`, ...; the Echo refuses them too). Its `package` is the plugin's own release asset,
`<source>/releases/download/<tag>/<id>-<version>.hmp`, and nothing else: the build fetches it from there, adds this
index's listing and publishes the result, which is what Echos install. `source` is the plugin's GitHub repository,
`https://github.com/<owner>/<repository>` and nothing after (the attestation is GitHub's). `workflow` is the
workflow file that built and attested that release, `.github/workflows/<name>.yml` (hassmic's template and
microWakeWord: `.github/workflows/release.yml`): the attestation has to be that file's own run for the push of
`<tag>`, and it is what the maintainer reads (below). It is a version's, beside its commit: a workflow renamed later
leaves the versions before alone.

A community plugin's entry names more of the package, so that the pull request shows the maintainer what it is
without opening it, and so that every byte of what is listed is the entry's word whatever the release asset is
replaced with later:

```json
{
  "id": "example",
  "name": "Example",
  "description": "One line, up to 240 characters.",
  "author": "Your name",
  "author_key": "<your public key, 64 hex digits: the template's keys/author.pub>",
  "tier": "community",
  "source": "https://github.com/your-account/hassmic-plugin-example",
  "versions": [
    { "version": 1,
      "commit": "<the commit the release was built from, 40 hex digits>",
      "workflow": ".github/workflows/release.yml",
      "manifest": "<the release's manifest's digest>",
      "package": "https://github.com/your-account/hassmic-plugin-example/releases/download/v1/example-1.hmp",
      "signature": "<the package's manifest.sig, 128 hex digits>",
      "license_sha256": "<the SHA-256 of the package's LICENSE, 64 hex digits>",
      "capabilities": { "storage": 1, "net.server": [ { "setting": "server", "proto": "udp", "ports": "setting:port" } ] } }
  ]
}
```

`commit` is the commit the release workflow ran at (the tag's), `workflow` that workflow's file,
`capabilities` what the version asks the owner for,
exactly as its manifest has it (the maintainer reads it in the pull request; the package has to ask for exactly that,
value for value). `manifest`, `signature`, `license_sha256` and `capabilities` come from the released package:
`python3 tools/index.py entry <id>-<version>.hmp` (this repository's tool; the template's `make index-check` prints
the whole entry) prints them. With them every byte of the package is named: the manifest by its digest, the program
by the manifest's, the signature, the LICENSE by its SHA-256.

## Where a package comes from

Every package the index lists, official and community alike, is a release asset of its plugin's own GitHub
repository, built by that repository's GitHub Actions and carrying a GitHub artifact attestation of build provenance
(Sigstore; `actions/attest-build-provenance` in the release workflow, as hassmic's template has it,
`.github/workflows/release.yml`). Before a version is listed, `index.py build` verifies it (`tools/attest.py`):

1. `gh attestation verify <package> --repo <owner>/<repository> --source-digest <commit> --source-ref
   refs/tags/<tag> --cert-identity-regex '^https://github\.com/(?i:<owner>/<repository>)/<workflow>@refs/tags/<tag>$'
   --signer-digest <commit> --deny-self-hosted-runners --predicate-type https://slsa.dev/provenance/v1
   --cert-oidc-issuer https://token.actions.githubusercontent.com --format json` (GitHub's CLI, with a read-only token
   for GitHub's API; `<tag>` is the one in the entry's `package` address, `<workflow>` the entry's, its dots escaped;
   for a version the published site lists already, against the bundle the site keeps, `--bundle`, which needs no
   API, only Sigstore's trust root; gh is the one release `tools/gh.sh` downloads and checks by its SHA-256, 2.105.0,
   never the runner image's);
2. its JSON answer read again, field by field, not taken on its exit status: the statement's subjects name the
   package's SHA-256; SLSA provenance v1, a certificate of GitHub Actions' issuer; the source repository is the
   entry's `source` and its commit the entry's `commit`; the runner GitHub-hosted; the run was started by the push
   of the tag (`buildTrigger` and `githubWorkflowTrigger` `push`; `sourceRepositoryRef` and `githubWorkflowRef`
   `refs/tags/<tag>`); the workflow that signed (`buildSignerURI`) and the workflow the run was for
   (`buildConfigURI`) are both exactly `https://github.com/<owner>/<repository>/<workflow>@refs/tags/<tag>`, at
   `<commit>` (`buildSignerDigest`, `buildConfigDigest`), the workflow repository that same one. gh has no flag for
   the trigger and `buildConfigURI`: only this reading holds them;
3. what that workflow lets run (`tools/workflow.py`), where the attestation was asked of GitHub's API (a version not
   listed yet, or listed with another commit, workflow or release than the entry names now): the entry's workflow
   at the entry's commit, every workflow it calls and every action they use, all the way down, read through
   GitHub's API at the commit each is taken at, and every `uses:` in them pinned to what runs. An action, or another
   repository's reusable workflow, by a commit (40 hex digits) that is the action's own repository's: the head of
   one of its branches or tags, or in the history of one (GitHub's compare API from that head, "behind" or
   "identical"; the default branch first, at most 20 compares per commit), as zizmor's impostor-commit audit finds
   it. GitHub runs `<owner>/<repo>@<commit>` for a commit of any repository of that fork network, under the
   original's name (an impostor commit): a forked `actions/checkout` that swaps the source after the checkout,
   pinned by its commit, builds the same bytes in every job and is attested as the tag's push, so only the action's
   own refs say whose a commit is (never the commit's own page, which GitHub serves for a fork's commit too). Then
   what it is at that commit: an action's metadata (`action.yml`, `action.yaml`, `Dockerfile`, `dockerfile`, the
   first there, as GitHub's runner looks): a composite action's steps held to the same rules, each action of theirs
   read in turn (an action of the author's own, pinned by its own commit, whose step is that forked checkout, is
   refused); a docker action's image by its digest, or a Dockerfile in the action whose `FROM` lines and every
   `--from=` of a `COPY` or `ADD` name an image by its digest, an earlier stage or `scratch`, and every mount's
   `from=` (`RUN --mount`, its value read as CSV as BuildKit reads it, keys in any case) an earlier stage, no build
   argument in them. A Dockerfile is read only where BuildKit cannot read it otherwise; the rest is refused, never
   mirrored: a line continued (one that ends in a backslash, of any form: BuildKit's own rule, which joins the next
   line with no blank, is not followed), a line that starts with `//` or `#!` (BuildKit may read a syntax from it), a
   parser directive (`# syntax=` builds with a builder image by its tag; `# escape=`, `# check=`; any case or spacing,
   also after the first instruction), a file that reads as JSON, a heredoc, a flag of `COPY`, `ADD` or `RUN` with a
   quote or a backslash in it (BuildKit takes them out: `--fr\om=` is `--from=`), a character outside tab and
   printable ASCII in an instruction, a `FROM` of other words than an image and `AS <name>`. A node action's own
   files are that commit's. Another repository's reusable workflow is read with the same reader as the entry's, its
   calls and actions held to the same. GitHub's self-repository reference, `$/<path>`, is the file's own repository
   at the commit the file is read at: at a step an action, at a job a workflow (`$/.github/workflows/<file>`), held
   as such (a `.`, `..` or `@` in it, or an expression: refused). Each file is read once (an action that uses itself, workflows that call each other); more than 50
   files for one version is no verdict (a person reads such a release), and so is a commit found on none of the refs
   read of a repository that has more than 1000 branches or tags (it may be on one not read). An image (`docker://`,
   a job's `container:` and `services:`) by its digest; jobs, a job or its `services:` that are no mapping (an
   expression GitHub would expand into one) are refused, never passed over. Refused: a tag, a branch, a short commit, an expression, a
   commit found on none of the action's own refs, a local action (`uses: ./<path>` at a step, also in a composite
   action: GitHub takes it from whatever the job checked out, not from the commit), a `.` or `..` in an action's name
   or path, a `uses` anywhere else; and a workflow the index's reader does not read as plain YAML (a character outside
   printable ASCII, a folded block, a tab, an anchor or alias, a flow mapping, a quoted key, a value YAML could read
   as more: no reading, never a part skipped). An action's metadata is read where it counts: its `runs:` with that
   reader, the rest only as far as where each top-level key's lines are (descriptions with folded blocks and quoted
   texts over lines, as real actions write them, and one document marker `---` as the first line that is not a
   comment, are read past; everything that could make a line belong to another key than it seems to refused: a
   second document marker, an item of a flow collection that opens with `?`, `&`, `!` or `*`, and the rest
   `workflow.skim` names; `tests/test_skim_fuzz.py` holds it to PyYAML where that is installed). That is stricter
   than GitHub, and refuses some honest actions: of 43 real ones read on 2026-11-23, cachix/install-nix-action (a
   step `- run :`), houseabsolute/actions-rust-cross (an `if:` over two lines) and pypa/gh-action-pypi-publish (a
   character outside printable ASCII in its `runs:`). An author whose release uses one picks another action, or
   writes the step in the workflow itself. What a pinned action's own code does (a node action's downloads, a Dockerfile's
   `RUN` and `ADD`) is that commit of its owner's, fixed by its id, and the maintainer's to read. GitHub's API
   answering anything but 200 or 404, or not at all, is no verdict, as gh's failures are (below); and for a version
   the published site lists (asked of the API since the entry names it otherwise now), so is this check's refusal:
   an action's repository deleted or made private since answers 404, and a check that answers otherwise one day takes
   no listed version off (the build fails, a person decides).

So a package is refused when its attestation is of another repository, commit, file or runner; of another workflow
of the same repository (a second workflow that downloads a package and attests it); of the entry's workflow called
by another (`workflow_call`: the attestation then names the caller as `buildConfigURI`, and the caller's inputs
steer the run); of a run started by hand (`workflow_dispatch`: anyone who may write to the repository can run any
workflow file at any ref so), of a pull request or of a branch; or of another tag's run than the one the release
asset is under. A package uploaded by hand, or built anywhere else, has no attestation at all. In a pull request's
check (`--strict`) any of that is an error; in a publish it is a warning and the version is left out. The attestation
step has to run in a job of the named workflow itself: hassmic's template runs its checks as a local reusable
workflow (`release.yml` calls `build.yml`) and attests in `release.yml`'s own `release` job, so both URIs name
`release.yml`; an attestation made inside a called workflow names that one as its signer, and is refused.

**When gh cannot say.** Its own no's are verdicts: no attestation for the file, a field that is not what a flag asks,
an identity that is not the one asked or a signature that does not hold, GitHub's API answering 404 for the
repository (`VERDICTS` in `tools/attest.py`: gh 2.105.0's words), or more than gh may print. Anything else gh fails
with (missing, too slow, the network, Sigstore's trust root, GitHub's API answering 5xx, 401, 403 or a rate limit, an
answer that is not the list gh prints, a gh that words its verdicts otherwise, a gh that is not 2.105.0 by its own
`gh --version`, wherever the index runs) is no verdict, and never takes a version off the index: where the published
site lists the version, the build fails and nothing is published (run it again once gh answers); a version not listed
yet fails a pull request's check, and a publish leaves it out, said as no verdict, so that one release's
attestations, or GitHub's API, out of reach hold back neither the other versions nor the revocation list (a later
publish lists it). A publish while Sigstore's trust root is out of reach therefore publishes nothing, a revocation
neither, until it is back: the versions the site lists need it. A version the published site lists is verified again
with the site's own bundle, which held when it was listed, for the very bytes it held for (both from the site, as
`index.json` names them): any no there, gh's own or this reading's, is no verdict either, since what changed is gh,
Sigstore's trust root or the check, not the release. The build fails and says so; a listed version leaves the index
only by a person's step, the revocation list or an entry without it, never by a check that answers otherwise one day.
Every listed version is asked before the build fails, and the failure names each one without a verdict (a pull
request's check, `--strict`, names every version it left out the same way): a new gh or trust root that refuses all
kept bundles at once is one look, not a round per version. Every package is held to its entry first (no gh, no
network: one that is not its entry's ends the build before any attestation is asked); then the versions with the
site's own bundle are asked, then those listed and asked of GitHub's API, then the new ones, each group after the one
before, six at a time within a group (`ATTEST_WORKERS`, `tools/index.py`). Every listed version is verified again at
every publish, never skipped: its bundle and its bytes are the site's, but gh, Sigstore's trust root and this reading
change, and a version none of them holds any longer is a build that fails, not a version that stays unasked. So the
publish job's time grows with the versions: about the versions over six times one gh run each (seconds for a bundle),
which the job's 30 minutes (`index.yml`) hold for some thousands; past that, more workers or a longer job. Each
version without a verdict is also printed as it is found (in its group's order), and once one gh call of a run took
its whole time (180 s for `gh attestation verify`, 60 s for a call of GitHub's API) every later one of its kind is no
verdict at once, each named: the publish job never ends at its time with no version named. The kinds
are two, GitHub's API (an attestation asked of it, `gh api`) and a site's bundle (`--bundle`, which asks no API): a
stalled call for a new version holds back no listed one, nor the revocation list. A version the published site lists, verified with its own bundle, is not asked step 3 again: the site
lists no version whose references did not hold when it was listed, and neither the commit's files nor the commits
they pin change since, so GitHub's API out of reach holds back no listed version, nor the revocation list.

The bundle of the one attestation that held is published beside the package
(`packages/<id>-<version>.hmp.sigstore.jsonl`, one JSON line, at most 4 MB: a larger one that holds is not kept, and
where none fits the version is left out at the build, never a site that fails its own check at signing), and
`index.json` names the release asset and its SHA-256 (the listed package without its listing is that file again), the
commit and the workflow, so that anyone can verify it with the very command above and `--bundle
<id>-<version>.hmp.sigstore.jsonl` (the page prints it whole per version). The next build takes that bundle from the
site only where the entry still names the commit, the workflow and the release (its tag) the site listed the version
with; otherwise it asks GitHub's API again (a site of 93174b2, whose versions name no workflow, has every
version asked again so). A site made before 93174b2 (its versions name no release asset and no bundle) is not read
as the published site at all (`index.py verify`, `--previous`): nothing of that form was ever published.

**What that proves, and what it does not.** It proves that GitHub's CI, on a machine GitHub runs, ran the workflow
file the entry names, of that repository at that commit, for the push of that tag, and that this run made these
bytes: not a file someone uploaded, not a build on the author's own machine, not another workflow of the repository.
It does not prove what the workflow does: a workflow can download a program from anywhere and attest it. So the
maintainer reads, at that commit, in the entry's pull request, the named workflow and everything it runs: every local
reusable workflow it calls (`uses: ./.github/workflows/...`, the template's `build.yml`), the scripts and make
targets its steps run (the template's `tools/release.sh`, the `Makefile`), and the actions it uses (pinned by
commit); that it builds the package from the repository's own source with pinned tools, and that its trigger is the
push of a tag and nothing else. Nothing of what goes into the package may come from outside that commit: no action
(`uses:`) not pinned by a commit of the action's own repository (one on its tags or branches: GitHub runs a fork's
commit under the original's name too, an impostor commit, which the index refuses), all the way down (a composite
action's own steps, a called workflow's, a docker action's image and its Dockerfile's `FROM`, by the same rule), no
artifact of another job or run (one only to compare a build of its own with), no other job's outputs
(`needs.*.outputs`) but a SHA-256 to compare with, nothing of the event's payload (`github.event.*`; a tag's
annotation is not in the commit) but the tag's name, no other repository checked out at a ref that moves (a branch or
a tag; a commit's id stays), no container image (`container:`, `docker://`) not pinned by its digest, no cache
(`actions/cache`, the caches `setup-*` actions keep, which other runs write), no `vars` and no secret as an input
(the signing key aside, which only the release job's environment holds: no other job names an environment, whose
secrets it would get), no release asset already there, no toolchain resolved online by a channel (rustup's `stable`,
`beta` or `nightly`, in a `rust-toolchain.toml` or on its command line), and no download not pinned by its hash; and
a re-run of an old run, which GitHub attests as that tag's push again, has to make the same bytes. For a community
plugin nobody reads the plugin's code itself. The entry pins every byte of the package besides, so a release asset
replaced after the merge (another run of the same commit, attested too) is listed only where it is the same bytes.
Nor does the attestation prove anything about GitHub: it is GitHub's word, as the release asset is GitHub's to serve.

**The harness, a smoke test** (`index.py smoke`, `tools/harness.py`, hassmic's `docs/plugins.md` 5.8): in a pull
request, each community version the published site does not have is fetched and its ARM program run under
`qemu-arm -strace` against a stand-in broker (HELLO, WELCOME with what the manifest asks for, FILES, CONFIG with the
defaults, READY, PINGs for 3 s, the requests an Echo with nothing set up answers, STOP, and an end of its own within
2 s), every system call judged by the sandbox's own table (`tools/filter.def` and `tools/mkfilter.py`'s `judge`,
hassmic's, copied by `make sync`): the table, not the kernel's filter, which qemu cannot run. The first call the
table refuses fails the pull request's job, and so does any call on a descriptor the program was neither given (0 to
3) nor made (qemu-user shares its descriptor table with the program, its log among them), and a line in qemu's log
that is not one qemu writes. A call above 386 (the time64 calls, `statx`) is named and passes: on an Echo it gets
ENOSYS and the runtime falls back. It runs nothing that is built here: the package is the release's, so the program
that ran is the one listed (the entry names it by the manifest's digest). It runs a stranger's program, so it runs in
a job of its own with no secret, no token and no write permission, under bubblewrap (`tools/sandbox.py`: no
network, no home, its own `/tmp` and `/dev/shm`, `/usr` and `/etc` read-only, only its own folder writable, nothing
else of the machine's) and under bounds (`sandbox.LIMITS`: address space, file size, CPU, processes per user
namespace, the wall clock); where no process gets a user namespace (Ubuntu's AppArmor restriction, which the job
lifts) it fails whole. Publishing never runs it, nor anything else of a package.

It is a smoke test, not a wall: it shows a plugin that makes a call the sandbox refuses in its first seconds, and
nothing more. qemu judges a call after it ran (the sandbox around qemu is what keeps those calls in); a program can
tell it runs under qemu (`uname` says the PC's kernel, among other things) and behave; it can wait out the 3 s;
ARM's private calls (`cacheflush`, `set_tls`: 0xf0000 to 0xf07ff) are handled inside qemu and never logged; how a
runtime takes a refusal, and where qemu differs from a 3.18 kernel, it cannot show. The boundary is the Echo's: the
launcher's seccomp filter, built from the same table, refuses each such call on the Echo whatever the harness saw
(hassmic's `docs/plugins.md` 2.4; the run on an Echo, `scripts/plugin-probe.sh`, is the proof).

## Withdrawn plugins

`revoked.json`: a serial and entries by plugin id (every version, or up to one) or by author key, each with a
reason:

```json
{ "serial": 1795300000, "entries": [ { "id": "someplugin", "upto": 3, "reason": "sends what it hears to its author" } ] }
```

The serial is the time of the change, in seconds (`date +%s`), raised with every change: higher than the published
one, and not more than a day ahead of now (an Echo with its clock set refuses a list further ahead, and one that
took it would hold every honest list to it). At most 2048 entries and 512 kB as published, a reason at most 200
bytes: an Echo refuses a longer list whole, so the tool refuses to build one. Any plugin: official, community, and
plugins installed from a file (by their id or their author's key). An official plugin that is published keeps its
entry, tier and author key; its versions may go, and the list may withdraw it.

An Echo refuses a list older than the one it took (or than its hassmic release takes), keeps the newest, refuses to
install what it names, and stops a plugin installed there that it names: kept, its card says the reason, removing
it or running it anyway (with the Echo's action button, until a newer list names it again) is the owner's. While
plugins are on and one is installed, an Echo asks for this list by itself once a day at a random time, and the
Echos of one network hand it to each other.

## What is published

Static files, on GitHub Pages from the branch `gh-pages`:

| File | |
|---|---|
| `index.json` | `serial` (the time of the commit it was built from, or one more than the published one where that is not higher, the published site was built from the same commit or one it descends from and the site is new: a publish of a commit run again; it never goes back, and another index needs a higher one than the published, which has to be one this key signed; an Echo refuses one lower than it has taken, or than its hassmic release takes, or more than a day ahead of its clock), `revoked_serial` (the serial of the `revoked.json` it was built with: an Echo takes the index only beside a revocation list at least that new), then per plugin its entry and per version what it speaks and is for and asks for (`requires`, below, `models`, `capabilities`), the source's `commit` and its release `workflow`, for a community plugin `broad` (the broad capabilities it asks for: `net.lan`, `net.internet`, `call`, `request.audio`, `request.text`, `log.read.full`, in the Echo's order; at most `BROAD_MAX` names of at most `CAP_NAME_MAX` bytes each, past which an Echo refuses the whole index, which the Echo's "Browse plugins" says in words beside the version, a name it does not know left out), its manifest's digest, the listed package's path, size and SHA-256, which an Echo checks before anything else, and where it came from, which no Echo reads: `release` (the release asset's address), `release_sha256` (its SHA-256: the listed package without its listing), `attestation` and `attestation_sha256` (the bundle of the attestation that held, beside the package, and its SHA-256 under this file's signature). A version the revocation list withdraws is left out, a plugin all of whose versions it withdraws too. At most 1 MB, 4096 plugins, 16 versions each, the texts within an Echo's bounds (`BOUNDS` in `tools/index.py`, the same numbers as hassmic's `plugin_index.h`, which `make check` compares): the build fails past any of them |
| `index.json.sig` | the index key's signature over `"hassmic plugin index 1\n"` + the file |
| `revoked.json`, `revoked.json.sig` | the list above; the signature over `"hassmic plugin revoked 1\n"` + the file |
| `built-from.txt`, `built-from.txt.sig` | `commit <id>` and `index.json <its SHA-256>`: which commit of this repository made the index beside it, so that the next build raises the serial only over a site of its own commit or of one it descends from (`index.py build --bump`); the signature over `"hassmic plugin index built from 1\n"` + the file. Read by no Echo |
| `packages/<id>-<version>.hmp` | the packages as fetched from their releases and checked, their attestations verified, each with this index's `listing.sig` added: the index key's signature over `"hassmic plugin listing 2\nid <id>\nversion <n>\ntier <official\|community>\nmanifest <digest>\nserial <the index's>\n"` (form 1 was hassmic's release key's; no hassmic takes it). An Echo downloads `<site>/packages/<id>-<version>.hmp`, made of its own base address, the id and the version, never the path the list names |
| `packages/<id>-<version>.hmp.sigstore.jsonl` | the Sigstore bundle of the package's attestation that held (one JSON line, as gh verified it, at most 4 MB): the command of "Where a package comes from" with `--bundle <this file>`, run on the release asset, checks it again (the page prints it whole). Read by no Echo |
| `index.html` | the same list for people (`tools/page.py`, made in the same run): search, what each version may do in the words the Echo's own dialog uses, its broad capabilities flagged, "Not reviewed" on a community plugin, which commit's workflow, by its file, built it for which tag (attested) and the whole command that verifies it again, the author key's fingerprint as the Echo shows it, a download link per version with its SHA-256, and how to install from a file. Not signed, and it says so: an Echo checks the package itself |

`requires` is the manifest's own, as it is written: the least version of each scope of the plugin protocol the version
speaks (hassmic's `sdk/PROTOCOL.md` "Versions"), `core` and the scope of each capability it asks for and nothing else,
`{"core": 1, "files": 1, "wake": 1}`. An Echo runs the version where its hassmic has every scope named at that version
or a later one, and says "needs a newer hassmic: `<scope> <n>`" where it has not, before anything is downloaded; the
index lists such a version all the same (it is read by Echos of many builds) and refuses only a manifest that requires a
version no hassmic has yet (`SCOPES` in `tools/index.py`, each scope's newest version, which `make check` holds to
hassmic's `sdk/plugmsg.h`; a new version goes in when the hassmic that brings it is released). The page shows it as
"Speaks core 1, files 1, wake 1". A key of the manifest that a later version of its scope brought (`KEYS` in
`tools/index.py`, hassmic's `messages.def` "keys" lines, which `make check` compares) refuses a manifest that does not
require that version, as the Echo refuses it; `make check` also holds the two to each other on hassmic's code built
as a later hassmic's (its `tests/unit/scopes_demo.py`).

Signatures are hassmic's own kind (Monocypher's EdDSA with BLAKE2b, not RFC 8032's Ed25519; `tools/otatool.py`),
64 bytes, each over a text that starts with its purpose, so that none passes for another. The public key is
`keys/index.pub`; every hassmic build carries a copy (its `keys/plugins.pub`, named with this site's address in its
`keys/plugins.conf`).

What an Echo asks for: the four files of the lists (when the owner opens a Plugins page or presses a button
there), a package (when the owner installs or updates one, or for the plugin that is its wake word engine after a
hassmic update, with online updates on), and `revoked.json` with its signature once a day while plugins are on and
one is installed. GitHub Pages sees the Echo's address, those file names and "hassmic" as what asks, nothing else.

## Working on it

```sh
make check                      # the entries and the revocation list keep the rules; the tool's tests (the
                                # template end to end, and the harness's own runs, with zig, qemu-arm and bwrap where
                                # they are; gh is a stand-in in the tests, tests/fake_gh.py), and the reading list
                                # of "Where a package comes from" in the same words in all eight places
                                # (tests/test_reading.py: hassmic's docs, the template's and microWakeWord's README and
                                # release.yml, where those trees are beside this one; CI's siblings job checks them
                                # out and runs it with --require, where a missing one fails), and every action a
                                # release workflow uses, all the way down, by a commit of its own repository's, the
                                # authors' copies of the reader the same text (tests/test_references.py)
make site                       # fetch every package (each plugin's release asset; PREVIOUS=<published site>: what
                                # it has is taken from there with its attestations' bundles), check each against its
                                # entry, verify its attestation (gh, GH_TOKEN; INDEX_GH=<gh 2.105.0>, `sh tools/gh.sh
                                # build/gh` fetches it: another gh's answers are no verdict), list it, build site/
                                # (listed by secrets/index.key where it is there, else by a throwaway key: a site
                                # to check, not one to publish); PACKAGES=<dir> takes the packages (and bundles)
                                # from there: every version no PREVIOUS lists as entered is asked what its workflow
                                # runs, a bundle beside it or not;
                                # STRICT=1: a version left out is an error
make smoke                      # each community version the published site (PREVIOUS) does not have, in the harness
make sign                       # sign site/ with secrets/index.key and verify it (lists, listings, bundles)
python3 tools/index.py          # every step by itself
```

Python's standard library only (gh verifies the attestations; the harness runs bubblewrap and qemu-arm).
`tools/plugcheck.py`, `tools/otatool.py`, `tools/filter.def` (hassmic's `sdk/filter.def`) and `tools/mkfilter.py` are
hassmic's, copied in (`make sync`, `make drift`; `tools/VERSION` says from which commit).

CI (`.github/workflows/index.yml`, every job on `ubuntu-24.04`; `tests/test_workflow.py` holds it to what follows):
every pull request and push gets the check and the site's build (`check`: the tool's tests, every package fetched
from its release, checked, its attestation verified with the run's read-only token, listings by a throwaway key,
against the published site, `tools/published.sh`; a pull request's with `STRICT=1`, so a version without an
attestation that holds fails it), and `siblings`: the reading list's eight copies, the template's and microWakeWord's
workflows read as the index reads them and their copies of the reader held to its text, those three repositories
checked out beside it (their default branches, those files alone, no credentials; `--require`: a copy not there
fails), in a job no other waits for: a sibling's branch moves when it likes, and its failure is shown on the run but
never holds back a publish. A pull request also gets `smoke`: the harness over the community versions the published site does not have, in
a job with no secret, no token and no write permission, which no other job waits for. A push to `main` publishes the
whole site in a job with the index key (secret `INDEX_SIGNING_KEY` of the environment `index`, which admits `main`
only: base64 of `secrets/index.key`), `publish`, right after `check`: it fetches and checks the packages again,
verifies their attestations again, lists them, signs and publishes, and builds and runs nothing. Its serial is the
commit's time, or one more than the published one where that is not higher (`make site` with `PREVIOUS`:
`index.py build --bump`, only over a site this same commit made, by its signed `built-from.txt`, or one this commit
descends from, `git merge-base --is-ancestor` in a checkout of the whole history), nothing pushed where nothing is
new (`tools/publish.sh`). Only the newest commit publishes, and no publish undoes another: the job runs only while
the run's commit is the head of `main` (asked with `git ls-remote` before the job queues, again as the job's first
step once it has its turn, so that one that waited while a newer run published skips its build, and by
`tools/publish.sh` right before it pushes; a run of an older commit skips publishing and says so), the push replaces
`gh-pages` only where it is still the site it was built on (`--force-with-lease`, `tools/published.sh`'s
`previous.ref`), one publish at a time in a concurrency group of its own, and a cancelled run publishes nothing more
(`!cancelled()`). The packages the published site has are taken from it (checked against its signed index, their
attestations verified again against the bundles it keeps), only new ones fetched; a plugin's release that is gone,
or a new version's attestation that does not hold or cannot be had, leaves that version out with a warning and
blocks nothing else, the revocation list least of all; gh without a verdict on a version the site lists fails the
publish ("When gh cannot say"). Every action is pinned by its commit. The workflow has not run on GitHub yet.

Not built of hassmic's design (5.3) for community plugins: a pull request that updates a community plugin merging
itself (its owner, only its file, nothing an owner approved changed); the run on an Echo before a version is called
tested on a model (5.8).

A new index key (none planned) needs a hassmic release first: a build takes the word of the keys it carries and no
other's. A is the key in use, B the new one. Three steps, numbered as hassmic's `docs/plugins.md` 5.2 "The steps, as
built" numbers them (it has what each step does on an Echo):

1. hassmic: B's public half beside A in its `keys/plugins.conf` (`PLUGINS_PUB2`, with `PLUGINS_PUB2_WITH`, A's hex),
   released; then time for that release to reach the Echos. Here nothing changes: the index signs with A.
2. Here, in one commit: `keys/index.pub` becomes B, A stays as `keys/index-previous.pub`, and the environment
   `index`'s secret `INDEX_SIGNING_KEY` becomes the base64 of B's secret half. The next publish reads the published
   site, which A signed, with either key (`index.py` `index_keys`: `published()`, `--bump`'s `built_from()`,
   `check --previous`, `fetch --previous`) and builds and signs everything anew with B alone: both lists,
   `built-from.txt`, every package's listing. The revocation list goes out under a serial one above the published
   one where `revoked.json` is unchanged (`load()`; later builds keep the published serial for the same list, and a
   change of it needs a higher one, as ever): an Echo of both keys takes a list of the serial it has as "the same" and
   kept A's signature, which the build of step 3 reads as no list, so what it withdrew ran there until that Echo's
   next look (a review of hassmic 3c5d7ff, R1; hassmic now also keeps the same list's new signature, B's, and never
   turns it back to A's). `sign` and
   `verify` take B alone. Echos of step 1's release take the B site and, at their next look at the index (the Plugins
   page, or the daily look by itself), the B listing of each version they have installed (no button, no install;
   a version this index does not list keeps its A listing, which step 3 cannot read).
   Without `keys/index-previous.pub` the build refuses the A site as one the index key did not sign, and nothing is
   published, revocations neither. Once the published site is B's (that first publish done),
   `keys/index-previous.pub` goes in a commit of its own, and A's secret half is retired.
3. hassmic: a release with B alone, only once this index lists, by B, every version still installed on the Echos:
   every version listed at step 2 stays listed until step 3 has been out for a while. An Echo that never looked at
   the index since step 2 has its plugins as from a file under it until that release's own look at the index, about
   a minute after its start (then hourly while it fails), takes their B listings by itself. A version this index no
   longer lists by then is never moved: under step 3 it is a file's, and with community plugins off (the default)
   it does not run, the wake word engine's neither, until its owner installs a version listed here or switches
   community plugins on. Where step 3 starts with the wake word engine's plugin stopped that way, its self test
   fails, and that only keeps the build from becoming the Echo's factory copy, the one it falls back to, while it
   is so: nothing goes back, the build runs on (its other plugins waiting for the self test, stopped), its look
   restores the plugin, and the self test, which asks again every 10 s, passes then: the build becomes the factory
   copy and the other plugins start (reviews of hassmic 3fcd319 and 9cd7a77).

`keys/index-previous.pub` must be 32 bytes, another key than `keys/index.pub`, and no key under which any signature
holds (small order: `otatool.weak`, which also refuses what it cannot read as a point: six such encodings Monocypher,
and so an Echo, reads as small order); so must `keys/index.pub` and every entry's `author_key`.

## Licence

MIT, see `LICENSE`. Each plugin has its own.
