#!/usr/bin/env python3
"""A plugin's release workflow read as data, and every action it uses held to a commit of that action's own
repository, all the way down (hassmic's docs/plugins.md 5.3 "As built"; README.md "Where a package comes from").
index.py build asks this of a version right after its attestation held, where that was asked of GitHub's API: what
the attestation proves is that the entry's workflow file at the entry's commit ran; this says what that file let run.

Why: `uses: <owner>/<repo>@<40 hex>` pins an action by its commit, and GitHub resolves that commit across the whole
fork network of <owner>/<repo>: a commit pushed to anyone's fork runs under the original's name (an "impostor
commit", as zizmor's audit of that name calls it).  A forked actions/checkout that swaps the source after checking
out the tag, pinned in both the build and the release job, builds the same bytes twice, is attested as the tag's
push, and passes every test the plugin's own repository has.  And one level is not enough (a review of 810b9e9): a
composite action of the author's own, pinned by its own commit, whose step is that forked checkout, or another
repository's reusable workflow whose actions are tags, runs them all the same.  So, for each version, everything the
run takes is read (GitHub's contents API at the commit it is taken at: a commit's files are its own whatever
repository serves them), starting with the entry's workflow at the entry's commit:
  - a workflow (the entry's; a local reusable one it calls, `uses: ./.github/workflows/<file>` at a job, which GitHub
    reads from the caller's repository and commit; another repository's, <owner>/<repo>/.github/workflows/<file>@<40
    hex> at a job; `$/.github/workflows/<file>` at a job, GitHub's self-repository reference, from the file's own
    repository and commit): read with the strict reader below, every `uses:` in it held to the rules, every job's
    `container:` and `services:` image by its digest (jobs, a job or its services that are no mapping, an
    expression GitHub would expand: refused, never passed over);
  - an action, <owner>/<repo>[/<path>]@<40 hex> at a step: first its commit has to be <owner>/<repo>'s own, found
    as zizmor's impostor-commit audit finds it: the head of one of its branches or tags (GitHub's listings of the
    repository itself, which no fork adds to), else in the history of one, by GitHub's compare API from that head to
    the commit ("behind" or "identical": the head reaches it), the default branch's first.  Only the repository's
    own refs are asked, never the commit's own page (GitHub serves a fork's commit there too, under the original's
    name).  At most COMPARES compares per reference: an honest pin is a tag's commit (the fast path) or one on the
    default branch; a commit found nowhere within them is refused, a verdict the author answers with a tag's commit
    (where GitHub's listing of the refs was longer than PAGES pages, none: the commit may be on one not read).  Then
    its metadata at that commit, as GitHub's runner looks for it (<path>/action.yml, action.yaml, Dockerfile,
    dockerfile, the first there): `runs.using: composite`, its `runs.steps` held to the same rules, each action of
    theirs read in turn; `docker`, its `runs.image` an image by its digest (docker://<image>@sha256:<64 hex>) or a
    Dockerfile in the action, whose FROM lines and every `--from=` of a COPY or ADD have to name an image by its
    digest, an earlier stage or scratch, and every mount's `from=` (RUN --mount, read as CSV, keys in any case) an
    earlier stage, no build argument in them.  A Dockerfile is read only where BuildKit cannot read it otherwise, and
    the rest is refused, never mirrored (a review of 5a3035d): a line continued (one that ends in a backslash, of any
    form), a line that starts with // or #!, a parser directive (`# syntax=` builds with a builder image by its tag;
    `# escape=`, `# check=`; any case or spacing, anywhere), a file that reads as JSON, a heredoc, a flag of COPY, ADD
    or RUN with a quote or backslash in it, a character outside tab and printable ASCII in an instruction, a FROM of
    other words than an image and `AS <name>`; anything else (node) runs the action's own files at that commit, fixed
    by its id.  The metadata is read where it matters: its top level by skim() (which keys there are, each one's
    lines, every form of YAML that could make a line belong to another key than it seems to refused), and its `runs:`
    with the strict reader.  That is stricter than GitHub, and refuses some honest actions (2026-11-23, of 43 real
    ones: cachix/install-nix-action, a `- run :`; houseabsolute/actions-rust-cross, an `if:` over lines;
    pypa/gh-action-pypi-publish, a character outside printable ASCII in its runs): an author whose release uses one
    picks another action, or writes the step in the workflow itself;
  - `$/<path>` at a step (GitHub's self-repository reference): the action at <path> of the file's own repository, at
    the commit the file is read at (a workflow's, a composite action's), held as an action of that commit is; a `.`,
    `..` or `@` in it, or an expression, refused;
  - docker://<image>@sha256:<64 hex> at a step: an image by its digest.
Anything else is refused: a tag or a branch (a ref that moves), a short commit, an expression, a local action
(`uses: ./<path>` at a step, in a workflow or a composite action: GitHub takes it from the job's workspace, which is
whatever the job checked out there, not necessarily the commit), a `.` or `..` in an action's name or path (the
runner joins the path to the action's folder as it is), a `uses` anywhere else.  Each file is read once (a workflow
that calls itself, an action that uses itself: read once, held once); more than FILES_MAX files for one version is
no verdict (attest.Unavailable: a bound of the index's, never a pass, and a person reads such a release).  What a
pinned action does inside its own code (a node action's downloads, a Dockerfile's RUN and ADD) is that commit of its
owner's; the maintainer reads the workflow and all it runs all the same (the reading list).

The reader is strict: the subset of YAML a workflow is written in (mappings, lists, block texts with |, plain and
simply quoted values, flow lists of those), and anything it would read otherwise than a YAML parser does is no
reading (ValueError, then Refused): a character outside tab, line feed and printable ASCII (a line or paragraph
separator, NEL, form feed: Python's splitlines breaks there and YAML does not), a tab outside a block text, a folded
block (>: its blank lines are YAML's to fold), an anchor, alias, tag, flow mapping, complex or quoted key, a key twice,
a value YAML would read as more than a value (": ", " #"), a line left over.  The plugin template's and
microWakeWord's tools/workflow_test.py carry the same reader (an author's own check; this one is the index's):
tests/test_references.py holds the three to one text where those trees are there (index.yml's siblings job), and
each of them holds its copy to this one where this tree is beside it.  tests/test_workflow.py reads index.yml with it.

API failures are no verdict (attest.Unavailable), as gh's are; a repository or file GitHub answers 404 for is a
verdict (attest.Refused).  Every call is gh's (`gh api`, the gh tools/gh.sh pins, attest.gh_checked), with --include,
so that the answer's HTTP status, not gh's wording, decides.  Python's standard library only."""
import csv, json, re, subprocess

import attest

# ---- the reader (the template's and microWakeWord's tools/workflow_test.py: the same text)

# a plain value YAML would read as something else when it starts so (an anchor, alias, tag, flow, block, quote,
# directive, reserved, comment, or an indicator with a blank after it)
_INDICATOR = re.compile(r"[&*!{}\[\]|>'\"%@`#,]|[-?:](\s|$)")


def scalar(t):
    """a value as YAML reads it (a text, or a list of texts from a flow list); ValueError where YAML might read it
    otherwise"""
    t = t.strip()
    if t.startswith("["):
        if not t.endswith("]") or re.search(r"[\[\]{}]", t[1:-1]):
            raise ValueError(f"a flow list not read: {t[:80]}")
        items = [x.strip() for x in t[1:-1].split(",")]
        if items[-1] == "":
            items.pop()
        if any(x == "" for x in items):
            raise ValueError(f"a flow list not read: {t[:80]}")
        return [scalar(x) for x in items]
    if t.startswith("'"):
        if len(t) < 2 or not t.endswith("'") or "'" in t[1:-1].replace("''", ""):
            raise ValueError(f"a quoted value not read: {t[:80]}")
        return t[1:-1].replace("''", "'")
    if t.startswith('"'):
        if len(t) < 2 or not t.endswith('"') or '"' in t[1:-1] or "\\" in t:
            raise ValueError(f"a quoted value not read: {t[:80]}")
        return t[1:-1]
    if _INDICATOR.match(t) or ": " in t or t.endswith(":") or " #" in t:
        raise ValueError(f"a value not read as plain: {t[:80]}")
    return t


def parse(text):
    """the subset of YAML a workflow is written in, as dicts, lists and strings, and the numbers of the lines that are
    block texts' (the rest are YAML's own).  Anything else is no reading (ValueError), never a part skipped: a key
    twice, a line left over (deeper than its place, or after the end), a key of another form.  A block text (run: |)
    is kept as written, its comment lines and its ` #` too: they are the shell's, and a check that read them cut off
    would pass what the shell runs (a review of 6bca341)"""
    text = text.replace("\r\n", "\n")
    bad = re.search(r"[^\t\n\x20-\x7e]", text)
    if bad:
        raise ValueError(f"a character outside tab, line feed and printable ASCII (U+{ord(bad.group()):04X}), line "
                         f"{text.count(chr(10), 0, bad.start()) + 1}: YAML and a reader by lines may break its lines apart differently")
    raw = text.split("\n")
    lines, blocks = [], set()
    for n, r in enumerate(raw):
        # (" #" begins YAML's comment on a line of its own; inside a quoted value it would not, and that value then
        # does not read: refused, never cut)
        s = r.split(" #")[0].rstrip()
        if s.strip() and not s.lstrip().startswith("#"):
            lines.append((len(s) - len(s.lstrip(" ")), s.strip(" "), n))
    pos = [0]

    def take():
        ind, s, n = lines[pos[0]]
        if "\t" in raw[n].split(" #")[0]:
            raise ValueError(f"a tab outside a block text, line {n + 1}: YAML takes none in indentation")
        return ind, s, n

    def block(indent):
        if pos[0] >= len(lines):
            return None
        if lines[pos[0]][1].startswith("- "):
            out = []
            while pos[0] < len(lines) and lines[pos[0]][0] == indent and lines[pos[0]][1].startswith("- "):
                ind, s, n = take()
                rest = s[2:]
                if re.match(r"[\w.-]+:( |$)", rest):
                    # a mapping as the item: its first key on the dash's line
                    lines[pos[0]] = (ind + 2, rest, n)
                    out.append(mapping(ind + 2))
                else:
                    pos[0] += 1
                    out.append(scalar(rest))
            return out
        return mapping(indent)

    def mapping(indent):
        out = {}
        while pos[0] < len(lines) and lines[pos[0]][0] == indent and not lines[pos[0]][1].startswith("- "):
            ind, s, n = take()
            m = re.match(r"([\w.-]+):(?: (.*))?$", s)
            if not m:
                raise ValueError(f"not read: line {n + 1}: {s[:80]}")
            key, val = m.group(1), (m.group(2) or "").strip()
            if key in out:
                raise ValueError(f"{key} twice, line {n + 1}")
            pos[0] += 1
            if re.fullmatch(r"\|[-+]?", val):
                # the raw lines below the key, as long as they are deeper than it (blank ones within); YAML's block
                # is as deep as its first line, and a line less deep ends it: refused here, never read into it
                end = n + 1
                while end < len(raw) and (not raw[end].strip() or len(raw[end]) - len(raw[end].lstrip(" ")) > indent):
                    end += 1
                body = raw[n + 1:end]
                while body and not body[-1].strip():
                    body.pop()
                deep = next((len(x) - len(x.lstrip(" ")) for x in body if x.strip()), 0)
                if any(x.strip() and not x.startswith(" " * deep) for x in body):
                    raise ValueError(f"a block text whose lines are less deep than its first, line {n + 2}")
                blocks.update(range(n + 1, end))
                out[key] = "\n".join(x[deep:] for x in body)
                while pos[0] < len(lines) and lines[pos[0]][2] < end:
                    pos[0] += 1
            elif val:
                out[key] = scalar(val)
            elif pos[0] < len(lines) and lines[pos[0]][0] > indent:
                out[key] = block(lines[pos[0]][0])
            elif pos[0] < len(lines) and lines[pos[0]][0] == indent and lines[pos[0]][1].startswith("- "):
                out[key] = block(indent)
            else:
                out[key] = None
        return out
    top = block(0)
    if pos[0] < len(lines):
        raise ValueError(f"not read: line {lines[pos[0]][2] + 1}: {lines[pos[0]][1][:80]}")
    return top, blocks


def read(text):
    """parse's dicts, lists and strings"""
    return parse(text)[0]


# ---- what a workflow uses

OWNER = r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}"
REPO = r"[A-Za-z0-9._-]{1,100}"
ACTION = re.compile(rf"({OWNER})/({REPO})((?:/[A-Za-z0-9._-]+)*)@([0-9a-f]{{40}})")
LOCAL_WORKFLOW = re.compile(r"\./(\.github/workflows/[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}\.ya?ml)")
REMOTE_WORKFLOW = re.compile(r"/(\.github/workflows/[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}\.ya?ml)")
# `$/<path>`: GitHub's self-repository reference, the repository of the file it is in at the commit that file is
# taken at (the runner's SelfRepositoryAlias; GitHub's docs: no @<ref> after it, and it resolves against the file's
# own repository, not a caller's), so read from there and held as a pinned action of that commit is
SELF = re.compile(r"\$/((?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+)")
IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:-]{0,255}@sha256:[0-9a-f]{64}")
FILES_MAX = 50                  # files read per version: workflows, actions' metadata, Dockerfiles (the template's
                                # release reads 8: release.yml, build.yml, five actions, and the one attest-build-
                                # provenance uses); past it no verdict
FILE_MAX = 1 << 20              # bytes of a file
COMPARES = 20                   # GitHub's compare asked per reference, after the heads of its branches and tags
PAGES = 10                      # pages of 100 branches, and of 100 tags, read per repository
SECONDS = 60                    # one gh api call
METADATA = ("action.yml", "action.yaml", "Dockerfile", "dockerfile")    # as GitHub's runner looks, in this order


def action(u):
    """the match of ACTION for U, None where it is none or names `.` or `..` as its repository or as a part of its
    path (GitHub's runner joins the path to the action's folder without normalising it: actions/checkout/../../x
    would be another folder than any the index read), or a repository GitHub would not give (attest.repo_of)"""
    m = ACTION.fullmatch(u)
    if not m or attest.repo_of(f"https://github.com/{m.group(1)}/{m.group(2)}") is None:
        return None
    if any(p in (".", "..") for p in m.group(3).split("/")[1:]):
        return None
    return m


def uses(tree, text_blocks, raw, where=("jobs",)):
    """every `uses` of the workflow TREE as (where, kind, value): kind "job" (a job's: a reusable workflow) or "step";
    ValueError for a `uses` anywhere else, for one that is no text, and where the lines that say `uses:` are not as
    many as the `uses` read (the reader's own check of itself).  WHERE ("runs",): a composite action's runs, whose
    steps are runs.steps"""
    found = []
    top = tree.get(where[0]) if isinstance(tree, dict) else None
    if not isinstance(top, dict):
        raise ValueError(f"no {where[0]}")

    def walk(v, path):
        if isinstance(v, dict):
            for k, x in v.items():
                if k == "uses":
                    found.append((path, x))
                walk(x, path + [k])
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(x, path + [i])
    walk(tree, [])
    out = []
    for path, value in found:
        at = ".".join(str(p) for p in path)
        if not isinstance(value, str):
            raise ValueError(f"{at}.uses is no text")
        if where == ("jobs",) and len(path) == 2 and path[0] == "jobs":
            out.append((at, "job", value))
        elif where == ("jobs",) and len(path) == 4 and path[0] == "jobs" and path[2] == "steps" and isinstance(path[3], int):
            out.append((at, "step", value))
        elif where == ("runs",) and len(path) == 3 and path[:2] == ["runs", "steps"] and isinstance(path[2], int):
            out.append((at, "step", value))
        else:
            raise ValueError(f"a uses where none is read: {at}")
    said = sum(1 for n, line in enumerate(raw) if n not in text_blocks and re.match(r"\s*(-\s+)*uses\s*:", line.split(" #")[0]))
    if said != len(found):
        raise ValueError(f"{said} lines say uses:, {len(found)} read")
    return out


def images(tree):
    """(where, image) of every job's container and services: what has to be pinned by its digest.  Where GitHub could
    read an image from a value that is not the mapping read here (jobs, a job or its services as an expression, a
    list), that value is returned as the image: it is none by its digest, so it is refused, never skipped (a review of
    9b02fdb, 3: `services: ${{ fromJSON(...) }}` and a job that was no mapping went by unread)"""
    out, jobs = [], tree.get("jobs")
    if jobs is not None and not isinstance(jobs, dict):
        return [("jobs", jobs)]
    for jid, job in (jobs or {}).items():
        if not isinstance(job, dict):
            out.append((f"jobs.{jid}", job))
            continue
        c = job.get("container")
        if c is not None:
            out.append((f"jobs.{jid}.container", c.get("image") if isinstance(c, dict) else c))
        services = job.get("services")
        if services is not None and not isinstance(services, dict):
            out.append((f"jobs.{jid}.services", services))
            continue
        for sid, s in (services or {}).items():
            out.append((f"jobs.{jid}.services.{sid}", s.get("image") if isinstance(s, dict) else s))
    return out


# ---- an action's metadata, and a Dockerfile

# what YAML (GitHub's runner reads action.yml with YamlDotNet) or Docker could take as a line break, or as more than
# a character, where a reader by "\n" would not; anything else of Unicode may stand in a description
_BREAKS = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f  ﻿\ud800-\udfff]")


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _close_quote(s, i, q):
    """the index after the quote that closes the one opened before S[i] (q: ' or "), None where the line ends first
    (a double-quoted value's backslash takes the next character with it, a single-quoted value's '' is one quote)"""
    while i < len(s):
        c = s[i]
        if q == "'" and c == "'":
            if s[i + 1:i + 2] == "'":
                i += 2
                continue
            return i + 1
        if q == '"' and c == "\\":
            i += 2
            continue
        if q == '"' and c == '"':
            return i + 1
        i += 1
    return None


def _flow_end(s, i):
    """the index after the flow collection that opens at S[i] closes, on this line; ValueError where it does not (a
    flow collection over lines is not read), a quoted value in it does not close, or an item in it opens with ?, &, !
    or * (a complex key, an anchor, a tag, an alias: after each YAML starts the item anew, and a quote there opens a
    quoted text, which a reader that took the item as begun missed; a review of 5a3035d)"""
    depth, item = 0, True
    while i < len(s):
        c = s[i]
        if c in "[{":
            depth, item = depth + 1, True
        elif c in "]}":
            depth -= 1
            if depth == 0:
                return i + 1
        elif c == ",":
            item = True
        elif c == "#" and s[i - 1] in " \t":
            break
        elif c in "'\"" and item:
            j = _close_quote(s, i + 1, c)
            if j is None:
                break
            i, item = j, False
            continue
        elif c in "?&!*" and item:
            raise ValueError(f"a flow collection with an item that opens with {c}: not read")
        elif c == ":":
            # (after a quoted key YAML takes `:` with no blank after it as the value's indicator too: a quote after
            # any `:` is taken as opening one, which refuses more, never less)
            item = True
        elif c not in " \t":
            item = False
        i += 1
    raise ValueError("a flow collection that does not close on its line")


def skim(text):
    """the top-level keys of an action's metadata file and each one's lines: {key: (first, end)} over
    text.split("\n").  Only its `runs:` is read further (with the strict reader); the rest (name, description,
    inputs, branding: what real actions write with folded blocks, quoted texts over lines and the like) only has to
    be where it seems to be.  So everything that could make a line at column 0 belong to another key than the one it
    seems to (a quoted text or a flow collection over lines, a block text) is followed as YAML follows it, and what
    is not followed here is no reading (ValueError): a character YAML or Docker could break a line at, a tab in
    indentation, an anchor, alias, tag or directive, a document marker but one as the first line that is not a
    comment, a quoted or complex key, a flow collection over lines or an item in one that opens with ?, &, ! or *, a block text with an indentation indicator, a quoted text or a plain text continued on a line not deeper
    than its key, a line at column 0 that is not `<key>:`, a key twice at the top"""
    text = text.replace("\r\n", "\n")
    bad = _BREAKS.search(text)
    if bad:
        raise ValueError(f"a character YAML may read as a line break or not at all (U+{ord(bad.group()):04X}), line "
                         f"{text.count(chr(10), 0, bad.start()) + 1}")
    raw = text.split("\n")
    keys, last, begun = {}, None, False
    block = quote = plain = expect = None       # the column a block text, an open quoted text, a plain text, a value
                                                # on the lines below is under (its key's, or its dash's)
    key = re.compile(r"([\w.-]+):(?=\s|$)")
    stack = [(0, "map")]                        # (column, "map" | "list") of each block collection open
    for n, line in enumerate(raw):
        if block is not None:
            # (its lines as deep as its first, which is deeper than its key; one less deep than its first but deeper
            # than its key YAML refuses)
            if not line.strip():
                continue
            if _indent(line) > block[0]:
                if block[1] is None:
                    block = (block[0], _indent(line))
                elif _indent(line) < block[1]:
                    raise ValueError(f"a block text's line less deep than its first, line {n + 1}")
                continue
            block = None
        if quote is not None:
            q, owner = quote
            if line.strip() and _indent(line) <= owner:
                raise ValueError(f"a quoted text continued on a line not deeper than its key, line {n + 1}")
            end = _close_quote(line, 0, q)
            if end is not None:
                quote = None
                rest = line[end:].strip()
                if rest and not rest.startswith("#"):
                    raise ValueError(f"after a quoted text: {rest[:40]!r}, line {n + 1}")
            continue
        s = line.strip(" ")
        if not s:
            continue
        if "\t" in line[:len(line) - len(line.lstrip())]:
            raise ValueError(f"a tab in indentation, line {n + 1}")
        if s.startswith("#"):
            plain = None
            continue
        ind = _indent(line)
        if ind == 0 and re.fullmatch(r"---([ \t]+#.*)?", line.rstrip(" \t")):
            # (one document: its start marker as the first line that is not a comment, as actions/setup-python's and
            # pypa/gh-action-pypi-publish's open; YamlDotNet, which GitHub's runner reads action.yml with, reads the
            # first document, so a second marker, which a reader by lines would read past, is refused)
            if keys or begun:
                raise ValueError(f"a document marker after the first line, line {n + 1}: a second document")
            begun = True
            continue
        if plain is not None and ind > plain:
            # a plain text's next line (YAML folds it into the text): nothing in it begins anything
            if re.search(r":(\s|$)", s.split(" #")[0]):
                raise ValueError(f"a plain text's next line that reads as a key, line {n + 1}")
            continue
        plain = None
        if ind == 0:
            m = key.match(line)
            if not m:
                raise ValueError(f"a line at the top that is not a key: {line[:60]!r}, line {n + 1}")
            if m.group(1) in keys:
                raise ValueError(f"{m.group(1)} twice at the top, line {n + 1}")
            if last is not None:
                keys[last] = (keys[last][0], n)
            keys[m.group(1)], last = (n, None), m.group(1)
            owner, pos, expect, stack = 0, m.end(), None, [(0, "map")]
        else:
            # the block collections open here: a line is an entry of one of them (a key of a mapping, a dash of a
            # list, at its column), or the first of a new one, or a value, deeper than the key or dash above that
            # left its value to the lines below.  Any other indentation YAML refuses, and so does this
            opened, expect = expect, None
            while stack[-1][0] > ind:
                stack.pop()
            kind = "list" if line[ind] == "-" and line[ind + 1:ind + 2] in (" ", "") else "map" if key.match(line, ind) else "value"
            if stack[-1][0] == ind:
                if stack[-1][1] == kind:
                    pass
                elif kind == "list" and opened == ind:
                    stack.append((ind, "list"))         # key:  then  - item  at the key's own column
                elif kind == "map" and stack[-1][1] == "list" and stack[-2] == (ind, "map"):
                    stack.pop()
                else:
                    raise ValueError(f"a {kind} where a {stack[-1][1]} is, line {n + 1}")
            elif opened is not None and ind > opened:
                if kind != "value":
                    stack.append((ind, kind))
            else:
                raise ValueError(f"an indentation YAML does not read here, line {n + 1}")
            pos, dash = ind, None
            while line[pos] == "-" and line[pos + 1:pos + 2] in (" ", ""):
                if dash is not None:
                    stack.append((pos, "list"))
                dash, pos = pos, pos + 1
                while pos < len(line) and line[pos] == " ":
                    pos += 1
                if pos == len(line):
                    break
            if pos == len(line) or line[pos] == "#":
                # a dash alone: its item on the lines below
                expect = dash
                continue
            m = key.match(line, pos)
            if m:
                if dash is not None:
                    stack.append((pos, "map"))      # - key: value, a mapping at the key's column
                owner, pos = pos, m.end()
            elif dash is not None:
                owner = dash                        # a list item's value
            elif kind == "value" and opened is not None:
                owner = opened                      # the value of the key above, on a line of its own
            else:
                raise ValueError(f"not read as a key or a value: {s[:60]!r}, line {n + 1}")
        while pos < len(line) and line[pos] in " \t":
            pos += 1
        v = line[pos:].rstrip(" ")
        if not v or v.startswith("#"):
            expect = owner
            continue
        c = v[0]
        if c in "'\"":
            end = _close_quote(line, pos + 1, c)
            if end is None:
                quote = (c, owner)
                continue
            after = line[end:].strip()
            if after.startswith(":"):
                raise ValueError(f"a quoted key, line {n + 1}")
            if after and not after.startswith("#"):
                raise ValueError(f"after a quoted text: {after[:40]!r}, line {n + 1}")
        elif c in "[{":
            after = line[_flow_end(line, pos):].strip()
            if after and not after.startswith("#"):
                raise ValueError(f"after a flow collection: {after[:40]!r}, line {n + 1}")
        elif c in "|>":
            if not re.fullmatch(r"[|>][-+]?(\s+#.*)?", v):
                raise ValueError(f"a block text's header not read: {v[:20]!r}, line {n + 1}")
            block = (owner, None)
        elif c in "&*!%@`?" or c == "-" and v[1:2] in (" ", ""):
            raise ValueError(f"not read: {v[:40]!r}, line {n + 1}")
        else:
            if re.search(r":(\s|$)", v.split(" #")[0]):
                raise ValueError(f"a plain text with ': ' in it, line {n + 1}")
            plain = owner
    if quote is not None:
        raise ValueError("a quoted text that does not close")
    if last is not None:
        keys[last] = (keys[last][0], len(raw))
    return keys


def metadata(text):
    """an action's metadata (action.yml) as its runs: (runs, the uses of a composite one's steps).  ValueError where
    it is not read (skim, the strict reader), has no runs.using, or a `uses` where GitHub reads none"""
    keys = skim(text)
    if "runs" not in keys:
        raise ValueError("no runs")
    a, b = keys["runs"]
    lines = text.replace("\r\n", "\n").split("\n")[a:b]
    tree, blocks = parse("\n".join(lines))
    runs = tree.get("runs") if isinstance(tree, dict) else None
    if not isinstance(runs, dict) or not isinstance(runs.get("using"), str):
        raise ValueError("no runs.using")
    found = uses(tree, blocks, lines, ("runs",)) if runs["using"].casefold() == "composite" else []
    if found and not isinstance(runs.get("steps"), list):
        raise ValueError("runs.steps is no list")
    if runs["using"].casefold() != "composite" and sum(1 for n, x in enumerate(lines) if n not in blocks and re.match(r"\s*(-\s+)*uses\s*:", x.split(" #")[0])):
        raise ValueError(f"a uses in the runs of a {runs['using'][:20]} action, which GitHub reads none of")
    return runs, found


# a line BuildKit continues on the next: its own rule is `([^\\])\\[ \t]*$|^\\[ \t]*$` (a line ending `\\\\` does not
# continue, and the continued line is joined with no separator, its blank and comment lines dropped): any line that
# ends in a backslash, of any form, is refused here instead (a review of 5a3035d: a reading by rstrip().endswith
# joined what BuildKit does not and the other way round, and a second FROM hid in between)
_CONTINUED = re.compile(r"\\[ \t]*$")
# a parser directive as BuildKit reads one before the first instruction (`# syntax=` builds with a builder image by its
# tag, `# escape=` changes how the rest is read, `# check=`), any case, any spacing; refused anywhere, also where it
# would be a comment
_DIRECTIVE = re.compile(r"[ \t]*#[ \t]*[A-Za-z][A-Za-z0-9]*[ \t]*=")
# a stage's name as BuildKit takes one (lowercased first; parse.go validStageName); anything else as a name is no
# reading, and a source that is not such a name is never taken for a stage
_STAGE = re.compile(r"[a-z][a-z0-9_.-]*")


def dockerfile(text):
    """what a Dockerfile builds from that is not an image by its digest, an earlier stage or scratch: a list of
    "line N: why".  ValueError where it is not read as BuildKit reads it, which is refused rather than mirrored where
    mirroring would be long (a review of 5a3035d): a character Docker could break a line at; a character outside tab
    and printable ASCII in an instruction (Go's flag reader takes the bytes 0x85 and 0xa0, inside a UTF-8 character
    too, for a blank); a file that reads as JSON, or opens with { or [; a line continued (one that ends in a
    backslash, any form); a line that starts with // or #! (BuildKit's syntax detection reads `// syntax=` and the
    like as a directive); a parser directive (`# syntax=`, `# escape=`, `# check=`, any case or spacing, anywhere); a
    heredoc; a flag of COPY, ADD or RUN with a quote or a backslash in it (BuildKit takes them out, so `--fr\\om=` is
    `--from=`); a FROM of more words than an image and `AS <name>`, or a stage's name BuildKit would not take.  A
    mount's `from=` (RUN --mount, its value read as CSV as BuildKit reads it, keys in any case) has to name an earlier
    stage; a `--from=` (COPY, ADD) an image by its digest or an earlier stage"""
    text = text.replace("\r\n", "\n")
    bad = _BREAKS.search(text)
    if bad:
        raise ValueError(f"a character Docker may read as a line break or not at all (U+{ord(bad.group()):04X})")
    try:
        json.loads(text)
        is_json = True
    except ValueError:
        is_json = False
    if is_json or text.lstrip().startswith(("{", "[")):
        raise ValueError("a file that reads as JSON, or opens as JSON does (BuildKit reads a syntax from one)")
    lines = []
    for n, line in enumerate(text.split("\n"), 1):
        if _CONTINUED.search(line):
            raise ValueError(f"a line continued on the next (a backslash at its end), line {n}: not read")
        s = line.strip(" \t")
        if s.startswith(("//", "#!")):
            raise ValueError(f"a line that starts with {s[:2]}, line {n}: BuildKit may read a syntax from it")
        if _DIRECTIVE.match(line):
            raise ValueError(f"a parser directive (or a comment written as one), line {n}")
        if not s or s.startswith("#"):
            continue                        # (a comment, a blank line)
        if re.search(r"[^\t\x20-\x7e]", s):
            raise ValueError(f"a character outside tab and printable ASCII in an instruction, line {n}")
        lines.append((n, s))
    stages, current, out = [], None, []        # the earlier stages' names (each a name or None), the current one's

    def source(x, stage_only=False):
        if "$" in x:
            return "a build argument"
        if re.fullmatch(r"[0-9]+", x):
            # (a stage by its number: an earlier one's, else BuildKit takes it for an image)
            return None if int(x) < len(stages) else "no earlier stage of that number"
        if _STAGE.fullmatch(x.lower()) and x.lower() in stages:
            return None
        if stage_only:
            return "not an earlier stage"
        if x.lower() == "scratch":
            return None
        return None if IMAGE.fullmatch(x) else "not an image by its digest (@sha256:...)"
    for n, ins in lines:
        word, args = (re.split(r"[ \t]+", ins, maxsplit=1) + [""])[:2]
        word = word.upper()
        if "<<" in ins and word in ("RUN", "COPY", "ADD"):
            raise ValueError(f"a heredoc, line {n}")
        if word == "FROM":
            parts = [x for x in args.split() if not x.startswith("--platform=")]
            if any(x.startswith("-") for x in parts) or any(c in args for c in "'\"\\"):
                raise ValueError(f"a FROM with a flag, a quote or a backslash, line {n}: not read")
            if len(parts) == 3 and parts[1].lower() == "as":
                if not _STAGE.fullmatch(parts[2].lower()):
                    raise ValueError(f"a stage's name BuildKit does not take ({parts[2][:40]!r}), line {n}")
                name = parts[2].lower()
            elif len(parts) == 1:
                name = None
            else:
                raise ValueError(f"a FROM of {len(parts)} words, line {n}: not read")
            why = source(parts[0])
            if why or re.fullmatch(r"[0-9]+", parts[0]):
                out.append(f"line {n}: FROM {args[:80]}: {why or 'a stage by its number, which FROM does not take'}")
            if current is not None:
                stages.append(current[0])
            current = (name,)
        elif word in ("COPY", "ADD", "RUN"):
            # (BuildKit's flags: the words before the first that does not start with --, up to a lone --)
            for flag in re.split(r"[ \t]+", args):
                if not flag.startswith("--") or flag == "--":
                    break
                if any(c in flag for c in "'\"\\"):
                    raise ValueError(f"a flag with a quote or a backslash in it, line {n}: not read ({flag[:60]!r})")
                key, _, value = flag.partition("=")
                key = key.lower()
                if key == "--from":
                    why = source(value)
                    if why:
                        out.append(f"line {n}: {word} --from={value[:80]}: {why}")
                elif key == "--mount":
                    try:
                        fields = next(csv.reader([value]), [])
                    except csv.Error as x:
                        raise ValueError(f"a --mount not read as CSV, line {n}: {x}")
                    for field in fields:
                        k, _, v = field.partition("=")
                        if k.strip().lower() == "from":
                            why = source(v, stage_only=True)
                            if why:
                                out.append(f"line {n}: RUN --mount from={v[:80]}: {why} (a mount's from= is taken only of one)")
        elif word == "ONBUILD":
            out.append(f"line {n}: ONBUILD: not read")
    if current is None:
        out.append("no FROM")
    return out


# ---- GitHub's API, through gh

def api(path, raw=False):
    """(HTTP status, body) of a GET of PATH through `gh api --include`; Unavailable where gh gave no such answer"""
    gh = attest.gh_program()
    attest.gh_checked(gh)
    attest.not_stalled("api")
    a = [gh, "api", "--include", "-H", "Accept: " + ("application/vnd.github.raw+json" if raw else "application/vnd.github+json"),
         "-H", "X-GitHub-Api-Version: 2022-11-28", path]
    status, out, err = attest.run_cli(a, SECONDS, f"gh api {path[:120]}", "api")
    # (gh prints the status line, the headers, a blank line and the body, also for an answer of 4xx or 5xx, for which
    # it ends with status 1; no status line is no answer: the network, the token, gh itself)
    head, _, body = out.replace(b"\r\n", b"\n").partition(b"\n\n")
    m = re.match(rb"HTTP/[0-9.]+ ([0-9]{3})\b", head)
    if not m:
        why = next((x.strip() for x in reversed(err.decode(errors="replace").splitlines()) if x.strip()), f"status {status}")
        raise attest.Unavailable(f"gh api {path[:120]}: no HTTP answer (" + "".join(c if " " <= c < "\x7f" else "?" for c in why)[:200] + ")")
    return int(m.group(1)), body


def _json(path):
    status, body = api(path)
    if status == 404:
        return None
    if status != 200:
        raise attest.Unavailable(f"GitHub's API answered {status} to {path[:120]}")
    try:
        return json.loads(body)
    except ValueError:
        raise attest.Unavailable(f"GitHub's API answered no JSON to {path[:120]}")


class Owner:
    """what GitHub's API says of one repository's own refs, asked once per build"""
    _repos = {}

    def __init__(self, owner, repo):
        self.name = f"{owner}/{repo}"
        info = _json(f"repos/{owner}/{repo}")
        if not isinstance(info, dict):
            raise attest.Refused(f"no repository {self.name} on GitHub")
        self.default = info.get("default_branch")
        self.heads = []                         # (ref, commit), the default branch first
        self.cut = []                           # the listings longer than PAGES pages: not all refs are known
        for kind in ("branches", "tags"):
            for page in range(1, PAGES + 1):
                got = _json(f"repos/{owner}/{repo}/{kind}?per_page=100&page={page}")
                if not isinstance(got, list):
                    raise attest.Unavailable(f"GitHub's API gave no list of {self.name}'s {kind}")
                for x in got:
                    sha = x.get("commit", {}).get("sha") if isinstance(x, dict) and isinstance(x.get("commit"), dict) else None
                    if isinstance(sha, str) and attest.COMMIT.fullmatch(sha):
                        self.heads.append((("refs/heads/" if kind == "branches" else "refs/tags/") + str(x.get("name")), sha))
                if len(got) < 100:
                    break
            else:
                self.cut.append(kind)
        self.heads.sort(key=lambda h: h[0] != f"refs/heads/{self.default}")
        self.owns = {}

    @classmethod
    def of(cls, owner, repo):
        """the repository's refs, or Refused where GitHub has no such repository (kept too: asked once)"""
        k = f"{owner}/{repo}".casefold()
        if k not in cls._repos:
            try:
                cls._repos[k] = cls(owner, repo)
            except attest.Refused as x:
                cls._repos[k] = x
        if isinstance(cls._repos[k], attest.Refused):
            raise cls._repos[k]
        return cls._repos[k]

    def own(self, sha):
        """None where SHA is one of the repository's own commits, else why not; Unavailable where it was not found
        and not every ref was listed (more than PAGES pages: the commit may be on one not read, so that is no
        verdict, never a refusal of an honest pin; a review of 810b9e9)"""
        if sha not in self.owns:
            self.owns[sha] = self._own(sha)
        return self.owns[sha]

    def _own(self, sha):
        if any(h == sha for _, h in self.heads):
            return None
        bases = list(dict.fromkeys(h for _, h in self.heads))[:COMPARES]
        for base in bases:
            got = _json(f"repos/{self.name}/compare/{base}...{sha}?per_page=1")
            if isinstance(got, dict) and got.get("status") in ("behind", "identical"):
                return None
        if self.cut:
            raise attest.Unavailable(f"{sha} is on none of the {len(self.heads)} branches and tags of {self.name} the index read, and GitHub "
                                     f"lists more {' and '.join(self.cut)} than it reads ({PAGES} pages of 100): no verdict")
        return (f"{sha} is on none of {self.name}'s own branches and tags (their heads, and the history of "
                f"{len(bases)} of them): a commit of a fork, which GitHub runs under {self.name}'s name too; pin a commit of one of its tags")


def file_at(repo, commit, path, missing=False, text="ascii"):
    """the file PATH of REPO at COMMIT, as text (TEXT "ascii": a workflow, which the strict reader reads; "utf-8": an
    action's metadata or a Dockerfile, which skim and dockerfile hold to their own characters).  MISSING: None where
    GitHub answers 404, else Refused"""
    status, body = api(f"repos/{repo}/contents/{path}?ref={commit}", raw=True)
    if status == 404:
        if missing:
            return None
        raise attest.Refused(f"{path} is not in {repo} at {commit[:12]}")
    if status != 200:
        raise attest.Unavailable(f"GitHub's API answered {status} for {path} at {commit[:12]}")
    if len(body) > FILE_MAX:
        raise attest.Refused(f"{path} at {commit[:12]} is larger than {FILE_MAX >> 10} kB")
    try:
        return body.decode(text)
    except UnicodeDecodeError:
        raise attest.Refused(f"{path} at {commit[:12]}: " + ("a character outside printable ASCII, which the index does not read"
                                                             if text == "ascii" else "not UTF-8"))


def check(source, commit, workflow):
    """None where every `uses:` of SOURCE's WORKFLOW at COMMIT, of every workflow it calls and of every action they
    use, all the way down, is pinned by a commit of the action's own repository (or an image by its digest), every
    job's image by its digest, and every Dockerfile an action builds from images by their digests; Refused with every
    reference that is not, Unavailable where GitHub's API gave no answer or more than FILES_MAX files were read"""
    repo = attest.repo_of(source)
    if repo is None or not attest.COMMIT.fullmatch(str(commit)) or not attest.WORKFLOW.fullmatch(str(workflow)):
        raise attest.Refused("the source, commit or workflow is not one")
    # (kind, repository, commit, path, how it was reached), read in that order, each once
    todo, seen, wrong, read = [("workflow", repo, commit, workflow, "")], set(), [], [0]

    def fetch(r, c, p, missing=False, text="ascii"):
        read[0] += 1
        if read[0] > FILES_MAX:
            raise attest.Unavailable(f"more than {FILES_MAX} files to read for one version (workflows, actions, Dockerfiles), the "
                                     "index's bound: no verdict, which a person gives by reading it")
        return file_at(r, c, p, missing, text)

    def held(u, kind, at, r, c):
        """U, a `uses` at AT of a file of R at C, held to the rules: what it runs is queued, what it may not be is said"""
        local, act, self_ = LOCAL_WORKFLOW.fullmatch(u), action(u), SELF.fullmatch(u)
        if kind == "job" and local:
            # (GitHub reads it from the caller's repository and commit)
            todo.append(("workflow", r, c, local.group(1), at))
        elif u.startswith("$/"):
            # (the file's own repository at the commit the file is read at: a workflow at a job, an action at a step;
            # no `.` or `..` (the runner joins the path as it is), no @<ref>, no expression, nothing but such a path)
            path = self_.group(1) if self_ else None
            if path is None or any(x in (".", "..") for x in path.split("/")):
                wrong.append(f"{at}: {u[:120]}: a self-repository reference ($/<path>) with `.`, `..`, `@`, an expression or "
                             "another character in its path: not read")
            elif kind == "job":
                if REMOTE_WORKFLOW.fullmatch("/" + path):
                    todo.append(("workflow", r, c, path, f"{at} ({u[:100]})"))
                else:
                    wrong.append(f"{at}: {u[:120]}: a job's self-repository reference that is not a workflow (.github/workflows/<file>)")
            else:
                todo.append(("action", r, c, path, f"{at} ({u[:100]})"))
        elif act and (kind == "step" or REMOTE_WORKFLOW.fullmatch(act.group(3))):
            try:
                why = Owner.of(act.group(1), act.group(2)).own(act.group(4))
            except attest.Refused as x:
                why = str(x)
            name = f"{act.group(1)}/{act.group(2)}"
            if why:
                wrong.append(f"{at}: {why}")
            elif kind == "job":
                todo.append(("workflow", name, act.group(4), act.group(3)[1:], f"{at} ({u[:100]})"))
            else:
                todo.append(("action", name, act.group(4), act.group(3)[1:], f"{at} ({u[:100]})"))
        elif kind == "step" and u.startswith("docker://") and IMAGE.fullmatch(u[len("docker://"):]):
            pass
        elif u.startswith("./"):
            wrong.append(f"{at}: {u[:120]}: a local action is taken from whatever the job checked out, not from the commit")
        else:
            wrong.append(f"{at}: {u[:120]}: not pinned by a commit (40 hex digits) of a repository by its name, or an image by its digest")

    def held_docker(text, where, via):
        try:
            for why in dockerfile(text):
                wrong.append(f"{where} ({via}) {why}")
        except ValueError as x:
            wrong.append(f"{where} ({via}) is not read as the index reads a Dockerfile ({x})")

    while todo:
        kind, r, c, p, via = todo.pop(0)
        key = (kind, r.casefold(), c, p)
        if key in seen:
            continue
        seen.add(key)
        here = f"{p}" if r == repo and c == commit else f"{r}/{p}@{c[:12]}".replace("/@", "@")
        if kind == "workflow":
            text = fetch(r, c, p)
            try:
                tree, blocks = parse(text)
                found = uses(tree, blocks, text.replace("\r\n", "\n").split("\n"))
            except ValueError as x:
                wrong.append(f"{here}{' (' + via + ')' if via else ''} is not read as the plain YAML the index reads ({x})")
                continue
            for where, k, u in found:
                held(u, k, f"{here} {where}", r, c)
            for where, image in images(tree):
                if where.count(".") < 2 or where.endswith(".services"):
                    wrong.append(f"{here} {where}: {str(image)[:120]}: not a mapping the index reads, where GitHub may read an image: none by its digest (@sha256:...) to be seen")
                elif not isinstance(image, str) or not IMAGE.fullmatch(image):
                    wrong.append(f"{here} {where}: {str(image)[:120]}: an image not pinned by its digest (@sha256:...)")
        elif kind == "action":
            base = p + "/" if p else ""
            for name in METADATA:
                text = fetch(r, c, base + name, missing=True, text="utf-8")
                if text is not None:
                    break
            else:
                wrong.append(f"{via}: no {', '.join(METADATA)} in {r}{'/' + p if p else ''} at {c[:12]}")
                continue
            where = f"{r}/{base}{name}@{c[:12]}"
            if name in ("Dockerfile", "dockerfile"):
                # (an action that is a Dockerfile alone: GitHub's runner builds it, as a docker action's)
                held_docker(text, where, via)
                continue
            try:
                runs, found = metadata(text)
            except ValueError as x:
                wrong.append(f"{where} ({via}) is not read as the index reads an action's metadata ({x})")
                continue
            using = runs["using"].casefold()
            if using == "composite":
                for at, k, u in found:
                    held(u, k, f"{where} {at}", r, c)
            elif using == "docker":
                image = runs.get("image")
                if isinstance(image, str) and image.startswith("docker://"):
                    if not IMAGE.fullmatch(image[len("docker://"):]):
                        wrong.append(f"{where} runs.image: {image[:120]}: an image not pinned by its digest (@sha256:...)")
                elif isinstance(image, str) and re.fullmatch(r"(\./)?[A-Za-z0-9_-][A-Za-z0-9._/-]{0,199}", image) and \
                        not any(x in (".", "..", "") for x in image.removeprefix("./").split("/")):
                    todo.insert(0, ("dockerfile", r, c, base + image.removeprefix("./"), via))
                else:
                    wrong.append(f"{where} runs.image: {str(image)[:120]}: neither an image by its digest nor a Dockerfile in the action")
            # (node, and anything else: the action's own files at that commit, which its id fixes)
        else:
            held_docker(fetch(r, c, p, text="utf-8"), f"{r}/{p}@{c[:12]}", via)
    if wrong:
        raise attest.Refused(f"{len(wrong)} reference{'s' if len(wrong) > 1 else ''} not pinned to what runs: " + "; ".join(wrong[:4])
                             + (f"; and {len(wrong) - 4} more" if len(wrong) > 4 else ""))
    return None
