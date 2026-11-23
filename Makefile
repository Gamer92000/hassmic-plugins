# The index of hassmic's plugins.  tools/index.py does the work; this is how its steps go together.  The index lists:
# every package is its plugin's own release asset, built and attested by that repository's GitHub Actions; nothing
# is built here.
#
#   make check      the entries and the revocation list keep the rules; the tool's own tests (tests/test_references.py:
#                   every action a release workflow uses, all the way down, by a commit of its own repository's; the
#                   authors' copies of the reader the same text; tests/test_skim_fuzz.py: an action's metadata read
#                   by skim as PyYAML reads it, skipped where PyYAML is not); the reading list in the same words in its eight
#                   places (tests/test_reading.py: the sibling trees where they are there; index.yml's siblings job,
#                   which no other job needs, checks them out and runs both with --require, where a missing one fails)
#   make site       fetch every entered package (what the published site PREVIOUS lists with the commit and workflow
#                   the entry names, from there, with the bundle of its attestation; the rest from each plugin's own
#                   release; one that cannot be had is left out, warned of) and build site/: each package checked
#                   against its entry and its attestation verified (tools/attest.py: gh attestation verify, the
#                   entry's workflow's own run for the tag's push; GH_TOKEN for GitHub's API; INDEX_GH the gh to run,
#                   which has to be tools/gh.sh's version, else no verdict (sh tools/gh.sh DIR fetches it);
#                   gh without a verdict on a version PREVIOUS lists fails it, and so does gh's no to the bundle
#                   PREVIOUS keeps of it, every such version named in the one failure; index.yml's gh is
#                   tools/gh.sh's, by its SHA-256),
#                   then listed (with PREVIOUS its serial is the commit's time, or one more than the published one
#                   where that is not higher, the published site was built from this same commit (COMMIT, its
#                   built-from.txt) or one it descends from (git merge-base: the whole history, not a shallow clone)
#                   and anything is new: index.py build --bump, a publish of the same commit run again; never over
#                   another commit's site): each package with the index's listing added, by
#                   KEY where it is there (the publish job), else by a throwaway key (a pull request's job, a PC
#                   without the key): such a site checks everything and is never one to publish (sign refuses it)
#                   (index.html with it: the list for people, tools/page.py)
#                   PACKAGES=<dir>: the packages (and their .sigstore.jsonl) from there instead of fetched (what a
#                   workflow runs is asked of every version PREVIOUS does not list as entered, bundle or not)
#                   STRICT=1: a version left out (no package, no attestation that holds) is an error (a pull request)
#   make smoke      each community version the published site does not have, fetched, its program run in the
#                   harness (tools/harness.py in tools/sandbox.py's bubblewrap; a smoke test, a pull request's job
#                   without secrets; QEMU: qemu-arm where index.py does not find it by itself)
#   make sign       sign site/ with the index key (KEY, default secrets/index.key) and verify it
#   make sync | drift   take hassmic's package tool, signatures and the sandbox's table from HASSMIC | say where they differ
HASSMIC ?= ../echo-dot-assist
KEY ?= secrets/index.key
# The index's serial only grows: the time of the commit it is built from
SERIAL ?= $(shell git log -1 --format=%ct 2>/dev/null || date +%s)
# and the commit itself, which the site records (built-from.txt): --bump goes only over a site of this commit
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null)
LISTKEY := $(if $(wildcard $(KEY)),$(KEY),build/throwaway.key)

check:
	python3 tools/index.py check
	python3 tests/test_index.py
	python3 tests/test_attest.py
	python3 tests/test_community.py
	python3 tests/test_workflow.py
	python3 tests/test_references.py
	python3 tests/test_skim_fuzz.py
	python3 tests/test_reading.py

build/throwaway.key:
	@mkdir -p build
	python3 tools/otatool.py keygen $@ build/throwaway.pub

site: $(LISTKEY)
	rm -rf build/packages site
	$(if $(PACKAGES),mkdir -p build/packages && cp $(PACKAGES)/*.hmp $(PACKAGES)/*.hmp.sigstore.jsonl build/packages/ 2>/dev/null || true,python3 tools/index.py fetch build/packages $(if $(PREVIOUS),--previous $(PREVIOUS)))
	python3 tools/index.py build build/packages site --serial $(SERIAL) --key $(LISTKEY) $(if $(COMMIT),--commit $(COMMIT)) \
	    $(if $(PREVIOUS),--previous $(PREVIOUS) --bump) $(if $(STRICT),--strict)

smoke:
	rm -rf build/smoke
	python3 tools/index.py fetch build/smoke $(if $(PREVIOUS),--previous $(PREVIOUS))
	python3 tools/index.py smoke build/smoke $(if $(PREVIOUS),--previous $(PREVIOUS)) $(if $(QEMU),--qemu $(QEMU))

sign:
	python3 tools/index.py sign site $(KEY)
	python3 tools/index.py verify site

sync:
	tools/sync.sh $(HASSMIC)
drift:
	tools/sync.sh --check $(HASSMIC)

.PHONY: check site smoke sign sync drift
