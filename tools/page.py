"""The site's page for people (index.html): every plugin of index.json with what it may do, in the words the Echo
itself shows before its button is pressed, and each version's package to download for an install from a file.

Made by index.py build from the same data as index.json, in the same run, so the two never say different things.
The page is not signed: what an Echo checks is the package (the author's signature, the index key's listing),
and the page says so.  It is whole by itself: no font, script or picture from anywhere else, and it reads well
without its script, which only filters.  Every text from an entry or a manifest goes through html.escape; the
only addresses are an entry's source (https, entry_check's URL rule) and the site's own packages/ paths."""
import datetime, hashlib, html, json
import attest

def reach_line(words, v):
    """net.lan's and net.internet's line as hassmic's reach_line makes it (API 0.6): each entry's protocol and ports"""
    try:
        parts = [f"{'UDP' if e['proto'] == 'udp' else 'TCP'}, " + ("any port" if e["ports"] == "any" else ("ports " if len(e["ports"]) > 1 else "port ") + ", ".join(str(p) for p in e["ports"])) for e in v]
        return f"{words} ({'; '.join(parts)})"
    except (TypeError, KeyError, AttributeError):
        return words


# hassmic's plugin_store.c ps_cap_line, word for word where the index has what the Echo fills in: the page says
# what the dialog on the Echo will say.  One a later hassmic adds and this does not know yet is shown by its name.
CAP_WORDS = {
    "storage": lambda v, x: f"Keeps up to {v} kB of its own data on this Echo",
    "files": lambda v, x: f"Reads the files you give it on its page ({', '.join(x.get('file_labels') or []) or 'none'}, up to {v} MB)",
    "state": lambda v, x: "Sees when this Echo listens and speaks",
    "log.read": lambda v, x: "Reads this Echo's technical log",
    "log.read.full": lambda v, x: "Reads this Echo's whole log, including what was said",
    "net.server": lambda v, x: "Connects to the server you enter",
    "net.lan": lambda v, x: reach_line("Connects to any device on your network", v),
    "net.internet": lambda v, x: reach_line("Connects to the internet", v),
    "net.udp": lambda v, x: "Can be reached from your network",
    "net.discover": lambda v, x: "Searches your network for its server",
    "audio.music": lambda v, x: "Plays sound on this Echo's speaker, whenever it likes",
    "audio.volume": lambda v, x: "Changes this Echo's volume",
    "call": lambda v, x: "Makes and takes calls: a call coming in is answered only at the Echo, one goes out only when Home Assistant or the settings page asks. Hears the room during a call",
    "wake": lambda v, x: "Hears this Echo's microphone all the time, to listen for its wake words",
    "request.audio": lambda v, x: "Hears everything said to this Echo after the wake word or the button",
    "request.text": lambda v, x: "Reads what was said to this Echo and what it answered",
    "ha.entities": lambda v, x: "Shows in Home Assistant",
    "ha.actions": lambda v, x: "Home Assistant can tell it what to do",
    "button": lambda v, x: "Hears presses of this Echo's buttons, as Home Assistant's \"Button\" does",
}
# the ones that reach past the Echo or hear more than the wake word: marked, so they stand out in a list
CAP_LOUD = {"net.lan", "net.internet", "net.udp", "net.discover", "request.audio", "request.text", "log.read.full", "call", "audio.music"}


def fingerprint(key_hex):
    """as hassmic's ps_fingerprint and sdk/plugcheck.py show: the first 16 hex digits of BLAKE2b-256 over the key,
    in fours.  What the Echo's dialog shows for the author, so the two can be compared by eye"""
    h = hashlib.blake2b(bytes.fromhex(key_hex), digest_size=32).hexdigest()[:16]
    return " ".join(h[i:i + 4] for i in range(0, 16, 4))


def withdrawn(plugin, version, revoked):
    """the revocation list's reason for this version, or None"""
    for r in revoked.get("entries", []):
        if r.get("author_key") == plugin["author_key"]:
            return r["reason"]
        if r.get("id") == plugin["id"] and ("upto" not in r or version <= r["upto"]):
            return r["reason"]
    return None


def size(n):
    return f"{n / 1048576:.1f} MB" if n >= 1048576 else f"{max(1, round(n / 1024))} kB"


def e(s):
    return html.escape(str(s), quote=True)


def cap_items(caps, extra):
    out = []
    for name, value in caps.items():
        words = CAP_WORDS[name](value, extra) if name in CAP_WORDS else f"{name} (a capability this page has no words for yet)"
        loud = ' class="loud"' if name in CAP_LOUD else ""
        out.append(f'<li{loud}><span class="cap">{e(name)}</span> {e(words)}</li>')
    return "".join(out)


def version_block(p, v, revoked, newest):
    reason = withdrawn(p, v["version"], revoked)
    x = v.get("_page", {})
    head = f'<span class="vname">Version {e(v["version_name"])}</span>'
    if v["version_name"] != str(v["version"]):
        head += f' <span class="dim">({e(v["version"])})</span>'
    meta = [e(size(v["size"]))]
    if x.get("license"): meta.append(f'licence {e(x["license"])}')
    if x.get("memory_mb"): meta.append(f'up to {e(x["memory_mb"])} MB of memory')
    models = v.get("models", ["*"])
    meta.append("every Echo" if models == ["*"] else "for " + e(", ".join(models)))
    out = [f'<div class="version{" newest" if newest else ""}">', f'<div class="vhead">{head}<span class="meta">{" · ".join(meta)}</span></div>',
           # (the least version of each scope of the protocol it speaks: an Echo whose hassmic has them runs it, an
           # older one says it needs a newer hassmic)
           f'<p class="speaks dim">Speaks {e(", ".join(f"{k} {n}" for k, n in v["requires"].items()))}</p>']
    if reason:
        out.append(f'<p class="withdrawn"><strong>Withdrawn:</strong> {e(reason)}. Not offered here, and an Echo that has the list refuses it.</p>')
    else:
        out.append(f'<p class="get"><a class="download" href="{e(v["package"])}" download>Download {e(p["id"])}-{e(v["version"])}.hmp</a>'
                   f'<span class="sha" title="SHA-256 of the package">SHA-256 <code>{e(v["sha256"])}</code>'
                   f'<button type="button" class="copy" data-copy="{e(v["sha256"])}" aria-label="Copy the SHA-256">Copy</button></span></p>')
    out.append(f'<p class="said">The Echo asks you to accept that it:</p><ul class="caps">{cap_items(v["capabilities"], x)}</ul>')
    # flagged (hassmic's docs/plugins.md 3.3, 5.3): it hears every request and has a way out; the Echo asks for its
    # button twice, the second time on a screen of its own (plugin_store.c ps_second, in the same words)
    if "request.audio" in v["capabilities"] and any(c.startswith("net.") for c in v["capabilities"]):
        to = [w for c, w in (("net.internet", "the internet"), ("net.lan|net.udp|net.discover", "your network"), ("net.server", "the server you enter"))
              if any(k in v["capabilities"] for k in c.split("|"))]
        out.append(f'<p class="flag"><strong>Hears every request and can send what it hears to {e(" and ".join(to) if len(to) < 3 else ", ".join(to[:2]) + " and " + to[2])}.</strong> '
                   'The Echo asks for its action button twice for it, the second time on a screen of its own.</p>')
    # the broad ones (hassmic's docs/plugins.md 5.3; index.json's "broad"): named again, whatever else says them
    if v.get("broad"):
        out.append(f'<p class="flag">Broad: {e(", ".join(v["broad"]))}. Read what each lets it do above before you install it.</p>')
    # where it came from (5.3): built and attested by its own repository's GitHub Actions at that commit, in the
    # workflow the entry names, for the tag's push, which the index verified before it listed it; the bundle beside
    # the package lets anyone verify it again, with the very command the index ran (attest.command)
    repo = p["source"][len("https://github.com/"):] if p["source"].startswith("https://github.com/") else p["source"]
    words = ("Built by its author's own GitHub Actions from " if p["tier"] == "community" else "Built by its repository's GitHub Actions from ")
    if v.get("release") and v.get("attestation") and v.get("workflow"):
        tag = v["release"].rsplit("/", 2)[-2]
        name = f'{p["id"]}-{v["version"]}.hmp'
        out.append(f'<p class="dim small">Manifest digest <code>{e(v["manifest"])}</code>. {words}'
                   f'<a href="{e(p["source"])}" rel="noopener">its source</a> at <code>{e(v["commit"][:12])}</code>, in its workflow '
                   f'<code>{e(v["workflow"])}</code> for the push of the tag <code>{e(tag)}</code>, on a machine GitHub hosts, '
                   f'and attested so (<a href="{e(v["attestation"])}">provenance</a>): this index checked that before it listed it. '
                   'That says which workflow of which commit built it, not what the workflow does'
                   + (': nobody of hassmic\'s has read either' if p["tier"] == "community" else '')
                   + f'. To check it again: <code>{e(attest.command(name, repo, v["commit"], v["workflow"], tag, name + attest.SUFFIX))}</code> '
                   f'on <a href="{e(v["release"])}" rel="noopener">the release asset</a> '
                   f'(SHA-256 <code>{e(v["release_sha256"])}</code>; the package here is that one with the index\'s listing added).</p></div>')
    else:
        out.append(f'<p class="dim small">Manifest digest <code>{e(v["manifest"])}</code>, built from <code>{e(v["commit"][:12])}</code></p></div>')
    return "".join(out)


def plugin_card(p, revoked):
    tier = p["tier"]
    said = [CAP_WORDS[c](val, v.get("_page", {})) if c in CAP_WORDS else c for v in p["versions"] for c, val in v["capabilities"].items()]
    words = " ".join([p["id"], p["name"], p["description"], p["author"], tier] +
                     [c for v in p["versions"] for c in v["capabilities"]] + said).lower()
    out = [f'<article class="plugin" id="{e(p["id"])}" data-tier="{e(tier)}" data-words="{e(words)}">',
           f'<header><h2><a href="#{e(p["id"])}">{e(p["name"])}</a></h2>'
           f'<span class="tier {e(tier)}">{"Official" if tier == "official" else "Community"}</span></header>',
           f'<p class="desc">{e(p["description"])}</p>',
           *(['<p class="flag">Not reviewed: a community plugin. Nobody of hassmic\'s has read its code; what it may do is only what the Echo asks you to accept.</p>']
             if tier == "community" else []),
           f'<p class="who">By {e(p["author"])} · <a href="{e(p["source"])}" rel="noopener">source</a> · '
           f'author key <code title="Compare with what the Echo shows before you press its button">{e(fingerprint(p["author_key"]))}</code></p>']
    versions = sorted(p["versions"], key=lambda v: -v["version"])
    if not versions:
        out.append('<p class="none">No released version yet. When there is one, it is downloaded here.</p>')
    else:
        out.append(version_block(p, versions[0], revoked, True))
        if len(versions) > 1:
            out.append(f'<details><summary>{len(versions) - 1} older version{"s" if len(versions) > 2 else ""}</summary>'
                       + "".join(version_block(p, v, revoked, False) for v in versions[1:]) + "</details>")
    out.append("</article>")
    return "".join(out)


def page(index, revoked):
    """INDEX: index.json's object, each version with an extra "_page" (from its manifest: licence, memory, the
    labels of its file settings) that index.json does not carry.  REVOKED: revoked.json's"""
    plugins = sorted(index["plugins"], key=lambda p: (p["tier"] != "official", p["name"].lower()))
    when = datetime.datetime.fromtimestamp(index["serial"], datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    n = len(plugins)
    cards = "".join(plugin_card(p, revoked) for p in plugins) or '<p class="none">No plugin is listed yet.</p>'
    return PAGE.replace("@CARDS@", cards).replace("@WHEN@", e(when)).replace("@SERIAL@", e(index["serial"])) \
               .replace("@COUNT@", f"{n} plugin{'' if n == 1 else 's'}")


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>hassmic plugins</title>
<meta name="description" content="Plugins for hassmic, which turns Amazon Echos into Home Assistant voice satellites: what each may do, and its package to download.">
<style>
:root {
  --bg: #f6f7f9; --card: #ffffff; --text: #16191d; --dim: #5d6672; --line: #dfe3e8; --accent: #0b6bcb;
  --accent-text: #ffffff; --official: #0f7b4f; --official-bg: #e3f4ec; --community: #8a5a00; --community-bg: #fbf0d9;
  --warn: #9c3d00; --warn-bg: #fdeee3; --bad: #a3122a; --bad-bg: #fbe5e9; --code: #eef0f3;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #111418; --card: #1a1e24; --text: #e6e9ed; --dim: #9aa4b0; --line: #2c323a; --accent: #4fa3ff;
    --accent-text: #0b1520; --official: #5fd39e; --official-bg: #13301f; --community: #f0c060; --community-bg: #322710;
    --warn: #ffb27a; --warn-bg: #33200f; --bad: #ff8a9b; --bad-bg: #3a1219; --code: #232932;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main, .top-inner, footer { max-width: 860px; margin: 0 auto; padding: 0 16px; }
a { color: var(--accent); }
code { font: 0.86em ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: var(--code);
  padding: 0.1em 0.35em; border-radius: 4px; overflow-wrap: anywhere; }
.top { background: var(--card); border-bottom: 1px solid var(--line); padding: 28px 0 20px; }
h1 { margin: 0 0 4px; font-size: 1.7rem; letter-spacing: -0.01em; }
.lead { margin: 0 0 18px; color: var(--dim); max-width: 62ch; }
.search { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.search input { flex: 1 1 260px; font: inherit; padding: 10px 12px; border: 1px solid var(--line); border-radius: 8px;
  background: var(--bg); color: var(--text); }
.search input:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
.chips { display: flex; gap: 6px; }
.chips button { font: inherit; font-size: 0.9rem; padding: 7px 12px; border-radius: 999px; border: 1px solid var(--line);
  background: var(--bg); color: var(--text); cursor: pointer; }
.chips button[aria-pressed="true"] { background: var(--accent); border-color: var(--accent); color: var(--accent-text); }
.count { color: var(--dim); font-size: 0.9rem; margin: 18px 0 10px; }
.plugin { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 18px 20px; margin: 0 0 14px; }
.plugin header { display: flex; gap: 10px; align-items: baseline; justify-content: space-between; flex-wrap: wrap; }
.plugin h2 { margin: 0; font-size: 1.25rem; }
.plugin h2 a { color: inherit; text-decoration: none; }
.plugin h2 a:hover { text-decoration: underline; }
.tier { font-size: 0.78rem; font-weight: 600; padding: 2px 9px; border-radius: 999px; }
.tier.official { color: var(--official); background: var(--official-bg); }
.tier.community { color: var(--community); background: var(--community-bg); }
.desc { margin: 8px 0 4px; }
.who, .dim { color: var(--dim); }
.who { font-size: 0.92rem; margin: 0 0 12px; }
.small { font-size: 0.82rem; }
.none { color: var(--dim); font-style: italic; margin: 6px 0 0; }
.version { border-top: 1px solid var(--line); padding-top: 12px; margin-top: 12px; }
.vhead { display: flex; flex-wrap: wrap; gap: 4px 12px; align-items: baseline; }
.vname { font-weight: 600; }
.meta { color: var(--dim); font-size: 0.88rem; }
.get { display: flex; flex-wrap: wrap; gap: 8px 14px; align-items: center; margin: 10px 0; }
.download { display: inline-block; background: var(--accent); color: var(--accent-text); text-decoration: none;
  padding: 8px 14px; border-radius: 8px; font-weight: 600; }
.download:hover { filter: brightness(1.08); }
.sha { font-size: 0.82rem; color: var(--dim); display: inline-flex; gap: 6px; align-items: center; flex-wrap: wrap; min-width: 0; }
.copy { font: inherit; font-size: 0.78rem; padding: 2px 8px; border: 1px solid var(--line); border-radius: 6px;
  background: var(--bg); color: var(--text); cursor: pointer; }
.said { margin: 10px 0 4px; font-size: 0.92rem; }
.caps { margin: 0 0 8px; padding: 0; list-style: none; }
.caps li { padding: 4px 0 4px 12px; border-left: 3px solid var(--line); margin: 3px 0; }
.caps li.loud { border-left-color: var(--warn); }
.cap { display: inline-block; font: 0.78rem ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: var(--dim);
  min-width: 7.5em; }
@media (max-width: 560px) { .cap { display: block; min-width: 0; } .sha code { word-break: break-all; } }
.speaks { margin: 6px 0 0; font-size: 0.85rem; }
.flag { background: var(--warn-bg); color: var(--warn); padding: 8px 12px; border-radius: 8px; margin: 10px 0; }
.withdrawn { background: var(--bad-bg); color: var(--bad); padding: 8px 12px; border-radius: 8px; margin: 10px 0; }
details { margin-top: 10px; }
summary { cursor: pointer; color: var(--accent); }
.howto { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 4px 20px 10px; margin: 26px 0 14px; }
.howto h2 { font-size: 1.1rem; }
.howto ol { padding-left: 1.3em; }
.howto li { margin: 4px 0; }
footer { color: var(--dim); font-size: 0.85rem; padding-bottom: 40px; }
.hidden { display: none; }
#empty { color: var(--dim); }
</style>
</head>
<body>
<div class="top"><div class="top-inner">
<h1>hassmic plugins</h1>
<p class="lead">Programs that run beside <a href="https://github.com/Gamer92000/echo-dot-assist" rel="noopener">hassmic</a>
on an Echo, each in a sandbox, with only the powers you accept with the Echo's action button.
Plugins are experimental: switch them on under Plugins on the Echo's settings page.</p>
<div class="search" role="search">
<input id="q" type="search" placeholder="Search plugins: name, what it does, a capability" aria-label="Search plugins" autocomplete="off">
<div class="chips" role="group" aria-label="Tier">
<button type="button" data-tier="" aria-pressed="true">All</button>
<button type="button" data-tier="official" aria-pressed="false">Official</button>
<button type="button" data-tier="community" aria-pressed="false">Community</button>
</div>
</div>
</div></div>
<main>
<p class="count" id="count" aria-live="polite">@COUNT@</p>
<div id="list">@CARDS@</div>
<p id="empty" class="hidden">No plugin matches.</p>

<section class="howto" id="install">
<h2>Install</h2>
<p>An Echo that reaches the internet reads this list itself: on its settings page, Plugins, then "Browse plugins".
For one that does not, install from a file:</p>
<ol>
<li>Download the plugin's <code>.hmp</code> file here.</li>
<li>Open the Echo's settings page (the "Web UI" address in Home Assistant, or <code>http://&lt;the Echo's address&gt;:28931</code>),
then Plugins. Switch plugins on if they are off.</li>
<li>Choose "Install from file…" and pick the download. The Echo checks the package itself and shows what the plugin may do,
and the author key's fingerprint: it should read as it does here.</li>
<li>Press the Echo's action button to accept. Nothing is installed without it.</li>
</ol>
<p class="small dim">This page is not what keeps you safe: it is not signed. The Echo checks every package itself (its author's
signature, and the listing by this index's key) and refuses one that does not hold, whatever any page says.
An official plugin's update that asks for nothing new installs without the button; anything wider asks again.</p>
</section>
</main>
<footer>
<p>Listed @WHEN@ (serial @SERIAL@). The same list for programs, signed with the index key:
<a href="index.json">index.json</a> (<a href="index.json.sig">signature</a>), and what was withdrawn:
<a href="revoked.json">revoked.json</a> (<a href="revoked.json.sig">signature</a>).
Source of this list: <a href="https://github.com/Gamer92000/hassmic-plugins" rel="noopener">hassmic-plugins</a>.</p>
</footer>
<script>
(function () {
  var q = document.getElementById("q"), chips = document.querySelectorAll(".chips button"), tier = "";
  var cards = Array.prototype.slice.call(document.querySelectorAll(".plugin"));
  var count = document.getElementById("count"), empty = document.getElementById("empty");
  function apply() {
    var words = q.value.toLowerCase().split(/\s+/).filter(Boolean), shown = 0;
    cards.forEach(function (c) {
      var hit = (!tier || c.dataset.tier === tier) && words.every(function (w) { return c.dataset.words.indexOf(w) >= 0; });
      c.classList.toggle("hidden", !hit); if (hit) shown++;
    });
    count.textContent = shown === cards.length ? cards.length + (cards.length === 1 ? " plugin" : " plugins")
                                                : shown + " of " + cards.length + " plugins";
    empty.classList.toggle("hidden", shown > 0 || cards.length === 0);
  }
  chips.forEach(function (b) {
    b.addEventListener("click", function () {
      tier = b.dataset.tier;
      chips.forEach(function (o) { o.setAttribute("aria-pressed", o === b ? "true" : "false"); });
      apply();
    });
  });
  q.addEventListener("input", function () {
    apply();       /* the search in the address, to share; a plugin's own #id link is left alone until one types */
    try { history.replaceState(null, "", q.value ? "#q=" + encodeURIComponent(q.value) : location.pathname + location.search); } catch (e) {}
  });
  document.addEventListener("click", function (ev) {
    var b = ev.target.closest && ev.target.closest(".copy"); if (!b) return;
    var done = function () { var t = b.textContent; b.textContent = "Copied"; setTimeout(function () { b.textContent = t; }, 1200); };
    if (navigator.clipboard) navigator.clipboard.writeText(b.dataset.copy).then(done, function () {});
  });
  var m = /^#q=(.*)$/.exec(location.hash);
  if (m) { try { q.value = decodeURIComponent(m[1]); } catch (e) {} }
  apply();
})();
</script>
</body>
</html>
"""
