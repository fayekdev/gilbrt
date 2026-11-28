# gilbrt

An installable Python 3.10+ CLI for authorized website auditing, static client-side
secret detection, and opt-in synthetic AI application checks.

Website exclusions are enforced before audit traffic starts. See
[DO_NOT_TEST.md](DO_NOT_TEST.md) for the built-in blocked websites, scope guidance,
and additional domain exclusions. Absence from the list does not grant permission.

## Expanded discovery and staging checks

The crawler also discovers same-origin linked stylesheets, quoted CSS imports,
and embedded frames. Frames consume document depth; stylesheet imports and
explicit source maps consume the shared resource budget. All discoveries respect
robots rules, pacing, response-size limits and exact-origin redirect checks.

```bash
gilbrt --url https://staging.your-domain.example --confirm-authorized --sitemaps --max-pages 100 --max-depth 3 --exclude-domain production.your-domain.example
```

`--sitemaps` follows sitemap URLs declared in robots.txt, including sitemap indexes.
Sitemaps and their pages consume the same `--max-pages` budget; no sitemap paths
are guessed. Sitemap pages are independent depth-zero discovery seeds. When
`--ignore-robots` is used, robots.txt and its sitemap declarations are not loaded.
Additional exclusions use repeatable `--exclude-domain DOMAIN` arguments.

Active local/staging configurations can also include `http_checks` alongside
`isolation` and `prompts` (at most ten configured probes altogether):

```json
{
  "environment": "staging",
  "http_checks": [
    {"path": "/health", "method": "HEAD", "expected_status": [200],
     "required_headers": ["X-Content-Type-Options"]},
    {"path": "/api/public", "method": "OPTIONS", "expected_status": [200, 204]}
  ]
}
```

Run with `--active --active-config staging.json` in addition to the usual URL and
authorization arguments. Methods are restricted to GET, HEAD and OPTIONS on
explicit paths; redirects are refused and fresh sessions avoid inherited cookies.
These checks compare status codes and required header presence. Response bodies
and header values are withheld from findings. Configure only endpoints whose
documented behavior is safe for these methods; even GET can cause side effects
in a poorly designed application. Active checks are CLI-only. CSS/frame discovery
and the built-in website exclusions also apply to GUI audits.

## Graphical interface

The GUI matches the website's dark/sage palette and provides Audit, Findings,
Resources and Settings views. Findings can be filtered by severity and category.
Matched values are masked until **Show matched value** is selected in a finding;
exports remain redacted. In **Export**, select a format and choose **Download**
or **Copy to clipboard**. Clipboard export copies that format as text using the
server's redacted export, even after revealing evidence locally.

Open **New audit → Audit options** to set the resource limit, crawl depth,
resource size, request delay, sitemap discovery, robots handling and AI review
limits for that run. **Additional URLs** accepts explicit
same-origin resources. Save defaults under **Settings → Audit limits** and
**Local model**. Domain exclusions stay in Settings and apply to each audit;
they include their subdomains. Sitemap discovery
uses declarations in robots.txt and shares the resource budget; ignoring
robots.txt also disables sitemap discovery. Website-only options are hidden for
offline file audits. Restart `gilbrt --gui` after updating to load the new options.
The GUI checks its server protocol before enabling audits and shows a restart
instruction if an older process is still serving updated interface files.

Checks are grouped under a collapsible selection panel. Slide **Slide to
authorize** fully, then click the filled green pill to start. The entire pill
changes color from red through amber to green as it fills. Moving the slider
alone does not start an audit. Editing the setup or switching the
source resets confirmation. Severity dials show each severity's share of reported
findings; click a dial to filter the findings. They are not a security score.

The running-audit popup shows an **Elapsed** counter in `MM:SS` (or `HH:MM:SS`
for longer audits). It updates every second while network/model calls are pending,
restores the elapsed duration after a reload, and keeps counting during
cancellation until the backend has actually stopped. Restart the GUI server after
updating to load its timer asset and live duration reporting.

### Keep CLI results for the GUI

Add `--save-gui` to an authorized CLI audit, then open the GUI later:

```bash
gilbrt --url https://staging.your-domain.example --confirm-authorized --save-gui
gilbrt --gui
```

The audit command finishes normally. Its redacted result is saved atomically to
`GILBRT_RUNTIME/last-cli-report.json` (normally `.runtime/last-cli-report.json`).
Each `--save-gui` run replaces that one saved CLI report; use `--output` as well
to keep named history. This is opt-in: ordinary CLI audits do not save a GUI report.
Raw source bodies, terminal `--show-secrets` values, session tokens and API keys
are not added to this saved result. Restored reports cannot reveal plaintext
matched values. POSIX temporary files use private permissions; Windows uses the
runtime directory's ACLs. Keep that directory private to your account.

The GUI restores the saved report on startup. If the GUI was already open, reload
the page after the CLI audit to pick up a newer saved result. It will not interrupt
an audit in progress or replace a newer completed in-memory GUI audit with an
older file. Normal GUI audits still keep their results in memory only.

To view an existing JSON export without auditing the website again:

```bash
gilbrt --gui-report audit.json
```

Only gilbrt JSON reports up to 32 MiB and 50,000 findings are accepted. Imported
data is treated as untrusted text, its assessment is recomputed, and no discovered
URL is fetched. Missing or invalid explicitly selected reports fail with a clear
error; an invalid default saved report leaves the GUI available for a new audit.

### Headless remote GUI through SSH

On the remote machine, start the GUI without trying to launch a browser:

```bash
gilbrt --gui --no-browser
```

On your own computer, keep an authenticated SSH forwarding session open:

```bash
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:4174:127.0.0.1:4174 user@remote-host
```

Open `http://127.0.0.1:4174` locally. The GUI remains bound to remote loopback; SSH
provides the authenticated encrypted connection. Use matching local and remote
ports so the GUI's exact Host/Origin checks continue to work. If 4174 is occupied,
use `--gui-port 4175` and change all three ports in the forwarding command to 4175.
The GUI session token and cross-site request checks remain enabled. SSH forwarding
uses OpenSSH's documented [`-L` local forwarding](https://man.openbsd.org/ssh.1#L).

### Third-party AI and public tunnel design (planned)

Third-party inference is not enabled by these report/viewing commands. The proposed
next step is an explicit provider adapter alongside the existing bundled/Ollama
backends, with the same syntax-grounded candidate IDs and local evidence checks.
Provider/model selection must be separate from local model tags. API credentials
stay in server environment variables or an OS credential store, never browser
settings, report files, command-line arguments or prompt logs.

Before a remote review, the operator should see which provider/model is selected,
what source excerpts would leave the machine, and the request/token budget. Start
with minimal candidate context and locally substituted credential placeholders;
keep the original values only in local memory. Sending raw source would require
a separate explicit choice. Apply timeouts, bounded responses, request/token caps
and budget-aware retries. No automatic cloud fallback when local inference fails.
Use provider-supported structured responses where available, then independently
validate candidate IDs and source evidence. A schema controls response shape; it
does not prove the model's classification. See [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
for one provider's schema mechanism. Compare each provider against the same seeded
lab for detections, misses, incremental false alarms, coverage, latency and usage.

SSH is the first supported remote-access path. Future managed options could use
[Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve) within a
private tailnet, or a tunnel protected by
[Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/).
These integrations are not wired into gilbrt yet. They need an explicitly configured
external origin, authentication covering the entire UI including bootstrap,
appropriate identity-token verification, and session/CSRF protections behind the
proxy. A GUI bootstrap token is not a substitute for remote user authentication.
Do not expose an unauthenticated quick tunnel or bind the service to `0.0.0.0` to
work around Host/Origin checks. No public tunnel or provider account is created
by the commands above.

### Offline use

After installing gilbrt and its Python dependencies, `gilbrt --gui` works without
internet. Styles, icons, scripts and system fonts are bundled; there are no CDN,
analytics, cloud inference or update requests at GUI startup. Keep the local Python
server running while using the interface.

Choose **New audit → Local files** to inspect HTML, JS/TS, JSON, source maps, CSS or
TXT files without crawling or making target requests. Select up to 100 text files,
16 MiB combined; the configured resource count and per-resource size caps also apply.
Files are processed in memory and are not executed or automatically saved. Report
resource references use digests rather than original filenames. This mode is
available in the GUI; website CLI auditing is unchanged.

Static file checks, finding review, settings and report exports work offline.
Optional model reviews work offline once the bundled model is installed, or when
an installed local Ollama model and its loopback server are available. Model
installation, updating, HIBP queries and auditing public websites require internet.
Headers, TLS and breach checks are disabled for local files. Website audits against
reachable localhost/LAN targets need only that local network.

In Codespaces, files selected in the browser are sent to your running gilbrt
instance there. Fully disconnected use requires gilbrt to be installed and running
on your own machine.

### Launch

Run `gilbrt --gui` (or `python -m gilbrt --gui`) to open the local browser interface.
From this checkout in PowerShell: `.\.venv\Scripts\python.exe -m gilbrt --gui`.
The server listens only on `http://127.0.0.1:4174`; use `--gui-port 4175` if that
port is occupied. Keep the terminal running and use Ctrl+C to stop it.

In **GitHub Codespaces**, run `gilbrt --gui`, forward its port in the **Ports** tab,
and leave visibility **Private**. Open the forwarded HTTPS URL printed by gilbrt.
The GUI recognizes only this codespace's exact forwarded hostname using GitHub's
`CODESPACE_NAME` and `GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN` environment variables.
Other forwarded hostnames/origins are rejected; API session tokens remain required.
Codespaces may independently rewrite Host or Origin to the exact HTTP loopback
address and port; those upstream values are accepted alongside the forwarded origin.
No local browser is launched inside Codespaces. The forwarded port protocol should
remain **HTTP** because the upstream Python server serves HTTP; GitHub provides
HTTPS for the browser-facing URL. Do not publish the port: authentication for remote
access is provided by Codespaces' private forwarding.

The GUI runs the same audit engine as the CLI. Start an authorized audit, select
checks and an optional installed local model, view live stages and resource counts,
inspect/filter findings, review coverage, and export JSON, HTML, CSV or AI
Markdown. Discovery has no known total, so progress shows stages and actual counts
instead of an estimated completion percentage. Coverage percentages describe only
attempted resources, not the entire site. Cancellation waits for an in-flight
network or inference request, then stops before the next request; previous completed
results remain available. Open a finding to see its matched values in the local
detail view; exported reports remain redacted. Revealed evidence stays in server
memory for the completed report and is fetched only when a finding is opened.
Active staging probes remain CLI-only.

Findings and coverage lists show 50 entries per page. Progress polling transfers
only job updates when the report has not changed, and slows down in background
tabs. The interface uses circular CSS dials without continuous animations or
full-screen blur effects.

Open **Settings** to save crawl limits, request pacing, default checks, export
format, model selection, the loopback Ollama address, AI batch budget, and bundled
candidate limits. Settings apply to future audits and are saved to
`GILBRT_RUNTIME/gui-settings.json` (normally `.runtime/gui-settings.json`). Audit
targets, findings and source bodies are not automatically written to disk. An
explicit CLI `--save-gui` run saves its redacted report as described above. Normal
GUI results stay in server memory until replaced or the server stops.

The model dropdown lists the installed bundled CPU model and installed local
Ollama models; cloud-backed entries are excluded. Use `gilbrt --install-models`
to install another supported model, then **Refresh models**. Audits never download
models. The GUI starts with static checks only; explicitly choose a model to use
local AI. HIBP catalogue checks use `HIBP_API_KEY` from the launch environment,
when present; the GUI does not store that key.

## Local accuracy benchmark

For a harder integration test, use the seeded multi-resource laboratory:

```powershell
.\.venv\Scripts\python.exe -m scripts.benchmark_lab --with-ai
```

This creates 46 content cases (28 intended findings and 18 harmless controls),
six header contracts, six explicitly configured synthetic API/AI endpoint checks,
and robots/cross-origin traps. Credentials, resource paths, import ordering and
line padding change with `--seed`; the default is `20261127`. A credential only
scores when the detector recovers its entire expected value in the correct
resource and category. Matching a fragment, repeating observations or reporting
missing headers cannot increase the content score. Unreached positive cases count
as misses; unreached harmless controls never count as true negatives.

The lab runs separate resource-count, depth and per-file-size limit profiles,
then a broad static audit, a static audit with an explicitly supplied runtime API
URL, and (with `--with-ai`) the actual installed bundled model. `--model TAG` selects
an installed Ollama model instead. No model is downloaded automatically. Reports
distinguish discovery misses from analysis misses and record AI-only gains and
false alarms. Complete results, redacted reports and the ground-truth manifest are
saved under `.runtime/hard-lab/`; change the destination with `--output-dir`.

To use the lab as a local target in the GUI, keep this command running:

```powershell
.\.venv\Scripts\python.exe -m scripts.benchmark_lab --serve --port 8765
```

Audit `http://127.0.0.1:8765/` with a resource limit of 128, depth 4 and sitemap
discovery enabled to reproduce broad passive discovery. Active checks require the
generated `active-config.json` and synthetic environment values shown in
`scripts/benchmark_lab.py`; the automatic benchmark configures them itself. The
server binds only to loopback. Ctrl+C stops it. Do not deploy this deliberately
vulnerable lab to public hosting.

Its cases include custom password callbacks, Unicode hydration JSON, split and
encoded secrets, source maps reached through CSS imports, nested iframes, deep
links, sitemaps, large embedded assets, browser-input aliases, cross-module and
mutable data flow, runtime-only APIs, and harmless UI/documentation examples.
Known unsupported cases remain in the denominator. HTTP/record/AI endpoint probes
use deterministic synthetic responses; the chat stubs do not establish an actual
LLM's prompt-injection resistance. This lab does not test SQL injection or execute
target JavaScript, validate real provider credentials, or prove XSS exploitation.

Reports start with a coverage assessment and distinguish credential candidates
from header/TLS configuration observations. A header-only result does not establish
that passwords were checked successfully. A run that scans zero source resources
is marked `source_scan_failed`: the CLI still exports its diagnostics but exits 1,
and the GUI marks the scan incomplete. Partially inspected sources or interrupted
AI coverage are labeled partial; a finished bounded crawl is never proof that the
whole application is secure. No recorded observations are hidden by this summary.

Run a deliberately vulnerable synthetic website bound only to `127.0.0.1`, audit
it through the real CLI, and compare findings against predefined ground truth:

```powershell
.\.venv\Scripts\python.exe -m scripts.benchmark_demo
.\.venv\Scripts\python.exe -m scripts.benchmark_demo --with-ai
.\.venv\Scripts\python.exe -m scripts.benchmark_demo --extended --with-ai --output-dir .runtime/extended-benchmark
```

On Linux or with an activated environment, use `python -m scripts.benchmark_demo`.
`--with-ai` uses the already installed bundled model; it does not install a model.
The temporary server shuts down after the audits. Reports, CLI logs, and per-case
results are written to `.runtime/demo-benchmark/`; `--output-dir` changes that path.

The original content fixture contains 42 cases (25 exposures and 17 harmless
controls). `--extended` adds 31 connection, form and browser-code cases, for 73
content cases (44 intended findings and 29 harmless controls). Both modes include
15 header cases and four configured synthetic record-isolation checks. Some of
the extended findings, such as token storage and wildcard messages, require
contextual review and do not establish an exploitable vulnerability.
Precision and recall count content cases, not repeated findings. Header and
isolation outcomes are reported separately. All content resources must be checked
in `all_case_resources_scanned` before interpreting scores. The runtime-only secret
is deliberately outside passive discovery and remains in the recall denominator.

On 2026-11-23, the initial implementation detected 21/25 exposure cases and
flagged 1/17 harmless controls (95.5% precision, 84% recall). After adding bounded
constant reconstruction, both static scanning and static plus the bundled Qwen
0.5B model detected 24/25 with the same false alarm (96% precision and recall).
Concatenated passwords, encoded passwords and a computed gate are now detected.
The remaining miss is an unlinked runtime-fetched secret. The false alarm is a
deliberately public, provider-shaped documentation key; token syntax cannot prove
credential validity. The extended corpus detected 43/44 intended findings with
1/29 harmless controls flagged (97.7% precision and recall). AI completed without
errors or budget exhaustion, but added no case detections on either corpus.
All 15 header cases and four isolation checks passed after the improvements.

The earlier easy corpus did not establish performance on other websites. A harder
retest on 2026-11-25 used 27 source cases, including returning/arrow validators,
embedded hydration data, alternate password names, split provider keys, aliased
browser input and harmless password instructions:

```powershell
.\.venv\Scripts\python.exe -m scripts.benchmark_demo --challenge --with-ai --output-dir .runtime/refinement-after
.\.venv\Scripts\python.exe -m scripts.benchmark_demo --holdout --with-ai --output-dir .runtime/refinement-holdout
```

Before refinement, both static checks and bundled AI found 1/14 intended findings,
with five false alarms among 13 harmless cases. After refinement, static checks
found 8/14; static plus the actual bundled CPU model found 12/14, with one false
alarm among the same 13 controls. The four additional detections came from the
broader AI review pool and remain unconfirmed review candidates. The separate
20-case variant corpus found 6/10 with static checks and 8/10 with AI, but AI also
added a false alarm: combined results flagged 2/10 harmless controls. This variant
set was evaluated after refinement, not used for the before/after comparison.
These remain small authored fixtures, not an independent real-world benchmark.

Known misses in both harder sets are a secret reconstructed across function
scopes and a secret available only from an unexecuted runtime fetch. Provider-shaped
documentation examples can still be flagged, and the tiny model can misclassify
ordinary UI predicates. JSON results include every miss/false alarm, resource
coverage, model failures and (for new runs) AI-only case contributions.

These are synthetic development results, not independent certification or an
estimate of accuracy across arbitrary websites. Provider strings and the private
key marker are inert detection fixtures, not valid credentials. The benchmark
does not assess SQL injection, XSS exploitation, real TLS certificates, breach
catalogues, or actual model prompt-injection resistance. HSTS warnings are excluded
from header scoring because the demo intentionally uses loopback HTTP.

## Install and run

If the command still points at a deleted or moved checkout, repair it from the
checkout you want to use:

```bash
cd ~/PROJECTS/gilbrt
bash install.sh --relink
hash -r
gilbrt --gui --no-browser
```

`--relink` rewrites the generated `~/.local/bin/gilbrt` launcher to this checkout's
`bin/gilbrt`. It backs up a previous generated launcher under a unique
`gilbrt.backup.*` name, preserves argument quoting, and does not download models,
reinstall Python dependencies or edit shell startup files. `--prefix DIRECTORY`
can select a different command directory. Unrelated commands and modified launchers
are left untouched. If the new checkout has no working Python environment, run
`bash install.sh` afterward; a normal install can also repair a stale owned launcher.

From Bash on Linux or Git Bash on Windows:

```bash
bash install.sh --add-path
source ~/.bashrc
gilbrt
```

This installs a normal `gilbrt` terminal command. Add `--with-ai` on a new machine
to choose a local model interactively, or use `--ai-model bundled` for the low-RAM
Qwen2.5-Coder 0.5B model and `--ai-model ollama:qwen2.5-coder:0.5b` for Ollama.
The command opens the website field, checkboxes, export and authorization flow.
For the installed small model with visible local values:

```bash
gilbrt --interactive --local-model bundled --show-secrets
```

Without installing the command, run `bash gilbrt.sh` from this checkout.
The Bash command uses the existing Python audit engine and native CPU model;
it requires no PowerShell or manual virtual-environment activation.
Interactive Git Bash sessions automatically use `winpty` when available so the
native Windows Python checkbox interface receives a real terminal. Linux uses
its terminal directly.

If Debian/Ubuntu reports that `ensurepip` is unavailable, install the venv package
matching your Python version (for example `python3.13-venv`). Then run the project
installer again from its existing checkout. It repairs an existing environment
that has Python but lacks pip. After a website bootstrap failure, the checkout is
normally `${XDG_DATA_HOME:-$HOME/.local/share}/gilbrt`; the bootstrap preserves it.

PowerShell remains available:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
gilbrt --url https://your-authorized-site.example --confirm-authorized
python -m gilbrt --url https://your-authorized-site.example --confirm-authorized --output audit.html --format html
```

For the guided flow, run just `gilbrt` (or `python -m gilbrt`). From an unactivated
PowerShell environment in this project, run:

```powershell
.\.venv\Scripts\gilbrt.exe
```

The wizard asks for the website URL, search categories, whether to export a full
report, report format/path, whether to copy the redacted report to the clipboard,
local secret-reveal preference, and authorization.
No network requests are made until setup finishes and authorization is confirmed.
Declining authorization cancels the audit. Ctrl+C cancels setup cleanly. Bare
invocation requires an interactive terminal; scripts should use explicit flags.

Passive mode sends GET requests and a verified TLS handshake. It never executes
JavaScript, submits forms, guesses paths, tests credentials, injects SQL/XSS, or
validates discovered secrets against providers. Source maps are fetched only when
explicitly referenced by an already fetched same-origin script or stylesheet. No external
scripts are downloaded. Exact scheme and netloc are enforced at each redirect;
endpoint inventory only records references already exposed in fetched source and
does not request guessed or discovered API paths. An HTTP-to-HTTPS redirect
therefore needs a separate audit of the HTTPS target.

## Options

Install local AI models after installing gilbrt:

```bash
gilbrt --install-models
```

This checks available RAM, CPU architecture, OS and whether Ollama is installed,
shows estimated model downloads and memory needs, and lets you choose a suitable
model. The largest model within the conservative RAM estimate is recommended;
without Ollama, the supported bundled CPU model is recommended. These are CPU/RAM
estimates, not speed or GPU compatibility guarantees. Unknown or insufficient
available memory prevents installation; close other apps and retry.

```bash
gilbrt --list-models                         # preview only; no downloads
gilbrt --install-models bundled              # explicit bundled installation
gilbrt --install-models ollama:qwen2.5-coder:1.5b
```

Supported choices are the bundled Qwen2.5-Coder 0.5B model and Ollama
Qwen2.5-Coder 0.5B, 1.5B, 3B and 7B. Ollama choices require an existing local
Ollama installation and running server. Successful installation saves the default
model for the audit wizard; enable `local-ai` there or pass `--local-model TAG`.
Scripts must specify a model explicitly. `GILBRT_RUNTIME` can select the bundled
runtime and default-model directory. Normal audits never download models.

- `--confirm-authorized`: required in scripts; the guided flow asks for equivalent
  confirmation interactively. Prints the authorization disclaimer before requests.
- `--max-depth 2`: document link depth; root is depth zero. Script assets do not add depth.
- `--max-resource-mb 16`: maximum decompressed MiB per website resource (1-64).
  Oversized resources produce a coverage finding and are not counted as scanned.
- `--max-pages 25`: total resource attempts including documents, scripts and source maps.
  Robots requests and up to five followed redirects per resource are additional.
- `--rate-limit 1.0`: finite nonnegative seconds between request starts, including redirects.
- `--ignore-robots`: approved internal environments only. Otherwise robots applies to
  documents, scripts, source maps, active endpoints and redirect destinations.
  Missing robots (404/410) permits crawling; other errors deny crawling. Integer
  Crawl-delay values are honored if greater than the requested delay.
- `--hibp-api-key`: optional; prefer the `HIBP_API_KEY` environment variable to avoid
  storing credentials in shell history/process arguments.
- `--output PATH --format json|csv|html|ai`: save a report; existing output is overwritten.
  `ai` writes a Markdown report designed to attach to or paste into an AI coding tool.
- `--copy-report`: copy the same complete, redacted report to the local clipboard.
  Linux requires `wl-copy`, `xclip`, or `xsel`; headless systems can use `--output`.
- `--update`: update a clean Git installation using a fast-forward-only pull and
  refresh the editable Python package. It refuses tracked local modifications.
- `--local-model bundled|TAG`: use the installer-selected bundled model or an
  installed Ollama model tag. The installer accepts `--ai-model bundled|ollama:TAG`.
- `--active --active-config FILE`: opt in to explicit staging probes described below.

## Choose what to search for

Open a checkbox menu (the same menu is opened by bare `gilbrt`):

```powershell
.\.venv\Scripts\gilbrt.exe --interactive --confirm-authorized
```

The menu prompts for the target URL, categories, and whether to reveal matched
values in the local terminal. Search categories appear as selectable `[x]` / `[ ]`
boxes. All checks start selected. Use Up/Down to move, Space to toggle a box,
`A` to select/clear all, and Enter to continue. At least one check must be selected.
Ctrl+C cancels setup before any requests. Scripts can still use comma-separated
category names with `--search`.
Interactive mode requires a terminal; CLI flags work in scripts and PowerShell.

```powershell
# Password detection with deeper discovery and an HTML report:
.\.venv\Scripts\gilbrt.exe --url "https://your-authorized-site.example/" --confirm-authorized --search passwords --max-depth 4 --max-pages 100 --output audit.html --format html

# Also search provider keys and tokens; explicitly reveal matches locally:
.\.venv\Scripts\gilbrt.exe --url "https://your-authorized-site.example/" --confirm-authorized --search passwords,api-keys,tokens --show-secrets

# Include a known, approved resource that is not linked from the homepage:
.\.venv\Scripts\gilbrt.exe --url "https://your-authorized-site.example/" --confirm-authorized --search passwords --include-url /public-config.json
```

Categories: `passwords`, `access-codes`, `api-keys`, `tokens`, `private-keys`, `entropy`, `comments`,
`endpoints`, `headers`, `tls`, `breaches`, `connections`, `browser-code`, `forms`.
Default: `all`. `--search` can be repeated. Selecting
`breaches` still requires a HIBP key. Active probes require their separate flags.
`local-ai` is an additional opt-in checkbox, initially unchecked and excluded from
the CLI `all` selection. It requires an installed local model.

Password checks do not require high entropy: they find literal
`password`, `passwd`, `pwd`, `pass` and prefixed assignments such as `dbPassword`
or `DB_PASSWORD`, including `passwordValue`/`passwordInput` forms, prefilled password-related HTML fields, and password data
attributes. JavaScript assignments can contain string/numeric literals or supported
constant expressions. Bounded reconstruction supports string concatenation,
literal `atob`, `String.fromCharCode`, literal array `.join`, and eligible earlier
`const` bindings in the same block. Mutable values, unknown calls, cross-scope
references, comments and quoted code examples are skipped. Array bindings are
skipped when another use could mutate or expose the array. Reconstruction has
size, depth and node limits, and rejects explicit shadows of decoder built-ins.
It does not execute JavaScript or establish runtime behavior; external monkeypatches
and complex obfuscation remain outside coverage.
Visible password fields and plain-text `password: value` fields are also checked.
HTML tables with a password-labeled first column are also checked. Source-map
`sourcesContent` is decoded before scanning, including its escaped source text.
Empty values, explicit placeholders, environment templates and masked values are
filtered out. Findings remain candidates; values are never tried against a login service.
Nested JSON and HTML JSON hydration scripts are parsed explicitly for password
properties. Visible password fields must be complete fields within a text block;
unrelated labels, links and help text are not concatenated into a credential.
Custom dialog callbacks are also checked when the compared value comes from the
callback's parameter and the dialog call explicitly supplies a `password` input
type or a recognized access-code label. For example, an unnamed `v.trim()` check
that sets an admin flag is still a credential candidate. Reports identify this
as a password-input callback comparison. Array filters, display-template
conditions and common status values do not enter the broader AI-only pool;
explicitly named password checks remain eligible even for weak status-like values.
HTML meta charset declarations are honored when the HTTP header omits a charset,
so non-ASCII source strings are not silently decoded using the HTTP text default.
Provider-pattern checks also inspect bounded reconstructed credential assignments,
so a split or base64-encoded key can match the same provider rules as a raw key.

`connections` detects credential-bearing database, cache, queue and HTTP URLs in
already fetched content. Connection strings stay masked in reports and are never
used to connect to a service. `--show-secrets` retains its explicit local reveal
behavior for these candidates.

`browser-code` uses parsed JavaScript to flag direct browser-controlled values
such as `location.hash` reaching HTML insertion, `document.write`, or string-code
execution sinks. It also flags sensitive browser-storage key names and wildcard
`postMessage` destinations as Info review candidates. It does not infer arbitrary
data flow or claim XSS exploitability. Unknown calls, including sanitizer calls,
are outside this direct-flow detector; absence of a finding does not certify them.

`forms` checks password forms for GET submission, HTTP destinations and changes
of origin, including submit-button overrides. It also checks HTTP resource
references on HTTPS pages. `headers` additionally reviews CORS policy combinations,
cache variation, cookie-prefix requirements and version disclosure. CORS, cookie
and disclosure checks also apply to fetched non-HTML resources, without demanding
HTML-only browser defenses on JSON or scripts. All new categories are included
in `all` and the guided checkbox menu.

The `access-codes` check also detects client-side gates such as
`if (code === "4827")`, `if (pin !== 7392)` and reversed comparisons such as
`"example-gate" === enteredCode`. It recognizes named access-code assignments,
JSON properties, property lookups and simple method chains. Password comparisons
are also checked when only `passwords` is selected. Source-map embedded sources
are scanned after decoding. These checks do not require high entropy.

```powershell
.\.venv\Scripts\gilbrt.exe --url "https://your-authorized-site.example/" --confirm-authorized --search access-codes,passwords --show-secrets
```

In the checkbox menu, choose `access-codes` (selected by default with all checks).
Password findings are Critical; other comparisons with descriptive code names are Warning candidates. Generic
or minified comparisons require access-specific actions in their enclosing branch,
such as `if(x === "example-gate") unlock()`, and remain Info review candidates.
An arbitrary string comparison alone is ignored. Generic `code` assignments and
HTTP/error/keyboard code properties are ignored; a bare `code` comparison needs
a PIN-shaped numeric value or an access-specific branch. UI labels, credential
metadata properties and ordinary status/type checks are excluded.
The detector skips JavaScript comments, quoted code examples and dynamic template
strings. Tree-sitter parses JavaScript syntax, including regex literals and
template substitutions, to avoid confusing quotes with comparisons. It does not evaluate code;
computed/obfuscated codes, arbitrary data flow, and code absent from fetched
resources can be missed. No discovered code is submitted or tested against a gate.

Discovery also follows same-origin module-preload links and literal JavaScript
module imports, plus linked JSON/plain-text resources. `--include-url` accepts
explicit same-origin paths/URLs and obeys robots and the total resource cap. It
does not generate guessed configuration paths. Use `--max-depth` and `--max-pages`
to widen coverage. JavaScript is not executed: passwords fetched only at runtime
from an unlinked API or requiring authentication may remain outside coverage.
When the resource budget leaves queued references unvisited, the report records
`Resource budget reached`. Resource inventory entries distinguish JavaScript and
JSON and count content candidates. `metadata.credential_search` explicitly records
the credential checks requested, candidates found and source resources inspected;
no candidates is an inconclusive result, not a clean bill of health.

`--show-secrets` is an explicit exception to terminal redaction: matched values
appear in full in their terminal table rows, replacing the masked marker.
Password findings are Critical. Model-reviewed named access-code candidates are Warning;
broader AI-only validator candidates remain Info review observations.
nearby words such as `password` or `admin` do not promote an unrelated value to a
Critical password finding. Severity is triage priority, not proof of exploitation.
Terminal control characters are displayed as escapes. Recording/scrollback may retain values.
JSON/CSV/HTML reports always remain redacted. Do not redirect a revealed terminal
session to a public log. Default output stays masked. URL validation rejects
duplicate `https://` prefixes before making requests.

## Bash command and limited hardware

gilbrt is a foreground terminal command with a Python engine and a Bash launcher.
It uses the same checkbox interface from Bash; it does not require a GUI or a
continuously running AI daemon.

On Linux with Python 3.10+ and venv support:

```bash
bash install.sh --with-ai --add-path
source ~/.bashrc
gilbrt
```

The installer uses a per-project virtual environment and installs a per-user
command into `~/.local/bin` (or `--prefix DIRECTORY`). It refuses to overwrite an
unrelated existing command. `--add-path` adds an owned block to `.bashrc`, backing
up an existing file before changes. A fresh Bash home gets a login loader;
existing login startup files remain unchanged. With a terminal, `--with-ai` asks
you to choose the bundled low-RAM model or Ollama Qwen 0.5B. For automation, pass
`--ai-model bundled` or `--ai-model ollama:qwen2.5-coder:0.5b`. Omit AI options
for static-only installation. On
Windows, the existing virtual environment works from PowerShell and Git Bash:

```powershell
.\.venv\Scripts\gilbrt.exe --interactive --local-model bundled
```

```bash
bash bin/gilbrt --interactive --local-model bundled
```

The explicit small-AI installer is also available separately:

```bash
python scripts/install_small_ai.py
```

This installs the official **Qwen2.5-Coder-0.5B-Instruct Q4_K_M GGUF** (491,400,064
bytes, about 469 MiB) and a pinned CPU-only llama.cpp runner in `.runtime/`.
Downloads are streamed, resumable and SHA-256 verified. Windows/Linux x64 and
ARM64 download paths are supported; Linux needs the system libraries expected by
the official Ubuntu binary. This is not a 32-bit-hardware package. Models and
native binaries are excluded from the source ZIP; the explicit installer fetches them.

Select `local-ai` and model **`bundled`**. Its constrained settings are one CPU
thread, one inference slot, a 2,048-token context, 32-token processing batches,
at most 64 generated tokens per batch and one candidate-review batch at a time.
All scripts in a fetched resource are inspected with a small native JavaScript
parser before spending model tokens. Up to 256 credential-like candidates per
resource are ranked across those scripts by default. Each model batch reviews up to three short, bounded
source excerpts, returning candidate IDs only. Embedded assets and irrelevant
configuration blocks do not consume the inference budget. This also handles
minified ternary and short-circuit comparisons that the old text lexer missed.
The AI review pool also includes syntax-grounded returning validators and
security-related branches outside the stricter static pool. Each prompt identifies
the specific candidate value and operator. UI/protocol predicates are filtered
where recognizable; the model can still misclassify them. Findings already emitted
by a static credential check are not repeated as additional AI discoveries; metadata
counts these omitted duplicates. Candidate identifiers prevent invented values
from entering reports but do not establish the meaning of a literal or immunity
to source-based prompt injection.
By default, all retained candidates are reviewed sequentially; there is no two-batch
stop. This improves larger-site coverage without loading a bigger model or running
inference in parallel. Longer audits take more time. The spinner reports current
batch progress. Repeated source contexts reuse a bounded cache of at most 4,096
model decisions, avoiding redundant inference across pages.

`--ai-max-batches N` sets an optional global inference-call cap; `0` reviews all
retained candidates and is the bundled default. `--ai-max-chunks` remains an alias.
`--ai-candidate-limit N` controls the per-resource queue, from 24 to 4,096. The
default queue of 256 and bounded cache add little memory compared with model weights.
If the queue fills, the report records that coverage gap; increase the limit for
large bundles. Source/crawl depth and page limits remain explicit.

```bash
gilbrt --interactive --local-model bundled --show-secrets --ai-max-batches 0 --ai-candidate-limit 1024
```
No GPU is used. The model starts on demand and its owned runner stops after the
audit, including error/interruption cleanup.

Before loading, gilbrt checks available physical memory where supported. If less
than 768 MiB is free/available, it skips optional AI and records a coverage finding;
selected static checks continue. This is a conservative startup check, not a hard
memory cap. HTML parsing, large scripts, OS usage and other applications also need
RAM. A machine with less than 2 GB total RAM may still be unable to load the model.

Observed memory/timing for the authorized page audit is recorded in
`.runtime/memory-budget.json`: a 1 GiB Windows job-wide committed-memory cap was
enforced over the verifier, gilbrt and inherited runner processes. The test scanned
the page, reviewed all 14 retained candidates in five batches without an AI failure,
and observed a sum of process peak resident memory of about 684 MiB. Commit and resident memory are
different measurements. The cap does not include the OS, and the observed RSS is
sampled independently. The host has 16 GB RAM; this test
does not certify speed or compatibility on the target low-memory processor. Tiny
models produce both missed findings and false positives. Accepted values require
syntax-verified credential/comparison candidates; their
meaning remains a review candidate. Static checks stay available without AI.

The source archive includes the installer and launcher. Bash syntax, command
launching and installation into a test prefix are checked with Git Bash; the Linux
native runtime has not been executed on this Windows host.

## Optional Ollama code model

gilbrt supports an existing Ollama code model; no model training is required. A
small starting option is `qwen2.5-coder:1.5b` (approximately a 986 MB download in
the official Ollama catalogue). Small models can miss access logic or flag ordinary
constants, so use their findings alongside static checks and coverage metadata.

Install [Ollama for Windows](https://ollama.com/download/windows), then download
the model explicitly:

```powershell
ollama pull qwen2.5-coder:1.5b
```

Start your local Ollama server with cloud inference disabled. Quit any existing
Ollama tray server first if its port is already in use, then in a separate terminal:

```powershell
$env:OLLAMA_NO_CLOUD = "1"
ollama serve
```

In gilbrt's checkbox menu, select `local-ai` and enter the installed model tag, or:

```powershell
.\.venv\Scripts\gilbrt.exe --url "https://your-authorized-site.example/" --confirm-authorized --local-model qwen2.5-coder:1.5b --output gilbrt-report.md --format ai
```

The adapter sends source only to an HTTP literal loopback IP endpoint (default
`http://127.0.0.1:11434`); `--ollama-url` can select another loopback port.
It rejects model metadata marked as remote and uses no cloud fallback or
automatic model downloads. Run only a local server you trust; its own logging and
configuration control whether prompts are retained. Raw fetched source is sent
to that local server; reports and normal terminal output remain redacted.

Inline scripts and handlers, external fetched scripts and decoded source-map
content are split into overlapping 4,000-character chunks. Keyword neighborhoods
are prioritized. `--ai-max-chunks 12` is a global inference budget, configurable
from 1 to 100. Coverage reports distinguish submitted/completed chunks and budget
exhaustion. Large/minified programs can exceed this budget or cross chunk boundaries.

Model responses must be structured JSON. Each accepted candidate must match
actual source tokens and a qualifying credential assignment or access comparison
under the same syntax rules used by static checks. A model claim alone cannot
turn an ordinary comparison into a finding. Whitespace and
equivalent string quote spelling may differ; operators and identifiers must match.
The tool discards invented values, never executes model-generated actions,
and withholds model prose from reports. A verified literal does not prove it is
an access code; interpretation remains a review candidate. `--show-secrets` can
reveal accepted values locally, while all export formats remain redacted.

A model cannot analyze source that was never fetched. Large pages now use the
16 MiB default cap, and zero-resource runs explicitly say no source was scanned.
Inspect the report's resource inventory, source-size errors and robots coverage.
Browser DevTools search can include runtime-loaded scripts that the passive
crawler did not discover; use `--include-url` for a known same-origin source file.

Unit tests use a simulated local Ollama API. A separate synthetic verification
script exercises the installed native model and records its observed results and
memory usage. Neither is a general model detection-accuracy benchmark.
References: [Ollama generation API](https://docs.ollama.com/api/generate),
[Qwen2.5-Coder catalogue](https://ollama.com/library/qwen2.5-coder),
[Ollama local configuration](https://docs.ollama.com/faq).

## Export reports for AI tools

Choose `ai` in the wizard or use:

```powershell
.\.venv\Scripts\gilbrt.exe --url "https://your-authorized-site.example/" --confirm-authorized --search all --output gilbrt-report.md --format ai
```

The AI report contains the complete recorded findings, severity totals, all
remediation advice, selected categories, scope/limits, a resource inventory,
coverage observations and a suggested AI review task. Audit data is fenced as JSON
and explicitly labeled untrusted evidence to reduce instruction confusion. No
report is uploaded to any AI service; you choose where to attach it.

All exports remain redacted, including when `--show-secrets` is enabled. A full
report means all recorded audit observations and coverage metadata, not a dump of
website bodies or credentials. JSON contains full structured data, HTML provides a
readable report, and CSV provides findings as rows. The AI Markdown format includes
both structured data and instructions for prioritization, remediation and safe
retesting. Findings are candidates until validated; coverage limits remain explicit.

## AI application staging checks

Use only local/staging systems within an explicitly approved scope. Passive mode
does not become active unless **both** active flags are supplied. Configuring an
environment label is an attestation, not automatic proof that a host is staging.

Copy `active.example.json` to `active.local.json` and remove any probe you do not
want. Supply real staging paths and your staging model name. At most ten probes
are allowed. Every endpoint must match the target's exact origin; active probes
refuse redirects. Cookies are isolated between access checks.

For isolation checks, create a private synthetic conversation/file/retrieval record
owned by test account A containing a unique random marker (at least 16 characters).
Configure its explicit read-only GET endpoint, marker and two test-account token
environment variable names. gilbrt first requires account A to retrieve that marker,
then sends one unauthenticated request and one request as account B. A returned
marker is an access-isolation candidate requiring review against intended sharing
permissions. It does not enumerate IDs or download other users' records. Use an
endpoint that returns only synthetic content.

The prompt check sends **one POST** to an explicitly configured OpenAI-compatible
chat endpoint. The request contains a generated synthetic system-message canary
and a fixed user instruction attempting to reveal it. It sends no real secrets,
tools or exfiltration addresses. The returned assistant message is checked only
for that canary. This is a small instruction-boundary probe, not a full indirect
prompt-injection, RAG, agent-tool, or model safety assessment. It can consume paid
model tokens and create synthetic application logs/conversation records.

```powershell
# Set these through your preferred environment/secret manager:
# GILBRT_OWNER_TOKEN, GILBRT_OTHER_TOKEN, GILBRT_AI_TEST_TOKEN
gilbrt --url https://your-staging-app.example --confirm-authorized --active --active-config active.local.json --output audit.json
```

## Evidence, limitations and privacy

Findings store masked candidate secrets (at most first/last four characters), never
full bodies, raw comments, cookie values, tokens or exception messages. The optional
local terminal reveal does not change the stored findings. Short
secrets are masked fully. Comment findings list only matched keywords. URLs omit
credentials, paths, queries and fragments and include a stable resource digest for
correlation. To locate a finding, match its digest against a locally calculated
SHA-256 of the full source URL (`hashlib.sha256(url.encode()).hexdigest()[:12]`);
the scanner includes source line numbers for secret candidates. Low-entropy URLs
may be guessable from a digest, so treat audit reports as private.

Website responses are held in memory for analysis, bounded to 16 MiB each after
decompression by default (configurable with `--max-resource-mb`);
raw content is not written to reports. Requests have timeouts and bounded redirects.
The tool uses the system's normal DNS and does not pin hostnames against DNS rebinding;
run it against trusted, authorized hostnames. Environment proxies/netrc are disabled
to avoid unintended credential forwarding. Do not pass a URL from an untrusted party
to this tool as part of a server-side service.

Header checks and regex/entropy matches are heuristics. Google keys and JWTs can
be intentional public values. Headers can depend on response type, CSP nonces/hashes
can make some flagged keywords ineffective, and JavaScript-readable cookies can be
intentional. TLS checks use normal certificate validation but do not assess cipher
suites or revocation. No browser execution or login crawl is performed.

HIBP uses the public `/api/v3/breaches` catalogue and exact hostname matching; no
email addresses are queried. The supplied key is sent only to HIBP, without
following redirects. Subdomains are not automatically collapsed to parent domains.
An empty catalogue match does not imply absence of a breach. Breach data attribution:
[Have I Been Pwned](https://haveibeenpwned.com/),
[official API documentation](https://haveibeenpwned.com/API/v3).

Exit codes: 0 means the audit completed, even if it found issues or coverage gaps;
1 means configuration/report failure; 2 means argument misuse; 130 means interrupted.
Read Coverage findings before interpreting an otherwise empty report.

## Development

```powershell
python -m unittest discover -s tests -v
python -m compileall -q gilbrt
```

Tests use local HTTP fixtures or mocks; they never probe a public target.
GitHub Actions repeats fresh Bash installation and unit checks on Linux and Windows
with Python 3.10 and 3.13, plus website/bootstrap checks, after the repository is pushed.
For an explicit Windows budget check against an authorized target, run
`python scripts/verify_memory_budget.py --url YOUR_AUTHORIZED_URL --confirm-authorized --limit-mb 1024`.
This verifier performs real GET requests and local inference; its report distinguishes
the job commit cap from observed resident memory and excludes OS RAM.

## Layout

```text
gilbrt/
  pyproject.toml
  requirements.txt
  README.md
  active.example.json
  gilbrt/
    __init__.py
    __main__.py
    cli.py
    crawler.py
    headers.py
    scanner.py
    breach_check.py
    reporter.py
    models.py
    active.py
    access_codes.py
    local_ai.py
    bundled_ai.py
    js_parser.py
    menu.py
  tests/
    test_audit.py
    test_menu.py
    test_access_codes.py
    test_local_ai.py
    test_bundled_ai.py
    test_visible_report.py
    test_bash_install.py
  bin/gilbrt
  install.sh
  gilbrt.sh
  scripts/
    install_small_ai.py
    verify_small_ai.py
    verify_memory_budget.py
    install_bash_path.py
```
