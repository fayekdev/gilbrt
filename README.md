# gilbrt

An installable Python 3.10+ CLI for authorized website auditing, static client-side
secret detection, and opt-in synthetic AI application checks.

## Install and run

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
explicitly referenced by an already fetched same-origin script. No external
scripts are downloaded. Exact scheme and netloc are enforced at each redirect;
endpoint inventory only records references already exposed in fetched source and
does not request guessed or discovered API paths. An HTTP-to-HTTPS redirect
therefore needs a separate audit of the HTTPS target.

## Options

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
`endpoints`, `headers`, `tls`, `breaches`. Default: `all`. `--search` can be repeated. Selecting
`breaches` still requires a HIBP key. Active probes require their separate flags.
`local-ai` is an additional opt-in checkbox, initially unchecked and excluded from
the CLI `all` selection. It requires an installed local model.

Password checks do not require high entropy: they find quoted and unquoted
`password`, `passwd`, `pwd`, `pass` and prefixed assignments such as `dbPassword`
or `DB_PASSWORD`, prefilled password-related HTML fields, and password data
attributes. They scan visible password assignments and comments too.
HTML tables with a password-labeled first column are also checked. Source-map
`sourcesContent` is decoded before scanning, including its escaped source text.
Findings are candidates: sample strings and variable references can be false
positives. Values are never tried against a login service.

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
or minified `if` comparisons such as `if(x === "example-gate")` are Info review
candidates because ordinary UI conditions can look identical to access checks.
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

`--show-secrets` is an explicit exception to terminal redaction: matched values
appear in full in their terminal table rows, replacing the masked marker.
Password findings are Critical; password/admin credentials flagged by model review
are also prioritized as Critical. Severity is triage priority, not proof of exploitation.
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
actual source tokens and a string/numeric literal in that source. Whitespace and
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
