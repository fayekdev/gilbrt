# gilbrt website

A static landing page with a Three.js ASCII background, an editable browser demo, README-backed documentation tabs, a dedicated `/install` page, and live repository stars. The build step copies the repository README for offline fallback; no bundler or package installation is required.

## Run locally

Node.js 22+ is required for development; gilbrt itself requires Python 3.10+.

```sh
cd website
npm run dev
```

Open http://127.0.0.1:4173 (installation is at `/install`). The preview synchronizes the root README and serves both API endpoints with production security headers. Run `node --test tests/*.test.mjs` for endpoint, README parsing, link safety, and demo checks. With Bash available, run `bash tests/bootstrap.sh` for offline bootstrap integration tests; no package or AI downloads are performed.

## Deploy on Vercel

### Mascot assets

The hero background uses Three.js to place the original SVG's individual ASCII characters on
curved 3D geometry. `public/ascii-scene.js` renders glyphs in one point-cloud draw
call, with subtle rotation and pointer response. Rendering is capped at 30 fps and
1.5 device pixel ratio, and stops offscreen, when the tab is hidden, or when paused.
The user's reduced-motion preference starts the scene paused. Resizing updates
the camera without creating another renderer. WebGL context loss restores the SVG.

The original SVG stays visible if JavaScript, WebGL, or the scene module fails.
The page and installer work independently of the renderer. No CDN, remote fonts,
inline scripts, or relaxed Content Security Policy are needed. Local preview
serves the same security headers as Vercel.

Three.js is pinned in `public/vendor/three/version.json`; its MIT license is
included beside its browser modules. To reproduce the vendored files, run
`python scripts/vendor-three.py` from `website/` (requires internet access).
The helper downloads that pinned npm release and verifies its SHA-512 integrity.

Installation and documentation tabs support arrow keys, Home, and End.
`public/install.html` provides platform-specific commands and copy feedback.
`public/docs.js` fetches `/api/readme`, falling back to `public/readme.md` if
GitHub is unavailable. The build command `node scripts/sync-readme.mjs` refreshes
that snapshot from the root README. Fetched Markdown is rendered as safe DOM
nodes: raw HTML is displayed as text and active link schemes are rejected.

`public/demo-engine.js` contains limited, synchronous credential/header examples,
not the Python audit engine. Inputs stay in memory in the current page: there are
no target requests, uploads, credential validation, or persistent storage. Changing
inputs marks prior results as needing another run. Reports never echo credentials.

The top-right GitHub link loads the real star count from `/api/stats`. When GitHub
is unavailable it stays a working repository link without an invented count.

`mascot.svg` is the simplified navigation/footer logo. `favicon.svg` and the
16/32/48-pixel `favicon.ico` cover browser tabs; the web manifest references
192/512-pixel icons and a maskable icon, with a separate 180-pixel Apple touch icon.
These provide app branding without adding offline or service-worker behavior.

### Hosting

1. Commit the `website/` folder to the gilbrt repository and import that repository into Vercel.
2. Set **Root Directory** to `website`, **Framework Preset** to `Other`, and **Output Directory** to `public`. No install command is needed; the checked-in build command synchronizes the root README. The checked-in `vercel.json` configures the output and script headers. Vercel deploys `api/stats.js` and `api/readme.js` as Functions and rewrites `/install` to `public/install.html`.
3. Optionally add a server-only `GITHUB_TOKEN` environment variable with repository metadata read access, then redeploy. It is used only by the GitHub Functions, never sent to the browser. A private repository also needs contents read access for the README endpoint. Omit it for a public repository; do not prefix it with `NEXT_PUBLIC_` or `VITE_`.
4. Add your domain in Vercel's project domain settings and apply the DNS records Vercel provides. The website generates install commands from its current HTTPS origin; no source edits are needed.
5. The domain must be accessible without Vercel authentication for unattended downloads. Test `/install.sh` from an unauthenticated shell after deployment; Vercel deployment protection can otherwise return a sign-in page.

```bash
curl -fsSL https://YOUR-DOMAIN/install.sh -o /tmp/gilbrt-install.sh
# Inspect the downloaded file if desired.
bash /tmp/gilbrt-install.sh --add-path
export PATH="$HOME/.local/bin:$PATH"
gilbrt
```

The script clones the repository into `${XDG_DATA_HOME:-$HOME/.local/share}/gilbrt`, then invokes the existing project installer. It does not overwrite an existing destination. Shell profiles are unchanged by default; pass `--add-path` to explicitly configure Bash PATH. `--prefix DIRECTORY`, `--with-ai`, `--ai-model bundled|ollama:TAG`, and `--add-path` are forwarded to the upstream installer. The bundled AI runtime supports Linux/Windows x64 and ARM64; macOS uses static checks and is not execution-verified here. All platforms require Python 3.10+, Git, internet access and Python venv support. Run audits with explicit `--url` and `--confirm-authorized` in noninteractive environments.

The repository must be public for anonymous downloads. For a private repository, configure Git credentials or set `GILBRT_SOURCE_URL=git@github.com:fayekdev/gilbrt.git` with an authorized SSH key. A Vercel `GITHUB_TOKEN` enables GitHub metadata and README fetching: it is intentionally not exposed through the install script and does not grant download access. The bootstrap follows the repository's default branch and executes its installer; it is not a pinned-release installer.

For repeat installations choose a new absolute `GILBRT_INSTALL_DIR`, and a new `--prefix` if the current command points to an old checkout. Do not delete an existing checkout while its installed launcher is still in use.
