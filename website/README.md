# gilbrt website

A dependency-free static landing page with a Vercel Function for live GitHub stats.

## Run locally

Node.js 22+ is required for development; gilbrt itself requires Python 3.10+.

```sh
cd website
npm run dev
```

Open http://127.0.0.1:4173. Run `npm test` for the stats endpoint tests. With Bash available, run `bash tests/bootstrap.sh` for offline bootstrap integration tests; no package or AI downloads are performed.

## Deploy on Vercel

1. Commit the `website/` folder to the gilbrt repository and import that repository into Vercel.
2. Set **Root Directory** to `website`, **Framework Preset** to `Other`, and **Output Directory** to `public`. No install or build command is needed. The checked-in `vercel.json` configures the output and script headers. Vercel deploys `api/stats.js` as a Function.
3. Optionally add a server-only `GITHUB_TOKEN` environment variable with repository metadata read access, then redeploy. It is used only by the stats Function, never sent to the browser. Omit it for a public repository; do not prefix it with `NEXT_PUBLIC_` or `VITE_`.
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

The repository must be public for anonymous downloads. For a private repository, configure Git credentials or set `GILBRT_SOURCE_URL=git@github.com:fayekdev/gilbrt.git` with an authorized SSH key. A Vercel `GITHUB_TOKEN` only enables stats: it is intentionally not exposed through the install script and does not grant download access. The bootstrap follows the repository's default branch and executes its installer; it is not a pinned-release installer.

For repeat installations choose a new absolute `GILBRT_INSTALL_DIR`, and a new `--prefix` if the current command points to an old checkout. Do not delete an existing checkout while its installed launcher is still in use.
