# gilbrt GUI demo

The working GUI now ships with the Python package. Launch it with
`gilbrt --gui` or `.\.venv\Scripts\python.exe -m gilbrt --gui` from the repository
root. It uses the real engine, persisted settings and installed model selection.
This folder preserves the original standalone synthetic prototype for reference;
its preview server uses the same port, so stop it before launching the working GUI.

WHOOP-inspired local GUI concept. Synthetic data only; the audit engine is not connected and no target requests are made. This demo adds no dependencies.

Run from the repository root with Node.js:

```sh
node gui-demo/serve.mjs
```

Open http://127.0.0.1:4174. The initial dashboard shows a complete sample audit. Use **New audit** to try setup, selected check categories, simulated progress, and cancellation. Findings support search, severity filters, evidence details, and a redacted sample JSON export. Coverage and the activity chart are illustrative fixtures; advanced settings preview the form and do not change the simulation. Existing audit results stay visible if a new audit is cancelled.

The server binds to loopback only and the page disallows outgoing connections. Stop the server with Ctrl+C. This prototype does not change the CLI or the landing website.
