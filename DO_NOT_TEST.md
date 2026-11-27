# Websites excluded from gilbrt testing

gilbrt blocks these domains and all their subdomains before starting an audit:

- google.com
- youtube.com
- facebook.com
- instagram.com
- microsoft.com
- apple.com
- amazon.com
- github.com
- cloudflare.com
- paypal.com
- chase.com

This is a conservative product exclusion list, not a claim about these websites'
terms, vulnerability disclosure programs, or legal status. It is intentionally
incomplete. A website missing from this list is **not** permission to test it.
The built-in list lives in `gilbrt/scope.py` and applies to CLI and GUI audits,
including explicit URLs and redirect hops. There is no command-line bypass.

Add exclusions for your engagement with repeatable `--exclude-domain` arguments:

```bash
gilbrt --url https://staging.your-domain.example --confirm-authorized --exclude-domain production.your-domain.example
```

Do not test any other person's website without explicit permission for the exact
host, paths, methods, account fixtures, request volume and testing window. Keep
government, military, emergency services, healthcare, financial services, schools,
and shared hosting infrastructure outside your engagement unless the operator
has expressly included them in the approved scope. Permission for your own hosted
application does not extend to its hosting provider's domains or other tenants.

Use local fixtures or your own staging site for active checks. The `environment`
field and authorization flag record the operator's assertion; they do not verify
ownership or establish legal permission. Robots rules, exact-origin enforcement,
pacing and request limits remain in effect. Stop testing if authorization expires
or the operator requests it.
