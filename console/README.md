# Web console — implementation in progress

This directory adds a responsive, same-origin console to the existing manager. It is not a replacement for the subscription endpoint. No public route should be configured until Access JWT verification, local password/TOTP enrollment and deployment checks are complete.

Architecture: unprivileged FastAPI server at `127.0.0.1:18080`; root-owned broker on `/run/sb-console/broker.sock`; sequential in-memory queue; existing CLI controller and SQLite database. Only fixed operation names are accepted. Broker task metadata excludes submitted parameters and SSH passwords. Interrupted tasks require manual review and resubmission, not automatic retry.

`install-console.sh` installs services on an existing managed VPS. It intentionally installs a blank Access configuration: all HTTP requests fail closed until `SB_ACCESS_TEAM`, `SB_ACCESS_AUD`, `SB_ACCESS_EMAIL` and `SB_CONSOLE_ORIGIN` are configured in `/etc/sb-console/console.env`.

The first enrollment token is generated at `/var/lib/sb-console/setup-token` (mode 0600). Transfer it privately, enroll a TOTP authenticator and set a unique password. Do not put the token in a URL, command line argument, public issue or repository. Setup cannot be completed without the token and a valid Access identity.

Implemented UI: overview, nodes, user lifecycle, plan editing, subscription links and QR codes, task progress, audit and authentication. First-release password initialization requires root SSH; non-root enrollment remains supported through the CLI only. Recovery, authenticator replacement and software uninstall are intentionally not exposed over HTTP.

Node details show deployed protocols/ports, last sampled listener and service status, assigned user counts and users with recorded traffic. Listener presence is not an external end-to-end protocol test; no current-connection count is inferred from traffic counters. Stale samples remain marked with their timestamp.

Plans can use explicit selected nodes (an empty list authorizes none) or dynamic tag intersection. Per-user node rules override the plan: explicit deny, then explicit allow, then inherited plan membership. User/node disabled state, expiry, quota and stats readiness still gate grants. Admin subscriptions remain subject to node entitlement rules. Editing a plan's price/days/quota does not retroactively reset existing users' billing cycles; edit the user or renew deliberately.

Existing installs need `migrate-access.py` under the manager lock before deploying the updated broker snapshot code. It creates a root-only SQLite backup and adds tables; no existing tag policy is converted to an explicit node list. After a permission change, reconciliation updates node credentials and the subscription snapshot; offline revocation remains pending and clients must refresh subscriptions.

Tests:

```sh
python -m pip install -r console/requirements.txt
python -m unittest discover -s tests -v
node --check console/static/app.js
```

No end-to-end claim should be made before testing the actual Cloudflare route, enrollment, desktop/mobile layout and disposable remote-node initialization. Root broker necessarily manages privileged software; keep its socket inaccessible to other users, keep the code root-owned and do not offer a generic command-execution endpoint.
