# Sulav VPS Hosting Panel

A FastAPI-compatible ASGI hosting control panel for running Python/Node projects on a trusted VPS. It keeps the original dashboard, adds isolated project environments, safer uploads, CAPTCHA, CSRF protection, rate limiting, and a local port gateway.

## Install on a VPS

```sh
git clone <your-repository> /opt/sulav-vps
cd /opt/sulav-vps
chmod +x install.sh run.sh
./install.sh
# Edit .env and set long random SECRET_KEY, ADMIN_PASSWORD, and Turnstile keys
. .venv/bin/activate
./run.sh
```

## Run with Docker

Build and run this package on a persistent host or container platform. Do not
deploy it as a Vercel Function when you need hosted child services; the panel
needs a long-running process and writable storage.

```sh
docker build -t sulav-vps .
docker run -d --name sulav-vps --restart unless-stopped \
  --env-file .env -p 5000:5000 \
  -v sulav-vps-data:/data \
  sulav-vps
```

For 24/7 operation, copy `systemd-sulav-vps.service.example` to a systemd service, adjust the user/path, enable it, and put HTTPS in front with a reverse proxy. Vercel can serve the dashboard and API routes, but Vercel Functions are serverless/ephemeral: they cannot keep child processes alive, bind arbitrary ports, persist local files, or guarantee a 24/7 hosted user service. On Vercel, project start and the dynamic port gateway return a clear 409 response instead of pretending the service is running.

## Vercel

1. Import this folder into Vercel.
2. Set `APP_ENV=production`, a persistent `SECRET_KEY`, `ADMIN_PASSWORD`, and a non-obvious `ADMIN_PATH`. If `SECRET_KEY` is temporarily missing, the app still loads so `/healthz` and the configuration error page work, but sessions are not persistent until it is set.
3. Set both Cloudflare Turnstile values to enable CAPTCHA on user and admin login.
4. Keep `ENABLE_SERVER_CONSOLE=false` on Vercel.

The app exports a FastAPI `app` and mounts the existing Flask dashboard through ASGI, so Vercel's Python runtime and Uvicorn use the same entrypoint. The health check is `/healthz`.

## Hosting URLs

On a VPS, each running project can be reached through the panel's local gateway as `https://your-domain.example/<port>/...`, for example `https://your-domain.example/5001/`. The gateway only proxies a registered running project port. Vercel does not support this arbitrary child-port model.

## Dependency behavior

The panel creates `servers/<name>/venv` for every project and runs `python -m pip` inside that environment. Uploading a ZIP with `requirements.txt` installs with upgraded build tooling, no cache, and binary wheels preferred; Node projects use `npm install --no-audit --no-fund`. This avoids the common global-`pip`/`psutil` failure and prevents one project from overwriting another project's packages.

## Security notes

- No credentials are bundled in `data.json`; production secret values are required.
- Passwords use Werkzeug's scrypt hashing; legacy SHA-256 records are upgraded after successful login.
- Uploads sanitize filenames, reject ZIP traversal/symlinks, and enforce file/count/uncompressed-size limits.
- State-changing requests require CSRF tokens; login attempts are rate limited.
- Secure session cookies and security headers are enabled; CAPTCHA fails closed when configured.
- Admin Security Center records client IP activity, detects Vercel/Cloudflare proxy IPs safely, and supports temporary or permanent IP bans with unban controls.
- Set `TRUST_PROXY_HEADERS=true` only when the immediate proxy is trusted; never trust forwarded IP headers on a directly exposed VPS.
- The web console is disabled on Vercel by default and uses `shell=False` plus a small command allowlist when explicitly enabled on a trusted VPS.
