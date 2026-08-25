# Sulav VPS — Vercel deployment

This project is configured for Vercel's Python runtime.

## Deploy
1. Upload this folder to GitHub.
2. Import the repository into Vercel.
3. Set these environment variables in Vercel:
   - `SECRET_KEY` — a long random secret
   - `ADMIN_PASSWORD` — your admin password
   - `ADMIN_PATH` — your private admin URL segment
   - Optional Cloudflare Turnstile keys: `CF_TURNSTILE_SITE_KEY`, `CF_TURNSTILE_SECRET_KEY`
4. Deploy.

## Important Vercel limitation
Vercel Functions are serverless and ephemeral. The dashboard/web UI can run, but uploaded server processes, background timers, local file changes, and long-running VPS workloads are not persistent on Vercel. Use a VPS/Render/Railway for the actual server-running portion.
