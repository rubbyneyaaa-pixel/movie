# CineReview – Movie Review System

Black & gold movie review app: emoji ratings, admin dashboard (charts, filters, sorting, paging), CSV and SQLite database download.
Single file (`app.js`) · Node.js 22.13+ · built-in SQLite · no npm packages.

## Run locally
    node app.js
Open http://localhost:3000 — admin login: `admin` / `123`

## Environment variables (optional)
| Name | Purpose |
|---|---|
| PORT | Port to listen on (hosts set this automatically) |
| ADMIN_PASSWORD | Password for the first-time admin account (default `123`) |
| DB_PATH | Path of the SQLite file (point to a persistent disk when deployed) |

## Deploy on Render (from this GitHub repo)
1. Push this folder to a GitHub repository.
2. Render.com -> New -> Web Service -> connect the repo.
3. Runtime: Node · Build command: (leave empty) · Start command: `node app.js`
4. Environment: `NODE_VERSION=22`, `ADMIN_PASSWORD=<your password>`
5. Deploy, then open the .onrender.com URL.

Note: on free hosting the disk is temporary, so the SQLite file resets on redeploy/restart.
For permanent data, add a persistent disk (paid) and set `DB_PATH=/var/data/movie_reviews.db`.
