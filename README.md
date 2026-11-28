# FPP Fantasy

FRC fantasy esports game. Multiplayer — accounts and game state live in a shared
SQLite database (Turso / libSQL), served by a small Node backend.

## Stack

- `server.js` — Node `http` server: serves `index.html`, handles all `/api/*`
  routes, Argon2id password hashing (`hash-wasm`), session cookies
- `index.html` — the entire game client (single file, no build step)
- Database — SQLite via `@libsql/client`. Works against a local `file:` DB for
  dev or a hosted [Turso](https://turso.tech) DB in production. Same code, just
  different `TURSO_DATABASE_URL`.

## Local dev

```sh
npm install
npm start          # http://localhost:3000
```

No env vars needed — it creates `./game.db` automatically. That's it.

## Production (Turso)

1. Install the Turso CLI and create a free database:

   ```sh
   curl -sSfL https://get.tur.so/install.sh | bash
   turso auth signup            # or: turso auth login
   turso db create fpp-fantasy  # pick a region close to your host
   ```

2. Get the credentials:

   ```sh
   turso db show fpp-fantasy    # prints URL
   turso db tokens create fpp-fantasy   # prints an auth token
   ```

3. Set env vars on your host (Render, Railway, Fly, a VPS, etc.):

   ```
   TURSO_DATABASE_URL=libsql://fpp-fantasy-<org>.turso.io
   TURSO_AUTH_TOKEN=<token>
   PORT=3000            # host usually sets this for you
   MOD_USERNAME=yourname   # optional: this account becomes mod
   ```

   The schema (`users`, `user_auth`, `sessions`, `gamestate`) is created
   automatically on first boot — no migrations to run.

### Deploying

Any Node host works: connect the repo, set the env vars above, start command
`npm start`. **Do not use GitHub Pages** — it's static-only and can't run the
server. Free hosts with ephemeral disks are fine because all state lives in
Turso, not on the local filesystem.

## Accounts & security

- Passwords hashed with **Argon2id** (PHC-encoded, random 16-byte salt) — never
  stored or logged in plaintext.
- All SQL is parameterized; unique-constraint violations return safe,
  non-revealing errors (`Invalid username or password`).
- Sessions: 192-bit random tokens in the `sessions` table, 30-day expiry,
  `HttpOnly; SameSite=Lax` cookie.
- Schema runs with `PRAGMA foreign_keys = ON` (cascade deletes) and WAL journal
  mode where supported.

## Env vars

See `.env.example`. Summary:

| Var | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | HTTP listen port |
| `TIME_SCALE` | `1` | Game clock multiplier (testing) |
| `MOD_USERNAME` | first account | Username granted mod on register |
| `TURSO_DATABASE_URL` | `file:./game.db` | `libsql://...` for Turso, `file:` for local |
| `TURSO_AUTH_TOKEN` | — | Turso auth token (not needed for `file:`) |
| `DISCORD_WEBHOOK_URL` | — | Discord webhook for match/event notifications (unset = off) |
| `DISCORD_MENTION` | — | Optional mention prepended to notifications, e.g. `@here` |
| `SITE_URL` | — | Public URL used for event links in notifications |
