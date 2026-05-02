# auth-api

A production-ready authentication REST API built from scratch with Node.js. No auth libraries — every layer implemented manually to understand what tools like Supabase Auth do under the hood.

**Live:** https://auth-api-ovmb.onrender.com

---

## Why I built this

I had been using Supabase Auth without understanding what was happening internally. This project was built to answer the question: *what is an auth system actually doing?*

By the end I could explain JWTs, token rotation, refresh flows, and session management — not just use them.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Client                           │
│          (Browser / Postman / curl)                 │
└──────────────────────┬──────────────────────────────┘
                       │ HTTPS
┌──────────────────────▼──────────────────────────────┐
│                  Express API                        │
│                                                     │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │ Rate Limiter│  │  Auth Routes │  │  /me route│  │
│  │ (10req/15m) │  │              │  │(protected)│  │
│  └─────────────┘  └──────┬───────┘  └─────┬─────┘  │
│                          │                │         │
│                 ┌────────▼────────┐       │         │
│                 │  authenticateToken      │         │
│                 │  middleware     ◄───────┘         │
│                 │  (JWT verify)   │                 │
│                 └────────┬────────┘                 │
└──────────────────────────┼──────────────────────────┘
                           │
          ┌────────────────┼─────────────────┐
          │                │                 │
┌─────────▼──────┐ ┌───────▼──────┐ ┌───────▼──────┐
│   PostgreSQL   │ │    Resend    │ │     JWT      │
│   (Supabase)   │ │   (Emails)   │ │  (Tokens)    │
│                │ │              │ │              │
│ - users        │ │ - Welcome    │ │ - Access     │
│ - refresh_     │ │ - Password   │ │   token 15m  │
│   tokens       │ │   reset      │ │ - Signed with│
│ - password_    │ │              │ │   HMAC-SHA256│
│   reset_tokens │ └──────────────┘ └──────────────┘
└────────────────┘
```

---

## Token Flow

```
LOGIN
  │
  ├──► Access Token  (JWT, 15min, stateless)
  │         └──► Used in Authorization header for protected routes
  │
  └──► Refresh Token (random hex, 7 days, stored in DB)
            └──► Used to get a new access token without re-login

LOGOUT
  └──► Refresh token deleted from DB → session terminated

PASSWORD RESET
  └──► Time-limited token (1hr) → emailed → used once → marked as used
```

---

## Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/auth/register` | None | Create account, send welcome email |
| POST | `/auth/login` | None | Verify credentials, issue tokens |
| POST | `/auth/refresh` | None | Get new access token |
| POST | `/auth/logout` | None | Invalidate refresh token |
| POST | `/auth/forgot-password` | None | Send password reset email |
| POST | `/auth/reset-password` | None | Set new password via token |
| GET | `/me` | Bearer token | Return current user from token |

### Register
```bash
curl -X POST https://auth-api-ovmb.onrender.com/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "password": "yourpassword"}'
```

### Login
```bash
curl -X POST https://auth-api-ovmb.onrender.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "password": "yourpassword"}'
```

### Protected route
```bash
curl https://auth-api-ovmb.onrender.com/me \
  -H "Authorization: Bearer <your_access_token>"
```

---

## Stack

| Layer | Technology |
|-------|------------|
| Runtime | Node.js |
| Framework | Express.js |
| Database | PostgreSQL (Supabase) |
| Email | Resend |
| Deployment | Render |

---

## Security decisions

**Passwords** are hashed with `bcrypt` at cost factor 10 — deliberately slow to resist brute force.

**JWT payload** contains only `userId` and `email` — never sensitive data. The signature uses HMAC-SHA256 with a server-side secret, making tampering detectable.

**Login errors** always return `"Invalid credentials"` whether the email doesn't exist or the password is wrong — this prevents user enumeration attacks.

**Refresh tokens** are random 64-byte hex strings stored in the database. Logout deletes the token, immediately invalidating the session.

**Password reset tokens** are single-use and expire after 1 hour. Once used they are marked `used: true` and rejected on any subsequent attempt.

**Rate limiting** restricts `/auth/login` and `/auth/register` to 10 requests per IP per 15 minutes, preventing brute force attacks.

---

## Database schema

```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE refresh_tokens (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  token TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE password_reset_tokens (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  token TEXT UNIQUE NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

---

## What I learned

- A JWT is not encrypted — it is tamper-proof. The payload is base64 encoded and readable by anyone. The signature is what prevents modification.
- Access tokens are stateless — the server doesn't store them, it just verifies the signature.
- Refresh tokens are stateful — they live in the database, which is what makes logout possible.
- Supabase Auth is an implementation of exactly this pattern. Understanding it manually made every Supabase concept click.
- `bcrypt` is intentionally slow. That's the point.

---

## Local setup

```bash
git clone https://github.com/bogstar21/auth-api
cd auth-api
npm install
```

Create a `.env` file:
```
PORT=3000
JWT_SECRET=your-secret-key
DATABASE_URL=your-postgres-connection-string
RESEND_API_KEY=your-resend-key
APP_URL=http://localhost:3000
```

```bash
node index.js
```
