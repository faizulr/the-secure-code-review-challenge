# Secure Code Review Challenge #8: Employee Directory

**Employee Directory** is an internal company phonebook: look up colleagues' contact and desk details,
keep your own entry up to date, and let administrators manage the full records, including salary.
Your task is to review it the way you would review a real internal service handed to you before
launch: build a mental model of what it does and what it should protect, then find the one flaw that
breaks that model.

**Date Posted**: 16-Oct-2026

**Solution Will be Posted**: 30-Oct-2026

---

## The application

Employee Directory is a small, invite-only HR tool:

- **Accounts are invitation-only.** An admin creates an **invitation** for an email address; the
  response shows a one-time **invitation code**. Registering requires that email plus its code.
- **Two roles:** **employee** and **admin**. On first boot, with an empty database, the app creates a
  **bootstrap admin** (`admin@localhost`) and prints its random password to the logs.
- Every account is linked to an **employee record**: `name`, `title`, `manager`, `deskNumber`,
  `location`, `phone` (the **public** fields) and `salary` (a **sensitive** field).
- **Employees** browse everyone's public fields, see **salary only on their own record**, and can
  edit the public fields of **their own** record — never salary.
- **Admins** see and edit every field of every record (including salary), delete records, invite new
  hires, and **promote** other users to admin.
- Authentication is a **JWT**: the API returns it as a bearer token, and the server-rendered web UI
  keeps the same token in an **HTTP-only cookie** so you stay logged in while browsing.
- Data lives in **MongoDB**, accessed through **Mongoose**.
- The backend is **Express.js** (Node). The same server also renders a **server-side HTML UI**
  (Nunjucks templates) so the whole app is usable from a browser without touching the API directly.
- Everything is packaged with **Docker Compose**.

The full source is in this directory — `app.js`, `src/` for the API and data layer, and `views/` for
the server-rendered UI. It is a complete, working application — not a snippet. Read all of it,
including its dependencies.

Both surfaces are in scope: the browser UI (`views/`, served by `src/routes/pages.js`) and the JSON
API (`src/routes/`) are the same data seen two ways — the pages are only another consumer of the same
data layer, and the API is also reachable directly.

## Your mission

1. **Threat-model first.** Before reading line by line, map the system (see the
   [suggested methodology](../../README.md#suggested-methodology)).
2. **Identify** the planted vulnerability.
3. **Exploit** it to prove the impact.
4. **Fix** it — a primary fix plus any defense-in-depth you'd recommend.

Capture your findings in the [solution template](../../SOLUTION_TEMPLATE.md) (privately, no spoilers
please).

## Running the application

Requires Docker + Docker Compose (and `jq` for the examples below).

```bash
cd challenges/008-employee-directory
cp .env.example .env        # throwaway dev secrets — never reuse them
docker-compose up --build
```

This starts MongoDB and the app. On first boot, with an empty database, the app creates the
bootstrap admin and prints its password, then starts serving.

- Web UI: <http://localhost:3000/> — open in a browser to log in, browse, and manage records
- API: <http://localhost:3000/api> (used by the examples below)
- Health check: <http://localhost:3000/health>
- MongoDB: `localhost:27017`

### Get the bootstrap admin password

The only seeded account is the bootstrap admin. Read its password from the app logs:

```bash
docker-compose logs app | grep -A3 "Bootstrap administrator"
```

Log in as **`admin@localhost`** with that password, then invite and register as many employees as you
need. The password is printed only once — if you lose it, reset the database with
`docker-compose down -v` and start again.

Stop it with:

```bash
docker-compose down          # add -v to also drop the MongoDB volume
```

> ⚠️ This app is **deliberately vulnerable**. Run it locally only — never expose it to a network you
> don't fully control. The `.env.example` you copy holds throwaway dev secrets; never reuse them.

## Using the web UI (normal usage)

Open <http://localhost:3000/> and you can drive the whole service from the browser:

- **Login** (`/login`) — sign in as the bootstrap admin first; admins land on the Admin page.
- **Admin** (`/admin`, admins only) — **create invitations** (the code is shown once, right after you
  submit), **edit any employee** (including salary), **promote users** to admin, and review
  invitations.
- **Register** (`/register`) — log out, then create an account with an invited email and its
  invitation code.
- **Directory** (`/`) — everyone's public fields; the salary column shows only your own salary (or
  every salary, for admins).
- **My profile** (`/profile`) — edit your own public fields (not salary).
- **Logout** — top-right of the nav bar.

## Using the API (normal usage)

#### Log in as the admin

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@localhost", "password": "PASTE_BOOTSTRAP_PASSWORD_HERE"}' | jq -r '.token')
```

Pass `-H "Authorization: Bearer $TOKEN"` on requests that need authentication.

#### Invite and register an employee

```bash
# Admin creates an invitation and keeps the one-time code
INVITE_CODE=$(curl -s -X POST http://localhost:3000/api/admin/invitations \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"email": "jamie@example.com"}' | jq -r '.invitationCode')

# The invited user registers (also returns a token you can use right away)
curl -s -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"jamie@example.com\", \"password\": \"SecurePass123!\", \"invitationCode\": \"$INVITE_CODE\"}" | jq

# Log in later and keep the token
EMP_TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "jamie@example.com", "password": "SecurePass123!"}' | jq -r '.token')
```

#### Employee: update your profile and read the directory

```bash
curl -s -X PATCH http://localhost:3000/api/employees/me \
  -H "Authorization: Bearer $EMP_TOKEN" -H "Content-Type: application/json" \
  -d '{"title": "Engineer", "deskNumber": "42B", "phone": "555-0100"}' | jq

curl -s http://localhost:3000/api/employees -H "Authorization: Bearer $EMP_TOKEN" | jq
```

#### Admin: manage records and users

```bash
# Full employee records — take an employee id from here
curl -s http://localhost:3000/api/admin/employees -H "Authorization: Bearer $ADMIN_TOKEN" | jq

# Set a salary
curl -s -X PATCH http://localhost:3000/api/admin/employees/EMPLOYEE_ID \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"salary": 125000}' | jq

# List users and promote one to admin
curl -s http://localhost:3000/api/admin/users -H "Authorization: Bearer $ADMIN_TOKEN" | jq

curl -s -X PATCH http://localhost:3000/api/admin/users/USER_ID \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"role": "admin"}' | jq
```

## API reference

**Authentication**
- `POST /api/auth/register` — register with `email`, `password`, `invitationCode` *(returns a JWT)*
- `POST /api/auth/login` — log in with `email`, `password`, returns a JWT
- `POST /api/auth/logout` — clear the session cookie

**Directory** *(requires authentication)*
- `GET /api/employees` — directory entries, with field visibility rules applied
- `PATCH /api/employees/me` — update your own public fields *(not salary)*

**Administration** *(admin only)*
- `POST /api/admin/invitations` — create an invitation for `{ "email": "..." }` *(returns the code once)*
- `GET /api/admin/invitations` — list recent invitations *(metadata only)*
- `GET /api/admin/employees` — full employee records
- `PATCH /api/admin/employees/:id` — update any employee field, including salary
- `DELETE /api/admin/employees/:id` — remove an employee record
- `GET /api/admin/users` — list users (email, role, employee link)
- `PATCH /api/admin/users/:id` — promote a user with `{ "role": "admin" }`

**Utility**
- `GET /` and other non-API paths — the server-rendered web UI
- `GET /health` — health check

Authentication is accepted either as an `Authorization: Bearer <token>` header or as the `token`
cookie the web UI sets. Tokens expire after 24 hours.

## Record your solution

Work through the challenge using the [suggested methodology](../../README.md#suggested-methodology),
and record your findings in your own copy of the
[**solution template**](../../SOLUTION_TEMPLATE.md) — copy it into your private notes and fill it in
as you go.

### Please keep it private (no spoilers)

**Do not post the vulnerability, exploit, or fix in GitHub Issues or Discussions until the solution
is published.** Keep your write-up in your own notes so early answers don't spoil the challenge for
others. Post-reveal discussion is very welcome once the solution drops.

---

*The solution — correct answer, why the plausible alternatives don't fit, the "why it looks safe"
analysis, full exploitation steps, the fix, and real-world CVE grounding — will be published with the
next drop, about two weeks out.*
