# Banker Tips — Backend + Admin Panel API

This project provides a Node.js/Express API backed by MongoDB. It includes account registration/login, secure password hashing, server-side admin authorization, VIP activation/expiry, free/premium tips, tip result updates, and admin CRUD endpoints.

## 1. Requirements
- Node.js 20+
- MongoDB Atlas database (or a MongoDB server)
- GitHub account and Render account if deploying online

## 2. Install locally
```bash
npm install
cp .env.example .env
```
Edit `.env` and set:
- `MONGODB_URI`: your MongoDB connection string
- `JWT_SECRET`: a long random value (32+ characters)
- `ADMIN_EMAIL`: the admin login email
- `ADMIN_PASSWORD`: a unique password of at least 12 characters
- `FRONTEND_ORIGIN`: your website origin, e.g. `http://localhost:3000`
- `COOKIE_SECURE=false` for local HTTP only

Then run:
```bash
npm run dev
```
Open `http://localhost:3000`. The server reports status at `/api/health`.

## 3. Admin login
Open the website's normal login form and use the exact `ADMIN_EMAIL` and `ADMIN_PASSWORD` values from the server environment. There is no separate public admin login URL. After login, `/api/auth/me` returns `role: "admin"` and the frontend can show the admin section.

**Important:** Set `ADMIN_PASSWORD` to a unique, strong secret before the first run. Do not commit `.env` to GitHub or share it in screenshots. On each server startup, the configured admin account's password is synchronized from `ADMIN_PASSWORD`; update that environment variable when rotating the admin password. Consider removing or rotating bootstrap credentials after deployment according to your operations process.

## 4. Render deployment
1. Upload this folder to a GitHub repository.
2. In Render, create a **Web Service** connected to the repository.
3. Build command: `npm install`
4. Start command: `npm start`
5. Add the environment variables listed in `.env.example` in Render's Environment settings. Use your real MongoDB URI and a unique `JWT_SECRET`.
6. Set `NODE_ENV=production`, `COOKIE_SECURE=true`, and `FRONTEND_ORIGIN` to your exact deployed website origin, e.g. `https://your-service.onrender.com`.
7. If using a separate frontend domain, add that exact origin to `FRONTEND_ORIGIN`. Cross-site cookie deployments may need `SameSite=None; Secure` plus explicit CSRF-token handling; this starter intentionally uses same-origin hosting for safer defaults.
8. In MongoDB Atlas, allow the Render service to reach the database. Prefer restricted network access where feasible; avoid broad access if you can configure stable egress/IP access.

## 5. Frontend
Put the Banker Tips HTML file inside `public/index.html`. The API uses same-origin paths, so the frontend should call `/api/...` and browser fetch requests should use `credentials: "include"` for cookie sessions.

If you are using the previously generated `banker_tips_fixed.html`, copy it to `public/index.html`. Its API calls may need to be adjusted to use `credentials: "include"` on every request and the endpoints listed below. The frontend must not store passwords or session JWTs in localStorage.

## 6. API endpoints
### Public/member
- `POST /api/auth/register` — `{ "email", "phoneNumber", "password", "selectedPackage" }`; package is `daily`, `weekly`, or `monthly`
- `POST /api/auth/login` — `{ "email", "password" }`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/tips?type=free&date=YYYY-MM-DD`
- `GET /api/tips/history?type=free`
- `GET /api/tips?type=premium&date=YYYY-MM-DD` — requires active VIP or admin
- `GET /api/tips/history?type=premium` — requires active VIP or admin

### Admin (all require a logged-in admin)
- `GET /api/admin/tips`
- `POST /api/admin/tips` — create tip
- `PUT /api/admin/tips/:id` — edit match/tip/odds/date/type/result
- `DELETE /api/admin/tips/:id`
- `GET /api/admin/users`
- `PATCH /api/admin/users/:id/vip` — `{ "action": "approve" }`, `{ "action": "reject" }`, or `{ "action": "revoke" }`. Approval activates Daily for 1 day, Weekly for 7 days, or Monthly for 30 days. Verify payment independently before approving.

Tip payload example:
```json
{
  "date": "2026-10-18",
  "type": "free",
  "homeTeam": "Team A",
  "awayTeam": "Team B",
  "match": "Team A vs Team B",
  "tip": "Over 1.5",
  "odds": 1.45,
  "result": "Pending"
}
```

## Security notes
- Passwords are hashed using bcrypt.
- Admin access is checked by the backend on every admin route; changing browser UI state cannot grant admin access.
- Premium tips are authorized by the server for every request.
- HTTP-only cookies are used for sessions; use HTTPS in production.
- Rate limiting is applied to API and authentication routes.
- The backend validates incoming tip data and never allows public registration to choose a role.
- Before public production use, consider adding email verification, password reset, audit logs, backups, monitoring, and a dedicated CSRF-token implementation if the frontend and API are hosted on different sites.
- This is a starter implementation; review and test in your environment before accepting real customer payments. Payment activation is intentionally manual through the Admin membership review table. The interface lists supported payment methods and current M-Pesa instructions, but it does not collect transaction IDs or automatically verify M-Pesa, PayPal, Skrill, Eversend, or Binance payments. Admin must confirm the transaction independently before clicking Approve + activate. The approval endpoint sets the expiry based on the selected package. Existing users may need to log in again after deployment for updated membership status to be reflected.


## Fix for admin tip validation
The backend now splits a combined match string such as `Lyon - Nice` into `homeTeam` and `awayTeam` when separate team fields are not supplied by the frontend. Redeploy this updated `server.js` to fix the required-field validation error.


## Membership review workflow
1. Customer selects a subscription plan before registration.
2. Registration stores the selected package and leaves VIP access disabled.
3. Customer is signed in and sent to the Payment & Membership panel.
4. Admin opens the Admin panel, checks the actual payment record, then approves or rejects the request.
5. Approval activates VIP access for 1, 7, or 30 days based on the selected package. The backend enforces VIP authorization and expiry on premium-tip API requests.
