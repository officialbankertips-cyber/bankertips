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
- `GET /api/tips/history?type=premium` — requires active VIP or admin; returns up to 500 newest-date records with `authorized`, `type`, and `count` metadata. History responses use private no-store cache headers.

### Admin (all require a logged-in admin)
- `GET /api/admin/tips`
- `POST /api/admin/tips` — create tip
- `PUT /api/admin/tips/:id` — edit match/tip/odds/date/type/result
- `DELETE /api/admin/tips/:id`
- `GET /api/admin/users`
- `POST /api/payments/optimapay/stkpush` — authenticated user initiates an OptimaPay STK Push for their registered package; body: `{ "phone": "0712345678" }`.
- `GET /api/payments/:paymentId/status` — authenticated owner checks status; backend queries OptimaPay and activates membership only when the provider reports `completed` and the amount and phone match the pending payment.
- `PATCH /api/admin/users/:id/vip` — `{ "action": "approve" }`, `{ "action": "reject" }`, or `{ "action": "revoke" }`. Admin review remains available as a manual fallback.

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
- This is a starter implementation; review and test in your environment before accepting real customer payments. OptimaPay M-Pesa STK Push and server-side status polling are integrated. PayPal, Skrill, Eversend, and Binance are display-only and are not integrated.
- Configure `OPTIMA_BASE_URL=https://global.optimapaybridge.co.ke/api/v2` and country-specific credentials in Render: `KE_OPTIMAPAY_API_KEY`, `KE_OPTIMAPAY_API_SECRET`, `KE_OPTIMAPAY_ACCOUNT_ID`, `TZ_OPTIMAPAY_API_KEY`, `TZ_OPTIMAPAY_API_SECRET`, and `TZ_OPTIMAPAY_ACCOUNT_ID`. The server uses `POST /collecto/initiate` and `GET /collecto/status/{identifier}` for the selected country. Keep secrets out of frontend code and source control.
- The current integration uses server-side status polling against the provided Collecto status endpoint; verify the exact Collecto request and response schema with OptimaPay before live transactions. Membership is activated only when OptimaPay reports `completed` and the reported amount and phone match the stored payment. Test with a low amount and a test account first; confirm current package prices and your payment account ID before production use.


## Fix for admin tip validation
The backend now splits a combined match string such as `Lyon - Nice` into `homeTeam` and `awayTeam` when separate team fields are not supplied by the frontend. Redeploy this updated `server.js` to fix the required-field validation error.


## Membership review workflow
1. Customer selects a subscription plan before registration.
2. Registration stores the selected package and leaves VIP access disabled.
3. Customer is signed in and sent to the Payment & Membership panel; enters their Kenyan M-Pesa phone number and starts the STK Push.
4. Customer completes the prompt on their phone. The frontend polls the authenticated status endpoint, while the backend queries OptimaPay's status API.
5. On verified completion with matching phone and amount, the backend activates VIP for 1, 7, or 30 days based on the package. Pending payments do not grant access. The backend enforces VIP authorization and expiry on premium-tip API requests.


## Professional upgrade additions

This release adds the following features on top of the existing Banker Tips app:

- **PWA shell:** `public/manifest.webmanifest` and `public/service-worker.js` enable installation where supported and cache the app shell/logo. API responses are intentionally not cached, so private account/payment data is not stored in the service-worker cache. Offline mode is limited to the shell; live tips and account operations still require a connection.
- **Historical performance API:** `GET /api/stats/performance` aggregates recorded settled tips. Win rate excludes voids and is `null` when there are no wins/losses. Displayed performance is descriptive, not a guarantee.
- **Customer payment history:** `GET /api/payments/history` returns the signed-in user's recent payment records only.
- **Admin overview and ledger:** `GET /api/admin/overview` and `GET /api/admin/payments` require server-side admin authorization. The overview's completed-payment amount is a database total and should be reconciled against OptimaPay reports.
- **Notifications:** users can opt into browser notifications; when permission is granted, the app can show an in-browser reminder when a known VIP expiry is within three days. This is not a background push-notification service and requires the app to be opened with a supported browser.

## Validation and production notes

Run `npm install` and `npm start` with valid environment variables and a reachable MongoDB database. Static checks performed for this archive include `node --check server.js` and syntax checking of the inline frontend JavaScript. Live M-Pesa/STK Push, merchant status checks, browser push delivery, and database-backed end-to-end flows have **not** been tested in this environment. Complete a controlled low-value transaction in your own OptimaPay merchant account before production launch.

The public performance endpoint summarizes recorded tips; keep all outcomes accurately updated and disclose the measurement method. Browser notification permission is optional. For true background push notifications, add a push provider and server-side subscription storage rather than relying on browser notifications while the page is open.


## VIP subscription expiry rules

- Daily VIP plans expire at **00:00 Africa/Nairobi (EAT)** when the expiry date begins. A fresh daily activation is set to the next Nairobi midnight.
- Weekly and monthly plans retain their configured 7-day and 30-day durations.
- The account page displays the expiry date/time in EAT and a live countdown.
- The backend denies VIP access as soon as `vipExpiresAt` is reached, persists expired status on authenticated requests, and runs a database sweep every 60 seconds to set `isActivated=false` and `membershipStatus=expired`.
- The countdown is informational UI; server-side authorization and expiry timestamps are authoritative.

After deployment, verify with a test account: daily activation near midnight, access at 00:00 EAT, expired membership status, and renewal. Do not use a production customer to test expiry.


## Historical integration note
The earlier Collecto endpoint description below has been superseded by the current Tanzania-specific Global API documentation and implementation described in the Tanzania section at the end of this file.


## Tanzania OptimaPay Global API integration (feature-flagged)

The Tanzania checkout is implemented as a separate adapter. Existing Kenya checkout continues to use the original `OPTIMAPAY_API_KEY`, `OPTIMAPAY_API_SECRET`, `OPTIMAPAY_PAYMENT_ACCOUNT_ID`, `stkpush.php`, and `status.php` routes. Tanzania uses only the separate `TZ_*` variables.

### Tanzania provider endpoints
- API host: `https://global.optimapaybridge.co.ke`
- Initiate: `POST /api/v2/godigital/tz/collect`
- Verify status: `GET /api/v2/godigital/tz/status/{identifier}`
- Headers: `X-API-KEY`, `X-API-SECRET`, `Accept: application/json`, `Content-Type: application/json`
- Initiation body uses documented `providerCode`, `phone`, `amount`, `reference`, and `description` fields. Operator codes: `VODACOM`, `YAS`, `AIRTEL`, `HALOTEL`. Phone format sent to provider is `255` plus the Tanzanian mobile number.
- HTTP 202 / `PENDING` is not payment success. Membership activation is only attempted after server-to-server status polling reports `SUCCESSFUL`, and amount, phone, reference (when returned), and TZS currency are checked. No callback is trusted for activation; the provider documentation says callback delivery/signing must be confirmed, so the implementation relies on status polling.

### Render environment variables
Add these in Render → Environment. Keep the feature disabled until OptimaPay confirms merchant access and the final Tanzania prices are set:
- `TZ_PAYMENTS_ENABLED=false` initially; set to `true` only after controlled testing.
- `TZ_PAYMENT_API_BASE_URL=https://global.optimapaybridge.co.ke`
- `TZ_PAYMENT_API_KEY` — Tanzania-enabled OptimaPay API key.
- `TZ_PAYMENT_API_SECRET` — corresponding API secret.
- `TZ_DAILY_PRICE_TZS`, `TZ_WEEKLY_PRICE_TZS`, `TZ_MONTHLY_PRICE_TZS` — final whole-number TZS prices supplied by the business. No KES conversion/default price is applied.

All three TZS prices must be positive whole numbers and credentials must be present before the API reports Tanzania checkout as enabled. The four operator choices are shown only while this configuration is ready, but actual operator availability still depends on the merchant account; confirm all four channels with OptimaPay before enabling publicly.

### Routes added
- `GET /api/payments/tz/config` — reports whether Tanzania checkout is configured and exposes prices only when enabled.
- `POST /api/payments/tz/initiate` — authenticated Tanzania payment initiation using server-side price and operator validation.
- Existing `GET /api/payments/:paymentId/status` now dispatches Tanzania transactions to the Tanzania status endpoint while retaining the existing Kenya status call for Kenya records.

### Important launch checklist
1. Obtain final Daily/Weekly/Monthly TZS prices.
2. Confirm KYC and each operator channel (VODACOM, YAS, AIRTEL, HALOTEL) with OptimaPay.
3. Set Tanzania credentials and prices in Render while `TZ_PAYMENTS_ENABLED=false`.
4. Deploy and verify the Tanzania config endpoint remains disabled until the flag is enabled.
5. Run controlled sandbox/test payments for each enabled operator and verify status responses include the amount and payer phone. The implementation intentionally does not grant VIP when these checks mismatch or status is pending/unknown. The current build uses server-to-server status polling and does not register a callback URL because callback delivery and authenticity behavior are not confirmed in the provider documentation.
6. Only after testing, set `TZ_PAYMENTS_ENABLED=true`.

No live OptimaPay credentials were available during development, so live payment initiation, provider responses, and merchant-specific operator enablement have not been tested. Kenya credentials and prices are not changed by this integration.
