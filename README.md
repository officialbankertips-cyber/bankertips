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
- Configure the separate Kenya credentials (`KE_OPTIMAPAY_API_KEY`, `KE_OPTIMAPAY_API_SECRET`, `KE_OPTIMAPAY_PAYMENT_ACCOUNT_ID`) and the shared Tanzania/Uganda Global API credentials (`TZUG_OPTIMAPAY_API_KEY`, `TZUG_OPTIMAPAY_API_SECRET`, `TZUG_OPTIMAPAY_ACCOUNT_ID`) in Render. Keep secrets out of frontend code and source control.
- The current integration uses server-side status polling against the provided Collecto status endpoint; verify the exact Collecto request and response schema with OptimaPay before live transactions. Membership is activated only when OptimaPay reports `completed` and the reported amount and phone match the stored payment. Test with a low amount and a test account first; confirm current package prices and both the Kenya-only account ID and the shared Tanzania/Uganda merchant account ID before production use.


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


## Kenya + Tanzania Collecto integration (current)
- Base URL: `https://global.optimapaybridge.co.ke/api/v2`
- Initiate: `POST /collecto/initiate`
- Status: `GET /collecto/status/{identifier}`
- Set the separate Kenya and Tanzania API key, secret, and account ID variables shown in `.env.example`.
- The browser sends the selected country, package and mobile number to the backend. The backend determines price/currency and selects that country's credentials. Never trust a client-supplied amount.
- The integration sends account routing fields plus phone, amount, currency, country, reference and description. Confirm the exact accepted account field and status response schema with OptimaPay before production.
- Membership is activated only after provider status is successful and the returned phone and amount match the stored payment. Provider responses must include the paid amount and payer phone (or equivalent documented fields) for this verification to succeed.

## Multi-country OptimaPay mobile-money checkout

The subscription checkout supports Kenya, Tanzania and Uganda while retaining the existing Kenya M-Pesa STK Push integration (`stkpush.php` and `status.php`). Tanzania and Uganda use the OptimaPay Global API from the server only; API credentials must never be placed in browser code.

### Country pricing

| Package | Kenya (KES) | Tanzania (TZS) | Uganda (UGX) |
| --- | ---: | ---: | ---: |
| Daily VIP | 150 | 5,000 | 5,000 |
| Weekly VIP | 1,500 | 35,000 | 50,000 |
| Monthly VIP | 3,500 | 75,000 | 110,000 |

### Tanzania

- Collection: `POST https://global.optimapaybridge.co.ke/api/v2/godigital/tz/collect`
- Status: `GET https://global.optimapaybridge.co.ke/api/v2/godigital/tz/status/{identifier}`
- Checkout requires explicit network selection: `VODACOM`, `YAS`, `AIRTEL`, or `HALOTEL`.
- Phone numbers are normalized to `255` international format.
- Currency: TZS.

### Uganda

- Collection: `POST https://global.optimapaybridge.co.ke/api/v2/collecto/initiate`
- Status: `GET https://global.optimapaybridge.co.ke/api/v2/collecto/status/{identifier}`
- Supported wallet rails documented by OptimaPay: MTN and Airtel Money.
- Phone numbers are normalized to `256` international format.
- Currency: UGX. The Global Wallet collection payload takes phone, amount and reference; the API documentation does not define a separate network selector field for this endpoint.

### Configuration and payment confirmation

Kenya uses its own `KE_OPTIMAPAY_API_KEY`, `KE_OPTIMAPAY_API_SECRET` and `KE_OPTIMAPAY_PAYMENT_ACCOUNT_ID`. Tanzania and Uganda share one separate pair (`TZUG_OPTIMAPAY_API_KEY` and `TZUG_OPTIMAPAY_API_SECRET`) and one shared merchant account (`TZUG_OPTIMAPAY_ACCOUNT_ID`). For backward compatibility, the Kenya integration still accepts the legacy `OPTIMAPAY_API_KEY`, `OPTIMAPAY_API_SECRET` and `OPTIMAPAY_PAYMENT_ACCOUNT_ID` names as fallbacks. Do not put Kenya credentials in the TZUG variables or vice versa.

The published Global API request schema authenticates using the shared API key and secret headers and does not define an `account_id` property in the collection JSON body. The shared account ID is therefore kept as deployment/merchant configuration, not sent as an undocumented request field. If OptimaPay supplies a separate account-ID header or body-field requirement for this merchant, confirm its exact field name with them before adding it.

A collection response (including HTTP 202) is treated as pending, not paid. The server stores the transaction reference and checks the country-specific status endpoint. VIP membership is activated only after a successful final status whose amount and phone match the saved payment. Status checks are idempotent at the payment-record level. If initiation times out or returns an ambiguous gateway error, the original merchant reference is retained for reconciliation; customers are told not to retry until its status is checked.

Before production use, configure valid OptimaPay credentials and complete provider-side KYC/merchant activation. Test real low-value transactions on each supported rail, including pending, success, failed, cancelled and timeout cases. Confirm the Global Wallet status endpoint's final response fields and Uganda network eligibility with OptimaPay for the merchant account.


## GOAL API live scores and tip settlement

Configure `GOAL_API_KEY`, `GOAL_SYNC_INTERVAL_MS=600000`, and `APP_TIME_ZONE=Africa/Nairobi` in Render Environment Variables. See `README-AUTO-RESULTS. txt` for the provider workflow, supported markets, safety rules, and admin sync endpoints. The API key must remain server-side.
