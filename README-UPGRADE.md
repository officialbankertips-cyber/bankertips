# Banker Tips — Professional Upgrade

This upgrade is based on the supplied `index (8).html` and `server (2)(2).js` files.

## Included
- VIP expiry reminder jobs (24-hour and 3-hour push alerts) while preserving the existing countdown, renewal and payment history flows.
- Web Push subscription endpoints and server-triggered alerts for VIP activation/revocation, newly published tips, finished match results and upcoming membership expiry.
- Match Centre with fixture creation, filtering, match status and score updates. Fixtures/results are admin-managed; no third-party live sports-data provider was included or configured.
- PWA manifest, service worker, offline fallback and 192px/512px icons.
- Clean, responsive Match Centre UI integrated with the existing independent-route navigation and Comfortaa styling.

## Deployment
1. Put `server.js` at the backend project root.
2. Put the contents of `public/` in the backend `public/` folder. Ensure the HTML is deployed as `public/index.html`.
3. Install the added dependency: `npm install web-push`.
4. Keep all existing dependencies and environment variables from the current deployment. Do not replace your production `.env` values with sample values.
5. Generate VAPID keys once using `npx web-push generate-vapid-keys`.
6. Add these Render environment variables:
   - `VAPID_PUBLIC_KEY` = generated public key
   - `VAPID_PRIVATE_KEY` = generated private key
   - `VAPID_SUBJECT` = `mailto:officialbankertips@gmail.com`
7. Deploy and test HTTPS on the live domain. Users must sign in and tap the bell to enable notifications on each device/browser.

## Important notes
- Existing VIP pricing, OptimaPay integration, user sessions, tips, admin operations and MongoDB models are retained.
- Push notifications require browser permission and the VAPID environment variables. If these are missing, the rest of the site continues to run; the API reports that push is not configured.
- The Match Centre is intentionally manual-admin-managed. To automate fixtures/live scores, connect a licensed football-data API and map its competition/team IDs before enabling automated imports.
- The uploaded source did not include the original `package.json`, environment file, or original logo asset. This bundle includes a clean Banker Tips app icon in place of the missing logo file. Preserve your production-specific dependencies and secrets.
- The current platform is a predictions and information service. Results are not guaranteed; display historical performance transparently and encourage responsible play.
