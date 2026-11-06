# Tanzania and Uganda OptimaPay Global API update

The Tanzania and Uganda integration has been aligned with the OptimaPay Global API v2 documentation at https://global.optimapaybridge.co.ke/docs/global-api.

## Changes
- Keeps Tanzania collection at `POST /api/v2/godigital/tz/collect` and sends the customer-selected `providerCode` (`VODACOM`, `YAS`, `AIRTEL`, or `HALOTEL`).
- Keeps Uganda collection at `POST /api/v2/collecto/initiate`.
- Uses the documented status endpoints: `GET /api/v2/godigital/tz/status/{identifier}` and `GET /api/v2/collecto/status/{identifier}`.
- Reads the documented transaction payload from the response `data` object and recognizes final `SUCCESSFUL`, `FAILED`, `CANCELLED`, and pending states.
- Adds a server-side background verifier for pending Tanzania/Uganda payments. It runs every 20 seconds, so verification and VIP activation do not depend on the customer keeping the checkout page open.
- Recovers stale `verifying` records after two minutes and retries status checks.
- Keeps server-side amount and normalized phone matching before activating VIP access. Duplicate checks do not extend an already-completed payment twice.
- Leaves Kenya's existing M-Pesa STK integration untouched.

## Required hosting environment variables
Set these in the hosting provider's environment/secrets settings (not in browser code):
- `TZUG_OPTIMAPAY_API_KEY`
- `TZUG_OPTIMAPAY_API_SECRET`

The documentation does not require an account ID in the Global API request body. Keep the merchant API secret private.

## Deployment and verification
1. Upload/replace the project with this ZIP and deploy/restart the Node service.
2. Confirm both Global API credentials are set in the hosting environment.
3. Test one low-value Tanzania payment for each network you support and one Uganda payment.
4. Confirm the Admin payment ledger shows `completed` and the member account shows active VIP access after OptimaPay reports `SUCCESSFUL`.
5. Check server logs for `Automatic TZ payment verification failed` or `Automatic UG payment verification failed` if a payment remains pending.

A successful initiation response (`202 Accepted`) is only a submitted prompt, not proof of payment. The server grants VIP access only after a successful status lookup confirms the amount and phone number.
