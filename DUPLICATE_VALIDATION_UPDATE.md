# Duplicate registration and tip validation update

## User registration
- Registration email addresses are trimmed and lowercased before lookup and storage.
- The server checks for an existing address case-insensitively, including legacy mixed-case records.
- Existing email addresses receive HTTP 409 with code `EMAIL_ALREADY_EXISTS` and a clear message asking the visitor to log in or use another address.
- MongoDB's unique email index remains enabled and is explicitly verified during startup where possible; duplicate-key races are also handled as HTTP 409.
- The browser API helper now displays the server's validation message instead of replacing it with a generic error, so the duplicate-email message is visible in the registration form.

## Tip validation
- Duplicate detection applies to the same date, tip category (`free` or `premium`), home team, away team and selection.
- Team and selection comparisons are case-insensitive; repeated internal whitespace is normalized for newly submitted tips.
- The same match can still have a separate Free and VIP entry, because the category is part of the duplicate key.
- Both creating and editing tips are checked. Editing the existing tip itself is allowed; creating a second identical selection or editing one into a duplicate returns HTTP 409 with code `DUPLICATE_TIP`.
- A MongoDB unique compound index provides an additional race-condition safeguard when existing data permits index creation.
- Duplicate validation feedback is displayed in the Admin tip form.

## Verification
- `node --check server.js` passed.
- Inline JavaScript extracted from `public/index.html` passed `node --check`.
- Existing football logic tests passed: 6/6.
- Live MongoDB index creation and live registration/tip requests were not run in this environment.

## Deployment note
Deploy the updated project to Render. On startup, inspect Render logs for messages indicating that a unique index could not be created because duplicate legacy records already exist. The API-level checks remain active, but the unique index is the additional database-level protection against simultaneous requests.
