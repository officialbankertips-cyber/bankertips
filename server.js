require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const COOKIE_NAME = "banker_tips_session";
const TOKEN_TTL = "12h";
const OPTIMAP_BASE_URL = String(process.env.OPTIMA_BASE_URL || "https://global.optimapaybridge.co.ke/api/v2").replace(/\/$/, "");
const OPTIMAPAY_BASE_URL = OPTIMAP_BASE_URL;
const COLLECTO_INITIATE_URL = `${OPTIMAP_BASE_URL}/collecto/initiate`;
const COLLECTO_STATUS_URL = `${OPTIMAP_BASE_URL}/collecto/status`;
const PACKAGE_PRICES = Object.freeze({ daily: 250, weekly: 1500, monthly: 3500 });
// Configure final Tanzania prices in Render before accepting production payments.
const TZ_PACKAGE_PRICES = Object.freeze({ daily: Number(process.env.TZ_PRICE_DAILY || 5000), weekly: Number(process.env.TZ_PRICE_WEEKLY || 30000), monthly: Number(process.env.TZ_PRICE_MONTHLY || 70000) });
const PACKAGE_DAYS = Object.freeze({ daily: 1, weekly: 7, monthly: 30 });
const MEMBERSHIP_TIME_ZONE = "Africa/Nairobi";
const MEMBERSHIP_SWEEP_INTERVAL_MS = 60 * 1000;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("FATAL: Set JWT_SECRET to a random secret of at least 32 characters.");
  process.exit(1);
}
if (!process.env.MONGODB_URI) {
  console.error("FATAL: Set MONGODB_URI in your environment.");
  process.exit(1);
}

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https:"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: process.env.NODE_ENV === "production" ? [] : null
    }
  }
}));

const allowedOrigins = (process.env.FRONTEND_ORIGIN || "")
  .split(",").map(v => v.trim()).filter(Boolean);
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Origin not allowed by CORS"));
  },
  credentials: true
}));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "100kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { success: false, message: "Too many attempts. Please try again later." }
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
  phoneNumber: { type: String, trim: true, maxlength: 30, default: "" },
  country: { type: String, enum: ["KE", "TZ"], default: "KE", index: true },
  passwordHash: { type: String, required: true, select: false },
  role: { type: String, enum: ["user", "admin"], default: "user", index: true },
  isActivated: { type: Boolean, default: false, index: true },
  membershipStatus: { type: String, enum: ["pending_approval", "active", "rejected", "expired"], default: "pending_approval", index: true },
  selectedPackage: { type: String, enum: ["daily", "weekly", "monthly"], default: null, index: true },
  vipExpiresAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now }
}, { versionKey: false });

const tipSchema = new mongoose.Schema({
  date: { type: String, required: true, match: /^\d{4}-\d{2}-\d{2}$/ , index: true },
  type: { type: String, enum: ["free", "premium"], required: true, index: true },
  homeTeam: { type: String, required: true, trim: true, maxlength: 120 },
  awayTeam: { type: String, required: true, trim: true, maxlength: 120 },
  match: { type: String, required: true, trim: true, maxlength: 250 },
  time: { type: String, trim: true, maxlength: 20, default: "" },
  tip: { type: String, required: true, trim: true, maxlength: 120 },
  odds: { type: Number, required: true, min: 1, max: 1000 },
  result: { type: String, enum: ["Pending", "Win", "Lose", "Void"], default: "Pending" },
  league: { type: String, trim: true, maxlength: 120, default: "" },
  notes: { type: String, trim: true, maxlength: 500, default: "" },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { versionKey: false });

tipSchema.pre("save", function(next) {
  this.updatedAt = new Date();
  next();
});

const paymentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  package: { type: String, enum: ["daily", "weekly", "monthly"], required: true },
  amount: { type: Number, required: true, min: 1 },
  currency: { type: String, enum: ["KES", "TZS"], default: "KES" },
  country: { type: String, enum: ["KE", "TZ"], default: "KE" },
  providerIdentifier: { type: String, default: null, index: true },
  phone: { type: String, required: true },
  reference: { type: String, required: true, unique: true },
  checkoutRequestId: { type: String, unique: true, sparse: true },
  merchantRequestId: { type: String, default: null },
  status: { type: String, enum: ["initiating", "pending", "verifying", "completed", "failed", "verification_error"], default: "initiating", index: true },
  transactionCode: { type: String, default: null },
  providerMessage: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now },
  completedAt: { type: Date, default: null }
}, { versionKey: false });

const User = mongoose.model("User", userSchema);
const Tip = mongoose.model("Tip", tipSchema);
const Payment = mongoose.model("Payment", paymentSchema);

function safeUser(user) {
  return {
    id: String(user._id),
    email: user.email,
    phoneNumber: user.phoneNumber || "",
    country: user.country || "KE",
    role: user.role,
    isActivated: Boolean(user.isActivated),
    membershipStatus: user.membershipStatus || (user.isActivated ? "active" : "pending_approval"),
    selectedPackage: user.selectedPackage || null,
    vipExpiresAt: user.vipExpiresAt || null
  };
}
function signToken(user) {
  return jwt.sign({ sub: String(user._id), role: user.role }, JWT_SECRET, { expiresIn: TOKEN_TTL });
}
function cookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === "true" || process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 12 * 60 * 60 * 1000
  };
}
function setSession(res, user) {
  res.cookie(COOKIE_NAME, signToken(user), cookieOptions());
}
function clearSession(res) {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === "true" || process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/"
  });
}
function validEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}
function csrfCheck(req, res, next) {
  // SameSite=Lax plus Origin/Referer checks help protect cookie-authenticated writes.
  const origin = req.get("origin");
  const referer = req.get("referer");
  const expected = (process.env.FRONTEND_ORIGIN || "").split(",").map(v => v.trim()).filter(Boolean);
  if (expected.length && (origin || referer)) {
    const candidate = origin || (() => { try { return new URL(referer).origin; } catch { return ""; } })();
    if (candidate && !expected.includes(candidate)) {
      return res.status(403).json({ success: false, message: "Request origin rejected." });
    }
  }
  next();
}
async function requireAuth(req, res, next) {
  try {
    const token = req.cookies[COOKIE_NAME];
    if (!token) return res.status(401).json({ success: false, message: "Please log in." });
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.sub);
    if (!user) {
      clearSession(res);
      return res.status(401).json({ success: false, message: "Session is no longer valid." });
    }
    // Persist expiry immediately on the first authenticated request at/after the deadline.
    await expireUserIfNeeded(user);
    req.user = user;
    next();
  } catch (err) {
    clearSession(res);
    return res.status(401).json({ success: false, message: "Session expired. Please log in again." });
  }
}
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ success: false, message: "Administrator access required." });
  }
  next();
}
function nairobiDateParts(date = new Date()) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: MEMBERSHIP_TIME_ZONE, year: "numeric", month: "2-digit", day: "2-digit"
  }).formatToParts(date);
  const values = Object.fromEntries(parts.map(part => [part.type, part.value]));
  return { year: Number(values.year), month: Number(values.month), day: Number(values.day) };
}

// Kenya has no daylight-saving changes. 00:00 Africa/Nairobi is 21:00 UTC on the prior date.
function nextNairobiMidnight(from = new Date()) {
  const { year, month, day } = nairobiDateParts(from);
  return new Date(Date.UTC(year, month - 1, day + 1, -3, 0, 0, 0));
}

function calculatePackageExpiry(packageKey, existingExpiry = null, currentlyActive = false, now = new Date()) {
  const validExistingExpiry = currentlyActive && existingExpiry && new Date(existingExpiry).getTime() > now.getTime();
  const base = validExistingExpiry ? new Date(existingExpiry) : now;
  if (packageKey === "daily") {
    // A fresh daily plan ends at the next midnight in Kenya. Renewals add one calendar day
    // to the still-active expiry so paying early does not discard remaining subscription time.
    return validExistingExpiry
      ? new Date(base.getTime() + 24 * 60 * 60 * 1000)
      : nextNairobiMidnight(now);
  }
  const days = PACKAGE_DAYS[packageKey];
  if (!days) throw new Error("Invalid subscription package.");
  return new Date(base.getTime() + days * 24 * 60 * 60 * 1000);
}

async function expireUserIfNeeded(user, now = new Date()) {
  if (!user || user.role === "admin" || !user.isActivated || !user.vipExpiresAt) return false;
  if (new Date(user.vipExpiresAt).getTime() > now.getTime()) return false;
  if (user.membershipStatus !== "expired" || user.isActivated) {
    user.isActivated = false;
    user.membershipStatus = "expired";
    await user.save();
  }
  return true;
}

async function expireMemberships(now = new Date()) {
  const result = await User.updateMany(
    { role: { $ne: "admin" }, isActivated: true, vipExpiresAt: { $ne: null, $lte: now }, membershipStatus: { $ne: "expired" } },
    { $set: { isActivated: false, membershipStatus: "expired" } }
  );
  if (result.modifiedCount) console.log(`Automatically suspended ${result.modifiedCount} expired VIP membership(s).`);
  return result.modifiedCount || 0;
}

function hasActiveVip(user) {
  if (user.role === "admin") return true;
  const validStatus = user.membershipStatus === "active" || (!user.membershipStatus && user.isActivated);
  const notExpired = !user.vipExpiresAt || new Date(user.vipExpiresAt).getTime() > Date.now();
  return Boolean(user.isActivated && validStatus && notExpired);
}
function cleanTipInput(body) {
  const type = body.type;
  const date = String(body.date || "");
  // Accept separate team fields or a combined match such as "Lyon - Nice".
  let homeTeam = String(body.homeTeam || "").trim();
  let awayTeam = String(body.awayTeam || "").trim();
  const suppliedMatch = String(body.match || "").trim();

  if ((!homeTeam || !awayTeam) && suppliedMatch) {
    const parts = suppliedMatch.split(/\s+(?:vs?\.?)\s+|\s*[-–—]\s*/i);
    if (parts.length >= 2) {
      if (!homeTeam) homeTeam = parts[0].trim();
      if (!awayTeam) awayTeam = parts.slice(1).join(" - ").trim();
    }
  }

  const match = suppliedMatch || `${homeTeam} vs ${awayTeam}`;
  const tip = String(body.tip || "").trim();
  const odds = Number(body.odds);
  const incomingStatus = String(body.status || body.result || "Pending").toLowerCase();
  const statusToResult = { pending: "Pending", win: "Win", won: "Win", lose: "Lose", lost: "Lose", void: "Void" };
  const result = statusToResult[incomingStatus];
  if (!["free", "premium"].includes(type)) throw new Error("Type must be free or premium.");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(Date.parse(date))) throw new Error("Date must be YYYY-MM-DD.");
  if (!homeTeam || !awayTeam || !match || !tip || !Number.isFinite(odds) || odds < 1 || odds > 1000) {
    throw new Error("Match must include both teams, a tip, and valid odds. Enter it as Home Team - Away Team.");
  }
  if (!result) throw new Error("Invalid result.");
  const time = String(body.time || "").trim();
  if (time && time.length > 20) throw new Error("Invalid match time.");
  return {
    type, date, homeTeam, awayTeam, match, time, tip, odds, result,
    league: String(body.league || "").trim(),
    notes: String(body.notes || "").trim()
  };
}


function normalizeKenyanPhone(value) {
  let phone = String(value || "").replace(/[\s()-]/g, "");
  if (phone.startsWith("+")) phone = phone.slice(1);
  if (/^0[17]\d{8}$/.test(phone)) phone = "254" + phone.slice(1);
  if (!/^254[17]\d{8}$/.test(phone)) return null;
  return phone;
}
function normalizePhone(value, country) {
  let phone = String(value || "").replace(/[\s()-]/g, "");
  if (phone.startsWith("+")) phone = phone.slice(1);
  if (country === "TZ") {
    if (/^0[67]\d{8}$/.test(phone)) phone = "255" + phone.slice(1);
    return /^255[67]\d{8}$/.test(phone) ? phone : null;
  }
  if (/^0[17]\d{8}$/.test(phone)) phone = "254" + phone.slice(1);
  return /^254[17]\d{8}$/.test(phone) ? phone : null;
}
function priceFor(country, packageKey) { return (country === "TZ" ? TZ_PACKAGE_PRICES : PACKAGE_PRICES)[packageKey]; }
function countryCredentials(country) {
  const isTz = country === "TZ";
  const apiKey = process.env[isTz ? "TZ_OPTIMAPAY_API_KEY" : "KE_OPTIMAPAY_API_KEY"]
    || process.env[isTz ? "TZ_OPTIMAP_API_KEY" : "KE_OPTIMAP_API_KEY"]
    || process.env.OPTIMAPAY_API_KEY;
  const apiSecret = process.env[isTz ? "TZ_OPTIMAPAY_API_SECRET" : "KE_OPTIMAPAY_API_SECRET"]
    || process.env[isTz ? "TZ_OPTIMAP_API_SECRET" : "KE_OPTIMAP_API_SECRET"]
    || process.env.OPTIMAPAY_API_SECRET;
  const accountId = process.env[isTz ? "TZ_OPTIMAPAY_ACCOUNT_ID" : "KE_OPTIMAPAY_ACCOUNT_ID"]
    || process.env[isTz ? "TZ_OPTIMAPAY_SYSTEM_ACCOUNT_ID" : "KE_OPTIMAPAY_PAYMENT_ACCOUNT_ID"]
    || process.env[isTz ? "OPTIMAPAY_SYSTEM_ACCOUNT_ID" : "OPTIMAPAY_PAYMENT_ACCOUNT_ID"];
  return { apiKey, apiSecret, accountId };
}
function countryConfigReady(country) {
  const c = countryCredentials(country);
  return Boolean(c.apiKey && c.apiSecret && c.accountId);
}
async function optimapayRequest(method, url, payload, country) {
  const credentials = countryCredentials(country);
  if (!credentials.apiKey || !credentials.apiSecret || !credentials.accountId) {
    throw new Error(`OptimaPay ${country} credentials or account ID are not configured.`);
  }
  const response = await fetch(url, {
    method,
    headers: { "X-API-Key": credentials.apiKey, "X-API-Secret": credentials.apiSecret, "Content-Type": "application/json", "Accept": "application/json" },
    ...(payload ? { body: JSON.stringify(payload) } : {}),
    signal: AbortSignal.timeout(20000)
  });
  let data;
  try { data = await response.json(); } catch { data = null; }
  if (!response.ok || !data || data.success === false || data.error) {
    const error = new Error(String(data?.message || data?.error || `OptimaPay request failed (HTTP ${response.status}).`));
    error.status = response.status;
    throw error;
  }
  return data;
}
function providerData(result) {
  return result?.data || result?.transaction || result?.payment || result;
}
function providerIdentifier(result) {
  const d = providerData(result);
  return d?.identifier || d?.payment_id || d?.paymentId || d?.transaction_id || d?.transactionId
    || d?.checkout_request_id || d?.checkoutRequestId || result?.identifier || result?.payment_id
    || result?.transaction_id || result?.checkout_request_id || null;
}
function normalizeProviderStatus(value) {
  const status = String(value || "").toLowerCase().trim();
  if (["completed", "success", "successful", "paid", "succeeded"].includes(status)) return "completed";
  if (["failed", "failure", "cancelled", "canceled", "rejected", "declined", "expired"].includes(status)) return "failed";
  return "pending";
}
async function activatePaidMembership(payment, providerStatus) {
  const reportedAmount = Number(providerStatus.amount);
  const reportedPhone = normalizePhone(providerStatus.phone, payment.country || "KE");
  if (String(providerStatus.status || "").toLowerCase() !== "completed") return false;
  if (!Number.isFinite(reportedAmount) || reportedAmount !== payment.amount || !reportedPhone || reportedPhone !== payment.phone) {
    payment.status = "verification_error";
    payment.providerMessage = "Provider status did not match the expected amount and phone; membership was not activated.";
    await payment.save();
    return false;
  }
  if (payment.status !== "completed") {
    const user = await User.findById(payment.user);
    if (!user) {
      payment.status = "verification_error";
      payment.providerMessage = "Payment user no longer exists.";
      await payment.save();
      return false;
    }
    // Activate only the package actually paid for; do not trust browser-supplied amounts or package names.
    const wasActive = user.isActivated && user.membershipStatus === "active";
    user.vipExpiresAt = calculatePackageExpiry(payment.package, user.vipExpiresAt, wasActive);
    user.selectedPackage = payment.package;
    user.isActivated = true;
    user.membershipStatus = "active";
    await user.save();
    payment.status = "completed";
    payment.transactionCode = String(providerStatus.transaction_code || "").slice(0, 100) || null;
    payment.providerMessage = "Payment verified with OptimaPay.";
    payment.completedAt = new Date();
    await payment.save();
  }
  return true;
}

function publicTip(tip) {
  const obj = typeof tip.toObject === "function" ? tip.toObject() : { ...tip };
  const resultToStatus = { Pending: "Pending", Win: "Won", Lose: "Lost", Void: "Void" };
  return {
    ...obj,
    id: String(obj._id || obj.id || ""),
    status: resultToStatus[obj.result] || obj.status || "Pending"
  };
}

app.use("/api", apiLimiter);

app.get("/api/health", (req, res) => {
  res.json({ success: true, status: "ok", database: mongoose.connection.readyState === 1 ? "connected" : "connecting" });
});

app.post("/api/auth/register", authLimiter, csrfCheck, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const phoneNumber = String(req.body.phoneNumber || "").trim();
    const country = String(req.body.country || "KE").toUpperCase();
    const password = req.body.password;
    const selectedPackage = String(req.body.selectedPackage || "").toLowerCase();
    if (!["KE", "TZ"].includes(country)) return res.status(400).json({ success: false, message: "Choose Kenya or Tanzania." });
    if (!normalizePhone(phoneNumber, country)) return res.status(400).json({ success: false, message: country === "TZ" ? "Enter a valid Tanzania mobile number, e.g. 0712345678 or 255712345678." : "Enter a valid Kenyan Safaricom number, e.g. 0712345678 or 254712345678." });
    if (!["daily", "weekly", "monthly"].includes(selectedPackage)) return res.status(400).json({ success: false, message: "Choose a valid subscription package before registering." });
    if (!validEmail(email)) return res.status(400).json({ success: false, message: "Enter a valid email address." });
    if (typeof password !== "string" || password.length < 10 || password.length > 128) {
      return res.status(400).json({ success: false, message: "Password must be 10–128 characters." });
    }
    if (phoneNumber.length > 30) return res.status(400).json({ success: false, message: "Phone number is too long." });
    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ success: false, message: "An account with that email already exists." });
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ email, phoneNumber: normalizePhone(phoneNumber, country), country, passwordHash, role: "user", selectedPackage, isActivated: false, membershipStatus: "pending_approval", vipExpiresAt: null });
    setSession(res, user);
    res.status(201).json({ success: true, message: "Account created. VIP access remains locked until an administrator activates it.", user: safeUser(user) });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ success: false, message: "An account with that email already exists." });
    console.error("Registration error:", err.message);
    res.status(500).json({ success: false, message: "Could not create account." });
  }
});

app.post("/api/auth/login", authLimiter, csrfCheck, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = req.body.password;
    if (!validEmail(email) || typeof password !== "string") {
      return res.status(400).json({ success: false, message: "Enter your email and password." });
    }
    const user = await User.findOne({ email }).select("+passwordHash");
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ success: false, message: "Invalid email or password." });
    }
    setSession(res, user);
    res.json({ success: true, message: "Login successful.", user: safeUser(user) });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ success: false, message: "Could not log in." });
  }
});

app.post("/api/auth/logout", csrfCheck, (req, res) => {
  clearSession(res);
  res.json({ success: true, message: "Logged out." });
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({ success: true, user: safeUser(req.user) });
});


// Authenticated members may select a renewal package before starting checkout.
app.post("/api/membership/renew-package", requireAuth, csrfCheck, async (req, res) => {
  try {
    if (req.user.role === "admin") return res.status(400).json({ success: false, message: "Admin accounts do not need a VIP subscription." });
    const packageKey = String(req.body.selectedPackage || "").toLowerCase();
    if (!Object.prototype.hasOwnProperty.call(PACKAGE_PRICES, packageKey)) return res.status(400).json({ success: false, message: "Choose a valid VIP package." });
    req.user.selectedPackage = packageKey;
    if (req.user.membershipStatus === "active" && req.user.vipExpiresAt && new Date(req.user.vipExpiresAt) <= new Date()) {
      req.user.membershipStatus = "expired"; req.user.isActivated = false;
    }
    await req.user.save();
    res.json({ success: true, user: safeUser(req.user), message: "Renewal package selected. Continue to payment." });
  } catch (err) {
    console.error("Renewal package selection error:", err.message);
    res.status(500).json({ success: false, message: "Could not update your renewal package. Please try again." });
  }
});

// OptimaPay STK Push. Provider credentials are read only from server environment variables.
app.post("/api/payments/optimapay/stkpush", requireAuth, csrfCheck, async (req, res) => {
  let payment;
  try {
    if (req.user.role === "admin") return res.status(400).json({ success: false, message: "Admin accounts do not need a VIP payment." });
    const country = String(req.body.country || req.user.country || "KE").toUpperCase();
    if (!["KE", "TZ"].includes(country)) return res.status(400).json({ success: false, message: "Choose Kenya or Tanzania." });
    if (!countryConfigReady(country)) return res.status(503).json({ success: false, message: `Payments for ${country === "TZ" ? "Tanzania" : "Kenya"} are not configured yet. Please contact support.` });
    const packageKey = req.user.selectedPackage;
    const amount = priceFor(country, packageKey);
    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ success: false, message: "Choose a valid VIP package before paying." });
    const phone = normalizePhone(req.body.phone || req.user.phoneNumber, country);
    if (!phone) return res.status(400).json({ success: false, message: country === "TZ" ? "Enter a valid Tanzania mobile number (e.g. 0712345678 or 255712345678)." : "Enter a valid Kenyan Safaricom number (e.g. 0712345678 or 254712345678)." });
    const reference = `BT${Date.now().toString(36).toUpperCase()}${crypto.randomBytes(3).toString("hex").toUpperCase()}`.slice(0, 30);
    payment = await Payment.create({ user: req.user._id, package: packageKey, amount, currency: country === "TZ" ? "TZS" : "KES", country, phone, reference, status: "initiating" });
    const credentials = countryCredentials(country);
    const payload = {
      account_id: credentials.accountId,
      phone,
      amount,
      currency: country === "TZ" ? "TZS" : "KES",
      country,
      reference,
      description: `Banker Tips ${packageKey} VIP membership`
    };
    if (country === "TZ") payload.system_account_id = credentials.accountId;
    else payload.payment_account_id = Number(credentials.accountId);
    const provider = await optimapayRequest("POST", COLLECTO_INITIATE_URL, payload, country);
    const identifier = providerIdentifier(provider);
    if (!identifier) throw new Error("OptimaPay initiate response did not include a payment identifier.");
    payment.providerIdentifier = String(identifier).slice(0, 200);
    payment.checkoutRequestId = String(identifier).slice(0, 200);
    const details = providerData(provider);
    payment.merchantRequestId = String(details?.merchant_request_id || details?.request_id || "").slice(0, 200) || null;
    payment.status = "pending";
    payment.providerMessage = String(provider.message || "Payment request sent. Complete the prompt on your phone and wait for confirmation.").slice(0, 300);
    await payment.save();
    res.status(202).json({ success: true, message: payment.providerMessage, paymentId: String(payment._id), amount: payment.amount, currency: payment.currency, country: payment.country, package: payment.package, status: payment.status });
  } catch (err) {
    if (payment) { payment.status = "failed"; payment.providerMessage = String(err.message || "Payment initiation failed.").slice(0, 300); await payment.save().catch(() => {}); }
    console.error("OptimaPay payment initiation error:", err.message);
    res.status(502).json({ success: false, message: "Could not start the payment. Check the mobile number and try again. If the problem continues, contact support." });
  }
});

// Polling endpoint checks OptimaPay's server-side status API; browser data never activates membership.
app.get("/api/payments/:paymentId/status", requireAuth, async (req, res) => {
  try {
    let payment = await Payment.findOne({ _id: req.params.paymentId, user: req.user._id });
    if (!payment) return res.status(404).json({ success: false, message: "Payment not found." });
    if (payment.status === "pending" && payment.checkoutRequestId) {
      if (!countryConfigReady(payment.country || "KE")) return res.status(503).json({ success: false, message: "Payment verification is not configured." });
      // Claim the pending record atomically so concurrent polls cannot activate the same purchase twice.
      const claimed = await Payment.findOneAndUpdate({ _id: payment._id, status: "pending" }, { $set: { status: "verifying" } }, { new: true });
      if (claimed) {
        payment = await Payment.findById(payment._id);
        try {
          const country = payment.country || "KE";
          const identifier = payment.providerIdentifier || payment.checkoutRequestId;
          const rawProvider = await optimapayRequest("GET", `${COLLECTO_STATUS_URL}/${encodeURIComponent(identifier)}`, null, country);
          const provider = providerData(rawProvider);
          provider.status = normalizeProviderStatus(provider.status || provider.payment_status || provider.result || provider.state);
          if (provider.phone == null) provider.phone = provider.msisdn || provider.payer_phone || provider.mobile_number || provider.customer_phone;
          if (provider.amount == null) provider.amount = provider.paid_amount || provider.transaction_amount;
          if (provider.transaction_code == null) provider.transaction_code = provider.mpesa_receipt || provider.receipt || provider.transaction_id;
          const status = String(provider.status || "").toLowerCase();
          if (status === "completed") {
            await activatePaidMembership(payment, provider);
          } else if (status === "failed") {
            payment.status = "failed";
            payment.providerMessage = String(provider.message || provider.ResultDesc || "Payment failed or was cancelled.").slice(0, 300);
            await payment.save();
          } else {
            payment.status = "pending";
            payment.providerMessage = String(provider.message || provider.ResultDesc || "Payment is still pending.").slice(0, 300);
            await payment.save();
          }
        } catch (providerError) {
          // Keep the payment pending on transient provider/network errors; do not grant access.
          payment.status = "pending";
          await payment.save().catch(() => {});
          console.error("OptimaPay status check error:", providerError.message);
        }
      } else {
        const refreshed = await Payment.findById(payment._id);
        if (refreshed) payment = refreshed;
      }
    }
    const user = payment.status === "completed" ? await User.findById(req.user._id) : null;
    res.json({ success: true, payment: { id: String(payment._id), package: payment.package, amount: payment.amount, currency: payment.currency || "KES", country: payment.country || "KE", status: payment.status, message: payment.providerMessage, transactionCode: payment.transactionCode }, user: user ? safeUser(user) : undefined });
  } catch (err) {
    res.status(400).json({ success: false, message: "Could not check payment status." });
  }
});

app.get("/api/tips", async (req, res) => {
  try {
    const type = String(req.query.type || "free");
    const date = String(req.query.date || new Date().toISOString().slice(0, 10));
    if (!["free", "premium"].includes(type)) return res.status(400).json({ success: false, message: "Invalid tips type." });
    if (type === "premium") {
      // Every premium request is authorized on the server; hiding a menu item is not security.
      const token = req.cookies[COOKIE_NAME];
      if (!token) return res.status(401).json({ success: false, message: "Log in to access premium tips." });
      let decoded;
      try { decoded = jwt.verify(token, JWT_SECRET); } catch { return res.status(401).json({ success: false, message: "Please log in again." }); }
      const user = await User.findById(decoded.sub);
      if (!user || !hasActiveVip(user)) return res.status(403).json({ success: false, message: "VIP access is not active. Contact the administrator after payment." });
    }
    const tips = await Tip.find({ type, date }).sort({ createdAt: 1 }).lean();
    res.json({ success: true, authorized: true, tips: tips.map(publicTip) });
  } catch (err) {
    console.error("Tips error:", err.message);
    res.status(500).json({ success: false, message: "Could not load tips." });
  }
});

app.get("/api/tips/history", async (req, res) => {
  // History may contain member-only premium selections: never let a browser or proxy cache it.
  res.set("Cache-Control", "private, no-store, max-age=0");
  res.set("Pragma", "no-cache");
  try {
    const type = String(req.query.type || "free").toLowerCase();
    if (!["free", "premium"].includes(type)) {
      return res.status(400).json({ success: false, authorized: false, message: "Invalid tips type." });
    }

    let authorized = type === "free";
    if (type === "premium") {
      const token = req.cookies[COOKIE_NAME];
      if (!token) {
        return res.status(401).json({ success: false, authorized: false, message: "Log in to access premium history." });
      }
      let decoded;
      try {
        decoded = jwt.verify(token, JWT_SECRET);
      } catch {
        clearSession(res);
        return res.status(401).json({ success: false, authorized: false, message: "Your session has expired. Please log in again." });
      }
      const user = await User.findById(decoded.sub);
      if (!user || !hasActiveVip(user)) {
        return res.status(403).json({ success: false, authorized: false, message: "Active VIP membership is required to view premium history." });
      }
      authorized = true;
    }

    // Keep a bounded history response; sort newest dates first and preserve entry order within a date.
    const tips = await Tip.find({ type })
      .sort({ date: -1, createdAt: 1, _id: 1 })
      .limit(500)
      .lean();
    return res.json({ success: true, authorized, type, count: tips.length, tips: tips.map(publicTip) });
  } catch (err) {
    console.error("History error:", err.message);
    return res.status(500).json({ success: false, authorized: false, message: "Could not load history." });
  }
});

// Admin-only user activation and VIP expiry controls.
app.get("/api/admin/users", requireAuth, requireAdmin, async (req, res) => {
  const users = await User.find({}).sort({ createdAt: -1 }).limit(1000).lean();
  res.json({ success: true, users: users.map(u => ({
    id: String(u._id), email: u.email, phoneNumber: u.phoneNumber,
    role: u.role, selectedPackage: u.selectedPackage || null, isActivated: u.isActivated, membershipStatus: u.membershipStatus || (u.isActivated ? "active" : "pending_approval"), vipExpiresAt: u.vipExpiresAt,
    createdAt: u.createdAt
  })) });
});

app.patch("/api/admin/users/:id/vip", requireAuth, requireAdmin, csrfCheck, async (req, res) => {
  try {
    const action = String(req.body.action || "").toLowerCase();
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found." });
    if (user.role === "admin") return res.status(400).json({ success: false, message: "Admin accounts cannot be changed from membership review." });
    if (action === "approve") {
      // Admin should verify payment against the real transaction record before activating.
      if (!PACKAGE_DAYS[user.selectedPackage]) return res.status(400).json({ success: false, message: "This user has no valid selected package." });
      const wasActive = user.isActivated && user.membershipStatus === "active";
      user.vipExpiresAt = calculatePackageExpiry(user.selectedPackage, user.vipExpiresAt, wasActive);
      user.isActivated = true;
      user.membershipStatus = "active";
    } else if (action === "reject") {
      user.isActivated = false;
      user.membershipStatus = "rejected";
      user.vipExpiresAt = null;
    } else if (action === "revoke") {
      user.isActivated = false;
      user.membershipStatus = "expired";
      user.vipExpiresAt = null;
    } else {
      return res.status(400).json({ success: false, message: "Choose approve, reject, or revoke." });
    }
    await user.save();
    res.json({ success: true, message: action === "approve" ? "Membership approved and activated." : action === "reject" ? "Membership request rejected." : "VIP access revoked.", user: safeUser(user) });
  } catch (err) {
    console.error("VIP membership update error:", err.message);
    res.status(400).json({ success: false, message: "Could not update VIP membership." });
  }
});

// Customer payment history. Sensitive provider payloads and credentials are never exposed.
app.get("/api/payments/history", requireAuth, async (req, res) => {
  try {
    const payments = await Payment.find({ user: req.user._id }).sort({ createdAt: -1 }).limit(100).lean();
    res.json({ success: true, payments: payments.map(p => ({ id: String(p._id), package: p.package, amount: p.amount, currency: p.currency || "KES", country: p.country || "KE", phone: p.phone, reference: p.reference, status: p.status, transactionCode: p.transactionCode, message: p.providerMessage, createdAt: p.createdAt, completedAt: p.completedAt })) });
  } catch (err) { res.status(500).json({ success: false, message: "Could not load payment history." }); }
});

// Public historical performance summary. Only settled tips count in the win-rate denominator.
app.get("/api/stats/performance", async (req, res) => {
  try {
    const rows = await Tip.aggregate([{ $match: { result: { $in: ["Win", "Lose", "Void"] } } }, { $group: { _id: "$type", total: { $sum: 1 }, wins: { $sum: { $cond: [{ $eq: ["$result", "Win"] }, 1, 0] } }, losses: { $sum: { $cond: [{ $eq: ["$result", "Lose"] }, 1, 0] } }, voids: { $sum: { $cond: [{ $eq: ["$result", "Void"] }, 1, 0] } } } }]);
    const total = rows.reduce((a, r) => ({ settled: a.settled + r.total, wins: a.wins + r.wins, losses: a.losses + r.losses, voids: a.voids + r.voids }), { settled: 0, wins: 0, losses: 0, voids: 0 });
    res.set("Cache-Control", "public, max-age=60");
    res.json({ success: true, ...total, winRate: total.wins + total.losses ? Math.round(total.wins / (total.wins + total.losses) * 1000) / 10 : null, methodology: "Settled recorded tips only; void tips excluded from win-rate denominator. Historical results do not guarantee future outcomes." });
  } catch (err) { res.status(500).json({ success: false, message: "Performance statistics unavailable." }); }
});

// Admin business overview and payment ledger.
app.get("/api/admin/overview", requireAuth, requireAdmin, async (req, res) => {
  try {
    const [users, payments, tips] = await Promise.all([
      User.aggregate([{ $group: { _id: null, total: { $sum: 1 }, active: { $sum: { $cond: [{ $and: [{ $eq: ["$isActivated", true] }, { $gt: ["$vipExpiresAt", new Date()] }] }, 1, 0] } } } }]),
      Payment.aggregate([{ $group: { _id: "$status", count: { $sum: 1 }, amount: { $sum: "$amount" } } }]),
      Tip.aggregate([{ $group: { _id: "$result", count: { $sum: 1 } } }])
    ]);
    res.json({ success: true, users: users[0] || { total: 0, active: 0 }, payments: payments.map(p => ({ status: p._id, count: p.count, amount: p.amount })), tips: tips.map(t => ({ result: t._id, count: t.count })) });
  } catch (err) { res.status(500).json({ success: false, message: "Admin overview unavailable." }); }
});
app.get("/api/admin/payments", requireAuth, requireAdmin, async (req, res) => {
  try {
    const payments = await Payment.find({}).populate("user", "email phoneNumber").sort({ createdAt: -1 }).limit(500).lean();
    res.json({ success: true, payments: payments.map(p => ({ id: String(p._id), email: p.user?.email || "Deleted user", userPhone: p.user?.phoneNumber || "", phone: p.phone, package: p.package, amount: p.amount, currency: p.currency || "KES", country: p.country || "KE", reference: p.reference, transactionCode: p.transactionCode, status: p.status, createdAt: p.createdAt, completedAt: p.completedAt, message: p.providerMessage })) });
  } catch (err) { res.status(500).json({ success: false, message: "Could not load payment ledger." }); }
});

app.get("/api/admin/tips", requireAuth, requireAdmin, async (req, res) => {
  const tips = await Tip.find({}).sort({ date: -1, createdAt: 1 }).limit(2000).lean();
  res.json({ success: true, tips: tips.map(publicTip) });
});

app.post("/api/admin/tips", requireAuth, requireAdmin, csrfCheck, async (req, res) => {
  try {
    const data = cleanTipInput(req.body);
    const tip = await Tip.create({ ...data, createdBy: req.user._id });
    res.status(201).json({ success: true, tip: publicTip(tip) });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message || "Could not create tip." });
  }
});

app.put("/api/admin/tips/:id", requireAuth, requireAdmin, csrfCheck, async (req, res) => {
  try {
    const data = cleanTipInput(req.body);
    const tip = await Tip.findByIdAndUpdate(req.params.id, { ...data, updatedAt: new Date() }, { new: true, runValidators: true });
    if (!tip) return res.status(404).json({ success: false, message: "Tip not found." });
    res.json({ success: true, tip: publicTip(tip) });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message || "Could not update tip." });
  }
});

app.delete("/api/admin/tips/:id", requireAuth, requireAdmin, csrfCheck, async (req, res) => {
  const tip = await Tip.findByIdAndDelete(req.params.id);
  if (!tip) return res.status(404).json({ success: false, message: "Tip not found." });
  res.json({ success: true, message: "Tip deleted." });
});

// Never allow a user to self-assign the admin role through public registration.
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  res.sendFile(path.join(__dirname, "public", "index.html"), err => {
    if (err) res.status(404).send("Frontend not found. Add your Banker Tips HTML to the public folder.");
  });
});

async function bootstrapAdmin() {
  const email = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password) {
    console.warn("ADMIN_EMAIL/ADMIN_PASSWORD not set; skipping automatic admin bootstrap.");
    return;
  }
  if (!validEmail(email) || password.length < 12) {
    throw new Error("ADMIN_EMAIL must be valid and ADMIN_PASSWORD must be at least 12 characters.");
  }
  let admin = await User.findOne({ email }).select("+passwordHash");
  const passwordHash = await bcrypt.hash(password, 12);
  if (!admin) {
    admin = await User.create({ email, passwordHash, role: "admin", isActivated: true });
    console.log(`Bootstrapped admin account: ${email}`);
  } else {
    admin.role = "admin";
    admin.isActivated = true;
    admin.passwordHash = passwordHash;
    await admin.save();
    console.log(`Admin account verified/updated from environment: ${email}`);
  }
}

mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log("MongoDB connected.");
    await bootstrapAdmin();
    // Sweep immediately at startup and then every minute. Access checks also enforce expiry
    // synchronously, so an expired member cannot keep VIP access while waiting for this sweep.
    await expireMemberships().catch(err => console.error("Initial membership expiry sweep failed:", err.message));
    const expirySweep = setInterval(() => {
      expireMemberships().catch(err => console.error("Membership expiry sweep failed:", err.message));
    }, MEMBERSHIP_SWEEP_INTERVAL_MS);
    if (typeof expirySweep.unref === "function") expirySweep.unref();
    app.listen(PORT, () => console.log(`Banker Tips server listening on port ${PORT}`));
  })
  .catch(err => {
    console.error("MongoDB connection failed:", err.message);
    process.exit(1);
  });

process.on("unhandledRejection", err => console.error("Unhandled rejection:", err));
