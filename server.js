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
let webpush = null;
try { webpush = require("web-push"); } catch (_) { /* Optional until push is configured. */ }

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const COOKIE_NAME = "banker_tips_session";
const TOKEN_TTL = "12h";
const OPTIMAPAY_BASE_URL = "https://optimapaybridge.co.ke/api/v2";
const OPTIMAPAY_GLOBAL_BASE_URL = "https://global.optimapaybridge.co.ke/api/v2";
const DEFAULT_VIP_PRICES = Object.freeze({
  KE: Object.freeze({ daily: 250, weekly: 1500, monthly: 3500 }),
  TZ: Object.freeze({ daily: 5000, weekly: 35000, monthly: 75000 }),
  UG: Object.freeze({ daily: 5000, weekly: 50000, monthly: 110000 })
});
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
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com", "data:"],
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
  country: { type: String, enum: ["KE", "TZ", "UG"], default: "KE", index: true },
  mobileMoneyProvider: { type: String, default: "" },
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
  publicationStatus: { type: String, enum: ["draft", "scheduled", "published"], default: "published", index: true },
  publishAt: { type: Date, default: null, index: true },
  type: { type: String, enum: ["free", "premium", "two_plus"], required: true, index: true },
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

// Prevent the same selection being entered more than once for the same
// match date and category. The case-insensitive unique index also protects
// against simultaneous admin requests reaching MongoDB at the same time.
tipSchema.index(
  { date: 1, type: 1, homeTeam: 1, awayTeam: 1, tip: 1 },
  { unique: true, collation: { locale: "en", strength: 2 }, name: "unique_tip_selection_per_day" }
);

tipSchema.pre("save", function(next) {
  this.updatedAt = new Date();
  next();
});

const paymentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  package: { type: String, enum: ["daily", "weekly", "monthly"], required: true },
  amount: { type: Number, required: true, min: 1 },
  phone: { type: String, required: true },
  country: { type: String, enum: ["KE", "TZ", "UG"], default: "KE", index: true },
  currency: { type: String, enum: ["KES", "TZS", "UGX"], default: "KES" },
  provider: { type: String, default: "kenya_mpesa" },
  providerCode: { type: String, default: null },
  globalReference: { type: String, default: null },
  globalTransactionId: { type: String, default: null },
  reference: { type: String, required: true, unique: true },
  checkoutRequestId: { type: String, unique: true, sparse: true },
  merchantRequestId: { type: String, default: null },
  status: { type: String, enum: ["initiating", "pending", "verifying", "completed", "failed", "verification_error"], default: "initiating", index: true },
  transactionCode: { type: String, default: null },
  providerMessage: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now },
  completedAt: { type: Date, default: null },
  updatedAt: { type: Date, default: Date.now }
}, { versionKey: false });

const User = mongoose.model("User", userSchema);
const Tip = mongoose.model("Tip", tipSchema);
const Payment = mongoose.model("Payment", paymentSchema);
const pushSubscriptionSchema = new mongoose.Schema({
  endpoint: { type: String, required: true, unique: true },
  subscription: { type: mongoose.Schema.Types.Mixed, required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null, index: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { versionKey: false });
const PushSubscription = mongoose.model("PushSubscription", pushSubscriptionSchema);

const matchFixtureSchema = new mongoose.Schema({
  league: { type: String, trim: true, maxlength: 100, default: "" },
  homeTeam: { type: String, required: true, trim: true, maxlength: 100 },
  awayTeam: { type: String, required: true, trim: true, maxlength: 100 },
  date: { type: String, required: true, match: /^\d{4}-\d{2}-\d{2}$/, index: true },
  time: { type: String, trim: true, maxlength: 5, default: "" },
  status: { type: String, enum: ["scheduled", "live", "finished", "postponed", "cancelled"], default: "scheduled", index: true },
  homeScore: { type: Number, min: 0, max: 99, default: null },
  awayScore: { type: Number, min: 0, max: 99, default: null },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { versionKey: false });
matchFixtureSchema.index({ date: 1, time: 1, league: 1 });
const MatchFixture = mongoose.model("MatchFixture", matchFixtureSchema);


// One persistent document stores the editable VIP prices for all supported countries.
const vipPricingSchema = new mongoose.Schema({
  key: { type: String, unique: true, default: "default" },
  prices: { type: mongoose.Schema.Types.Mixed, required: true }
}, { timestamps: true, versionKey: false });
const VipPricing = mongoose.model("VipPricing", vipPricingSchema);

async function getVipPrices() {
  const saved = await VipPricing.findOne({ key: "default" }).lean();
  const stored = saved && saved.prices && typeof saved.prices === "object" ? saved.prices : {};
  const result = {};
  for (const country of ["KE", "TZ", "UG"]) {
    result[country] = {};
    for (const plan of ["daily", "weekly", "monthly"]) {
      const value = Number(stored?.[country]?.[plan]);
      result[country][plan] = Number.isSafeInteger(value) && value > 0
        ? value : DEFAULT_VIP_PRICES[country][plan];
    }
  }
  return result;
}

function validateVipPrices(input) {
  const output = {};
  for (const country of ["KE", "TZ", "UG"]) {
    output[country] = {};
    for (const plan of ["daily", "weekly", "monthly"]) {
      const amount = Number(input?.[country]?.[plan]);
      if (!Number.isSafeInteger(amount) || amount < 1 || amount > 100000000) {
        throw new Error(`Enter a whole-number ${country} ${plan} price between 1 and 100,000,000.`);
      }
      output[country][plan] = amount;
    }
  }
  return output;
}

const auditLogSchema = new mongoose.Schema({
  actor: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
  actorEmail: { type: String, default: "system", maxlength: 254 },
  action: { type: String, required: true, maxlength: 80, index: true },
  entityType: { type: String, required: true, maxlength: 40 },
  entityId: { type: String, default: "", maxlength: 100 },
  summary: { type: String, required: true, maxlength: 500 },
  createdAt: { type: Date, default: Date.now, index: true }
}, { versionKey: false });
const AuditLog = mongoose.model("AuditLog", auditLogSchema);

const advertisementSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true, maxlength: 100 },
  description: { type: String, required: true, trim: true, maxlength: 240 },
  imageUrl: { type: String, trim: true, maxlength: 1000, default: "" },
  buttonText: { type: String, trim: true, maxlength: 35, default: "Learn more" },
  targetUrl: { type: String, required: true, trim: true, maxlength: 1000 },
  status: { type: String, enum: ["draft", "active", "paused"], default: "draft", index: true },
  position: { type: String, enum: ["home_vip"], default: "home_vip", index: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { versionKey: false });
advertisementSchema.index({ position: 1, status: 1, updatedAt: -1 });
const Advertisement = mongoose.model("Advertisement", advertisementSchema);

// Privacy-conscious website analytics: anonymous random visitor IDs only.
const visitorEventSchema = new mongoose.Schema({
  visitorId: { type: String, required: true, index: true },
  path: { type: String, required: true, maxlength: 180, index: true },
  createdAt: { type: Date, default: Date.now, index: true }
}, { versionKey: false });
visitorEventSchema.index({ createdAt: 1 }, { expireAfterSeconds: 400 * 24 * 60 * 60 });
const VisitorEvent = mongoose.model("VisitorEvent", visitorEventSchema);
const visitorPresenceSchema = new mongoose.Schema({
  visitorId: { type: String, required: true, unique: true },
  lastSeen: { type: Date, required: true }
}, { versionKey: false });
visitorPresenceSchema.index({ lastSeen: 1 }, { expireAfterSeconds: 15 *  60 });
const VisitorPresence = mongoose.model("VisitorPresence", visitorPresenceSchema);

async function recordAudit(req, action, entityType, entityId, summary) {
  try { await AuditLog.create({ actor: req.user?._id || null, actorEmail: req.user?.email || "system", action, entityType, entityId: String(entityId || ""), summary }); }
  catch (err) { console.error("Audit log write failed:", err.message); }
}

function safeUser(user) {
  return {
    id: String(user._id),
    email: user.email,
    phoneNumber: user.phoneNumber || "",
    country: user.country || "KE",
    mobileMoneyProvider: user.mobileMoneyProvider || "",
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
    if (user.role === "admin") {
      let changed = false;
      if (user.isActivated !== true) { user.isActivated = true; changed = true; }
      if (user.membershipStatus !== "active") { user.membershipStatus = "active"; changed = true; }
      if (user.vipExpiresAt != null) { user.vipExpiresAt = null; changed = true; }
      if (user.selectedPackage != null) { user.selectedPackage = null; changed = true; }
      if (changed) await user.save();
    } else {
      await expireUserIfNeeded(user);
    }
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

function nextNairobiMidnight(from = new Date()) {
  const { year, month, day } = nairobiDateParts(from);
  return new Date(Date.UTC(year, month - 1, day + 1, -3, 0, 0, 0));
}

function calculatePackageExpiry(packageKey, existingExpiry = null, currentlyActive = false, now = new Date()) {
  const validExistingExpiry = currentlyActive && existingExpiry && new Date(existingExpiry).getTime() > now.getTime();
  const base = validExistingExpiry ? new Date(existingExpiry) : now;
  if (packageKey === "daily") {
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
// 2+ Odds is reserved for administrators and active Weekly / Monthly subscribers.
function hasTwoPlusOddsAccess(user) {
  if (!user) return false;
  if (user.role === "admin") return true;
  return hasActiveVip(user) && ["weekly", "monthly"].includes(String(user.selectedPackage || "").toLowerCase());
}
function cleanTipInput(body) {
  const type = body.type;
  const date = String(body.date || "");
  let homeTeam = String(body.homeTeam || "").trim().replace(/\s+/g, " ");
  let awayTeam = String(body.awayTeam || "").trim().replace(/\s+/g, " ");
  const suppliedMatch = String(body.match || "").trim().replace(/\s+/g, " ");

  if ((!homeTeam || !awayTeam) && suppliedMatch) {
    const parts = suppliedMatch.split(/\s+(?:vs?\.?)\s+|\s*[-–—]\s*/i);
    if (parts.length >= 2) {
      if (!homeTeam) homeTeam = parts[0].trim();
      if (!awayTeam) awayTeam = parts.slice(1).join(" - ").trim();
    }
  }

  const match = suppliedMatch || `${homeTeam} vs ${awayTeam}`;
  const tip = String(body.tip || "").trim().replace(/\s+/g, " ");
  const odds = Number(body.odds);
  const incomingStatus = String(body.status || body.result || "Pending").toLowerCase();
  const statusToResult = { pending: "Pending", win: "Win", won: "Win", lose: "Lose", lost: "Lose", void: "Void" };
  const result = statusToResult[incomingStatus];
  if (!["free", "premium", "two_plus"].includes(type)) throw new Error("Type must be free, premium or two_plus.");
  const parsedDate = new Date(`${date}T00:00:00.000Z`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !Number.isFinite(parsedDate.getTime()) || parsedDate.toISOString().slice(0, 10) !== date) throw new Error("Date must be a valid calendar date in YYYY-MM-DD format.");
  if (!homeTeam || !awayTeam || !match || !tip || !Number.isFinite(odds) || odds < 1 || odds > 1000) {
    throw new Error("Match must include both teams, a tip, and valid odds. Enter it as Home Team - Away Team.");
  }
  if (type === "two_plus" && odds < 2) {
    throw new Error("2+ Odds selections must have decimal odds of 2.00 or higher.");
  }
  if (!result) throw new Error("Invalid result.");
  const time = String(body.time || "").trim();
  if (time && !/^(?:[01]\d|2[0-3]):[0-5]\d$/.test(time)) throw new Error("Kick-off time must use 24-hour HH:MM format.");
  const publicationStatus = String(body.publicationStatus || (date > footballDateISO() ? "scheduled" : "published")).toLowerCase();
  if (!["draft", "scheduled", "published"].includes(publicationStatus)) throw new Error("Invalid publication status.");
  const publishAt = publicationStatus === "scheduled"
    ? new Date(zonedDateTimeToEpoch(date, "00:00", APP_TIME_ZONE)) : null;
  return {
    type, date, publicationStatus, publishAt, homeTeam, awayTeam, match, time, tip, odds, result,
    league: String(body.league || "").trim(), notes: String(body.notes || "").trim()
  };
}


function cleanAdvertisementInput(body = {}) {
  const title = String(body.title || "").trim();
  const description = String(body.description || "").trim();
  const imageUrl = String(body.imageUrl || body.image || "").trim();
  const buttonText = String(body.buttonText || "Learn more").trim();
  const targetUrl = String(body.targetUrl || body.url || "").trim();
  const status = String(body.status || "draft").toLowerCase();
  const position = String(body.position || "home_vip").toLowerCase();

  const validWebUrl = value => {
    if (!value) return false;
    try {
      const parsed = new URL(value);
      return ["http:", "https:"].includes(parsed.protocol) && Boolean(parsed.hostname);
    } catch { return false; }
  };

  if (!title || title.length > 100) throw new Error("Advertisement title is required (maximum 100 characters).");
  if (!description || description.length > 240) throw new Error("Advertisement description is required (maximum 240 characters).");
  if (!validWebUrl(targetUrl) || targetUrl.length > 1000) throw new Error("Enter a valid HTTP or HTTPS destination URL (maximum 1000 characters).");
  const normalizedImagePath = imageUrl.replace(/^\/+/, "");
  const isLocalBannerPath = /^banners\/[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(normalizedImagePath)
    && !normalizedImagePath.split("/").includes("..");
  if (imageUrl && ((!isLocalBannerPath && !validWebUrl(imageUrl)) || imageUrl.length > 1000)) {
    throw new Error("Image must be a valid path inside public/banners (e.g. banners/helabet.jpg) or a valid HTTP/HTTPS URL.");
  }
  if (!buttonText || buttonText.length > 35) throw new Error("Button text is required (maximum 35 characters).");
  if (!["draft", "active", "paused"].includes(status)) throw new Error("Choose draft, active or paused as the publication status.");
  if (position !== "home_vip") throw new Error("Unsupported advertisement placement.");

  const storedImageUrl = isLocalBannerPath ? `/${normalizedImagePath}` : imageUrl;
  return { title, description, imageUrl: storedImageUrl, buttonText, targetUrl, status, position };
}
function publicAdvertisement(ad) {
  return {
    id: String(ad._id || ad.id),
    title: ad.title,
    description: ad.description,
    imageUrl: ad.imageUrl || "",
    buttonText: ad.buttonText || "Learn more",
    targetUrl: ad.targetUrl,
    status: ad.status,
    position: ad.position || "home_vip",
    createdAt: ad.createdAt,
    updatedAt: ad.updatedAt
  };
}
async function publishSingleHomepageAdvertisement(advertisementId) {
  await Advertisement.updateMany(
    { position: "home_vip", status: "active", _id: { $ne: advertisementId } },
    { $set: { status: "paused", updatedAt: new Date() } }
  );
}

function normalizeKenyanPhone(value) {
  let phone = String(value || "").replace(/[\s()-]/g, "");
  if (phone.startsWith("+")) phone = phone.slice(1);
  if (/^0[17]\d{8}$/.test(phone)) phone = "254" + phone.slice(1);
  if (!/^254[17]\d{8}$/.test(phone)) return null;
  return phone;
}
function normalizePhoneForCountry(value, country) {
  let phone = String(value || "").replace(/[\s()-]/g, "");
  if (phone.startsWith("+")) phone = phone.slice(1);
  if (country === "KE") return normalizeKenyanPhone(phone);
  if (country === "TZ") {
    if (/^0[67]\d{8}$/.test(phone)) phone = "255" + phone.slice(1);
    return /^255[67]\d{8}$/.test(phone) ? phone : null;
  }
  if (country === "UG") {
    if (/^0[37]\d{8}$/.test(phone)) phone = "256" + phone.slice(1);
    return /^256[37]\d{8}$/.test(phone) ? phone : null;
  }
  return null;
}
function kenyaOptimaPayConfig() {
  return {
    key: process.env.KE_OPTIMAPAY_API_KEY || process.env.OPTIMAPAY_API_KEY,
    secret: process.env.KE_OPTIMAPAY_API_SECRET || process.env.OPTIMAPAY_API_SECRET,
    accountId: process.env.KE_OPTIMAPAY_PAYMENT_ACCOUNT_ID || process.env.OPTIMAPAY_PAYMENT_ACCOUNT_ID
  };
}

function tanzaniaUgandaOptimaPayConfig() {
  return {
    key: process.env.TZUG_OPTIMAPAY_API_KEY,
    secret: process.env.TZUG_OPTIMAPAY_API_SECRET,
    accountId: process.env.TZUG_OPTIMAPAY_ACCOUNT_ID
  };
}

async function optimapayGlobalRequest(method, endpoint, payload) {
  // Tanzania and Uganda intentionally share one Global API credential pair and merchant account.
  const config = tanzaniaUgandaOptimaPayConfig();
  const { key, secret } = config;
  if (!key || !secret) throw new Error("Shared Tanzania/Uganda OptimaPay Global API credentials are not configured.");
  const response = await fetch(`${OPTIMAPAY_GLOBAL_BASE_URL}/${endpoint}`, {
    method,
    headers: { "X-API-KEY": key, "X-API-SECRET": secret, "Content-Type": "application/json", "Accept": "application/json" },
    ...(payload ? { body: JSON.stringify(payload) } : {}),
    signal: AbortSignal.timeout(20000)
  });
  let data; try { data = await response.json(); } catch { data = null; }
  if (!response.ok || !data || data.success === false) {
    const error = new Error(typeof data?.message === "string" ? data.message : `OptimaPay Global request failed (HTTP ${response.status}).`);
    error.status = response.status; throw error;
  }
  return data;
}

function paymentConfigReady() {
  const config = kenyaOptimaPayConfig();
  const accountId = Number(config.accountId);
  return Boolean(config.key && config.secret && Number.isInteger(accountId) && accountId > 0);
}
async function optimapayPost(endpoint, payload) {
  // Kenya retains its own API key, API secret and payment account ID.
  const config = kenyaOptimaPayConfig();
  const response = await fetch(`${OPTIMAPAY_BASE_URL}/${endpoint}`, {
    method: "POST",
    headers: {
      "X-API-Key": config.key,
      "X-API-Secret": config.secret,
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(15000)
  });
  let data;
  try { data = await response.json(); } catch { data = null; }
  if (!response.ok || !data || data.success === false) {
    const message = data && typeof data.message === "string" ? data.message : `OptimaPay request failed (HTTP ${response.status}).`;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return data;
}
async function activatePaidMembership(payment, providerStatus) {
  const reportedAmount = Number(providerStatus.amount);
  const reportedPhone = normalizePhoneForCountry(providerStatus.phone, payment.country || "KE");
  const normalizedStatus = String(providerStatus.status || "").toLowerCase();
  const successful = ["completed", "successful", "success", "paid"].includes(normalizedStatus);
  if (!successful) return false;
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
    const wasActive = user.isActivated && user.membershipStatus === "active";
    user.vipExpiresAt = calculatePackageExpiry(payment.package, user.vipExpiresAt, wasActive);
    user.selectedPackage = payment.package;
    user.isActivated = true;
    user.membershipStatus = "active";
    await user.save();
    payment.status = "completed";
    payment.transactionCode = String(providerStatus.transaction_code || providerStatus.gateway_transaction_id || providerStatus.reference || "").slice(0, 100) || null;
    payment.providerMessage = `Payment verified with OptimaPay (${payment.currency || "KES"}).`;
    payment.completedAt = new Date();
    payment.updatedAt = new Date();
    await payment.save();
  }
  return true;
}

function publicTip(tip) {
  const obj = typeof tip.toObject === "function" ? tip.toObject() : { ...tip };
  const resultToStatus = { Pending: "Pending", Win: "Won", Lose: "Lost", Void: "Void" };
  const { publicationStatus, publishAt, ...tipFields } = obj;
  return {
    ...tipFields,
    id: String(obj._id || obj.id || ""),
    status: resultToStatus[obj.result] || obj.status || "Pending",
    publicationStatus: obj.publicationStatus || "published",
    publishAt: obj.publishAt || null,
  };
}


// Application timezone used for date-based tip scheduling.
const APP_TIME_ZONE = String(process.env.APP_TIME_ZONE || "Africa/Nairobi");
function footballDateISO(date = new Date()) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: APP_TIME_ZONE, year: "numeric", month: "2-digit", day: "2-digit"
  }).formatToParts(date);
  const values = Object.fromEntries(parts.map(p => [p.type, p.value]));
  return `${values.year}-${values.month}-${values.day}`;
}
function zonedDateTimeToEpoch(date, time, timeZone) {
  const [year, month, day] = String(date).split("-").map(Number);
  const [hour, minute] = String(time).split(":").map(Number);
  if (![year, month, day, hour, minute].every(Number.isFinite)) return null;
  const desired = Date.UTC(year, month - 1, day, hour, minute);
  let guess = desired;
  for (let i = 0; i < 2; i++) {
    const parts = new Intl.DateTimeFormat("en-GB", {
      timeZone, year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", hourCycle: "h23"
    }).formatToParts(new Date(guess));
    const values = Object.fromEntries(parts.map(p => [p.type, p.value]));
    const represented = Date.UTC(Number(values.year), Number(values.month) - 1, Number(values.day),
      Number(values.hour), Number(values.minute));
    guess += desired - represented;
  }
  return guess;
}


app.use("/api", apiLimiter);

function pushConfigReady() { return Boolean(webpush && process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY); }
function configurePush() { if (pushConfigReady()) webpush.setVapidDetails(process.env.VAPID_SUBJECT || "mailto:officialbankertips@gmail.com", process.env.VAPID_PUBLIC_KEY, process.env.VAPID_PRIVATE_KEY); }
async function sendPushToAll(payload) {
  if (!pushConfigReady()) return; configurePush();
  const rows = await PushSubscription.find({}).limit(500);
  await Promise.all(rows.map(async row => { try { await webpush.sendNotification(row.subscription, JSON.stringify(payload)); } catch (err) { if (err.statusCode === 404 || err.statusCode === 410) await PushSubscription.deleteOne({ _id: row._id }); else console.warn("Push delivery failed:", err.statusCode || err.message); } }));
}
app.get("/api/push/public-key", (req, res) => {
  if (!process.env.VAPID_PUBLIC_KEY || !process.env.VAPID_PRIVATE_KEY || !webpush) return res.status(503).json({ success:false, message:"Push notifications are not configured yet. Add VAPID keys and install web-push on the server." });
  res.set("Cache-Control", "public, max-age=3600"); res.json({ success:true, publicKey:process.env.VAPID_PUBLIC_KEY });
});
app.post("/api/push/subscribe", async (req, res) => {
  try { const sub=req.body; if(!sub || typeof sub.endpoint!=="string" || !sub.endpoint.startsWith("https://") || !sub.keys?.p256dh || !sub.keys?.auth) return res.status(400).json({success:false,message:"Invalid push subscription."});
    let user=null; const token=req.cookies?.[COOKIE_NAME]; if(token){try{const decoded=jwt.verify(token,JWT_SECRET);user=decoded.sub;}catch(_){}}
    await PushSubscription.findOneAndUpdate({endpoint:sub.endpoint},{$set:{subscription:sub,user,updatedAt:new Date()},$setOnInsert:{createdAt:new Date()}},{upsert:true,new:true});
    res.status(201).json({success:true,message:"Push subscription saved."});
  } catch(err){console.error("Push subscription save failed:",err.message);res.status(500).json({success:false,message:"Could not save notification subscription."});}
});
app.post("/api/push/unsubscribe", async (req,res)=>{try{const endpoint=String(req.body?.endpoint||"");if(endpoint)await PushSubscription.deleteOne({endpoint});res.json({success:true});}catch(_){res.status(500).json({success:false,message:"Could not remove subscription."});}});
app.post("/api/admin/notifications/broadcast", requireAuth, requireAdmin, csrfCheck, async (req,res)=>{try{const title=String(req.body?.title||"Banker Tips update").trim().slice(0,80);const body=String(req.body?.body||"").trim().slice(0,180);if(!body)return res.status(400).json({success:false,message:"Enter a notification message."});await sendPushToAll({title,body,url:"/"});await recordAudit(req,"notification.broadcast","push","all",title);res.json({success:true,message:"Notification sent to subscribed devices."});}catch(err){res.status(500).json({success:false,message:"Could not send notifications."});}});

function fixturePayload(doc){const x=doc.toObject?doc.toObject():doc;return {id:String(x._id||x.id),league:x.league||"",homeTeam:x.homeTeam,awayTeam:x.awayTeam,date:x.date,time:x.time||"",status:x.status,homeScore:x.homeScore??null,awayScore:x.awayScore??null};}
app.get("/api/matches", async (req,res)=>{try{const date=String(req.query.date||footballDateISO());if(!/^\d{4}-\d{2}-\d{2}$/.test(date))return res.status(400).json({success:false,message:"Use a valid match date."});const matches=await MatchFixture.find({date}).sort({time:1,createdAt:1}).lean();res.set("Cache-Control","no-store");res.json({success:true,date,matches:matches.map(fixturePayload)});}catch(err){res.status(500).json({success:false,message:"Could not load fixtures."});}});
app.get("/api/admin/matches/:id",requireAuth,requireAdmin,async(req,res)=>{const match=await MatchFixture.findById(req.params.id);if(!match)return res.status(404).json({success:false,message:"Fixture not found."});res.json({success:true,match:fixturePayload(match)});});
function validateFixture(body){const data={league:String(body.league||"").trim().slice(0,100),homeTeam:String(body.homeTeam||"").trim().slice(0,100),awayTeam:String(body.awayTeam||"").trim().slice(0,100),date:String(body.date||""),time:String(body.time||"").trim(),status:String(body.status||"scheduled"),homeScore:body.homeScore===null||body.homeScore===""?null:Number(body.homeScore),awayScore:body.awayScore===null||body.awayScore===""?null:Number(body.awayScore)};if(!data.homeTeam||!data.awayTeam||data.homeTeam===data.awayTeam)throw new Error("Enter two different team names.");if(!/^\d{4}-\d{2}-\d{2}$/.test(data.date))throw new Error("Choose a valid match date.");if(data.time&&!/^([01]\d|2[0-3]):[0-5]\d$/.test(data.time))throw new Error("Enter kick-off time in HH:MM format.");if(!["scheduled","live","finished","postponed","cancelled"].includes(data.status))throw new Error("Choose a valid fixture status.");for(const k of ["homeScore","awayScore"])if(data[k]!==null&&(!Number.isInteger(data[k])||data[k]<0||data[k]>99))throw new Error("Scores must be whole numbers from 0 to 99.");return data;}
app.post("/api/admin/matches",requireAuth,requireAdmin,csrfCheck,async(req,res)=>{try{const match=await MatchFixture.create(validateFixture(req.body));await recordAudit(req,"match.created","match",match._id,`${match.homeTeam} vs ${match.awayTeam}`);res.status(201).json({success:true,match:fixturePayload(match)});}catch(err){res.status(400).json({success:false,message:err.message||"Could not create fixture."});}});
app.put("/api/admin/matches/:id",requireAuth,requireAdmin,csrfCheck,async(req,res)=>{try{const match=await MatchFixture.findByIdAndUpdate(req.params.id,{...validateFixture(req.body),updatedAt:new Date()},{new:true,runValidators:true});if(!match)return res.status(404).json({success:false,message:"Fixture not found."});await recordAudit(req,"match.updated","match",match._id,`${match.homeTeam} vs ${match.awayTeam} · ${match.status}`);res.json({success:true,match:fixturePayload(match)});}catch(err){res.status(400).json({success:false,message:err.message||"Could not update fixture."});}});
app.delete("/api/admin/matches/:id",requireAuth,requireAdmin,csrfCheck,async(req,res)=>{const match=await MatchFixture.findByIdAndDelete(req.params.id);if(!match)return res.status(404).json({success:false,message:"Fixture not found."});await recordAudit(req,"match.deleted","match",match._id,`${match.homeTeam} vs ${match.awayTeam}`);res.json({success:true,message:"Fixture deleted."});});


app.get("/api/health", (req, res) => {
  res.json({ success: true, status: "ok", database: mongoose.connection.readyState === 1 ? "connected" : "connecting" });
});

// Public prices are read-only; only authenticated administrators can change them.
app.get("/api/pricing", async (req, res) => {
  try {
    res.set("Cache-Control", "no-store, max-age=0");
    res.json({ success: true, prices: await getVipPrices() });
  } catch (err) {
    console.error("Public VIP pricing load failed:", err.message);
    res.status(500).json({ success: false, message: "VIP prices are temporarily unavailable." });
  }
});

app.get("/api/admin/vip-prices", requireAuth, requireAdmin, async (req, res) => {
  try {
    res.set("Cache-Control", "private, no-store, max-age=0");
    res.json({ success: true, prices: await getVipPrices() });
  } catch (err) {
    res.status(500).json({ success: false, message: "Could not load VIP pricing settings." });
  }
});

app.put("/api/admin/vip-prices", requireAuth, requireAdmin, csrfCheck, async (req, res) => {
  try {
    const prices = validateVipPrices(req.body?.prices);
    await VipPricing.findOneAndUpdate(
      { key: "default" },
      { $set: { prices }, $setOnInsert: { key: "default" } },
      { new: true, upsert: true, setDefaultsOnInsert: true, runValidators: true }
    );
    await recordAudit(req, "vip-prices.updated", "vip-pricing", "default", "Updated VIP package prices for Kenya, Tanzania and Uganda.");
    res.set("Cache-Control", "no-store, max-age=0");
    res.json({ success: true, prices, message: "VIP prices updated successfully." });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message || "Could not save VIP prices." });
  }
});

app.post("/api/auth/register", authLimiter, csrfCheck, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const phoneNumber = String(req.body.phoneNumber || "").trim();
    const password = req.body.password;
    const selectedPackage = String(req.body.selectedPackage || "").toLowerCase();
    const country = String(req.body.country || "KE").toUpperCase();
    const mobileMoneyProvider = String(req.body.provider || "").toUpperCase();
    
    if (!["KE", "TZ", "UG"].includes(country)) return res.status(400).json({ success: false, message: "Choose Kenya, Tanzania or Uganda." });
    if (country === "TZ" && !["VODACOM", "YAS", "AIRTEL", "HALOTEL"].includes(mobileMoneyProvider)) return res.status(400).json({ success: false, message: "Select your Tanzania mobile-money network." });
    if (!["daily", "weekly", "monthly"].includes(selectedPackage)) {
      return res.status(400).json({ success: false, message: "Choose a valid subscription package before registering." });
    }
    if (!validEmail(email)) {
      return res.status(400).json({ success: false, message: "Enter a valid email address." });
    }
    if (typeof password !== "string" || password.length < 10 || password.length > 128) {
      return res.status(400).json({ success: false, message: "Password must be 10–128 characters." });
    }
    if (phoneNumber.length > 30) {
      return res.status(400).json({ success: false, message: "Phone number is too long." });
    }

    const normalizedRegistrationPhone = normalizePhoneForCountry(phoneNumber, country);
    if (!normalizedRegistrationPhone) return res.status(400).json({ success: false, message: `Enter a valid ${country === "KE" ? "Kenyan" : country === "TZ" ? "Tanzanian" : "Ugandan"} mobile number.` });
    // Prevent registration using the example Kenyan mobile number.
    if (country === "KE" && normalizedRegistrationPhone === "254712345678") {
      return res.status(400).json({ 
        success: false, 
        message: "The number +254712345678 serves as an example format and cannot be used to register. Please enter your actual mobile number." 
      });
    }

    // Match legacy mixed-case records too; all new addresses are stored lowercase.
    const exists = await User.findOne({ email: new RegExp("^" + email.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "$", "i") }).select("_id");
    if (exists) return res.status(409).json({ success: false, code: "EMAIL_ALREADY_EXISTS", message: "This email address is already registered. Please log in or use a different email address." });
    
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ email, phoneNumber: "+" + normalizedRegistrationPhone, country, mobileMoneyProvider: country === "TZ" ? mobileMoneyProvider : "", passwordHash, role: "user", selectedPackage, isActivated: false, membershipStatus: "pending_approval", vipExpiresAt: null });
    setSession(res, user);
    res.status(201).json({ success: true, message: "Account created. VIP access remains locked until an administrator activates it.", user: safeUser(user) });
  } catch (err) {
    if (err.code === 11000 && (err.keyPattern?.email || err.keyValue?.email || /email_1/i.test(err.message || ""))) return res.status(409).json({ success: false, code: "EMAIL_ALREADY_EXISTS", message: "This email address is already registered. Please log in or use a different email address." });
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
  res.set("Cache-Control", "private, no-store, max-age=0");
  res.json({ success: true, user: safeUser(req.user) });
});

app.post("/api/membership/renew-package", requireAuth, csrfCheck, async (req, res) => {
  try {
    if (req.user.role === "admin") return res.status(400).json({ success: false, message: "Admin accounts do not need a VIP subscription." });
    const packageKey = String(req.body.selectedPackage || "").toLowerCase();
    const currentPrices = await getVipPrices();
    const country = String(req.user.country || "KE").toUpperCase();
    if (!["KE", "TZ", "UG"].includes(country) || !Object.prototype.hasOwnProperty.call(currentPrices[country] || {}, packageKey)) return res.status(400).json({ success: false, message: "Choose a valid VIP package." });
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

app.post("/api/payments/optimapay/stkpush", requireAuth, csrfCheck, async (req, res) => {
  let payment;
  try {
    if (req.user.role === "admin") return res.status(400).json({ success: false, message: "Admin accounts do not need a VIP payment." });
    if (!paymentConfigReady()) return res.status(503).json({ success: false, message: "M-Pesa payments are not configured yet. Please contact support." });
    const packageKey = req.user.selectedPackage;
    const currentPrices = await getVipPrices();
    if (!currentPrices.KE[packageKey]) return res.status(400).json({ success: false, message: "Choose a VIP package before paying." });
    const phone = normalizeKenyanPhone(req.body.phone || req.user.phoneNumber);
    if (!phone) return res.status(400).json({ success: false, message: "Enter a valid Kenyan M-Pesa number, e.g. 0712345678 or 254712345678." });
    const reference = `BT${Date.now().toString(36).toUpperCase()}${crypto.randomBytes(3).toString("hex").toUpperCase()}`.slice(0, 30);
    payment = await Payment.create({ user: req.user._id, package: packageKey, amount: currentPrices.KE[packageKey], phone, reference, status: "initiating" });
    const provider = await optimapayPost("stkpush.php", {
      payment_account_id: Number(kenyaOptimaPayConfig().accountId),
      phone,
      amount: payment.amount,
      reference,
      description: `Banker Tips ${packageKey} VIP membership`
    });
    if (!provider.checkout_request_id) throw new Error("OptimaPay response did not include checkout_request_id.");
    payment.checkoutRequestId = String(provider.checkout_request_id).slice(0, 200);
    payment.merchantRequestId = String(provider.merchant_request_id || "").slice(0, 200) || null;
    payment.status = "pending";
    payment.providerMessage = String(provider.message || "STK push sent. Complete the prompt on your phone.").slice(0, 300);
    await payment.save();
    res.status(202).json({ success: true, message: "STK Push sent. Enter your M-Pesa PIN on your phone, then wait while we verify the payment.", paymentId: String(payment._id), amount: payment.amount, package: payment.package, status: payment.status });
  } catch (err) {
    if (payment) {
      payment.status = "failed";
      payment.providerMessage = String(err.message || "STK push failed.").slice(0, 300);
      await payment.save().catch(() => {});
    }
    console.error("OptimaPay STK Push error:", err.message);
    res.status(502).json({ success: false, message: "Could not initiate M-Pesa payment. Please check your details and try again." });
  }
});

app.post("/api/payments/optimapay/global", requireAuth, csrfCheck, async (req, res) => {
  let payment;
  try {
    if (req.user.role === "admin") return res.status(400).json({ success: false, message: "Admin accounts do not need a VIP payment." });
    const country = String(req.user.country || "KE").toUpperCase();
    if (!["TZ", "UG"].includes(country)) return res.status(400).json({ success: false, message: "This checkout is for Tanzania and Uganda. Kenya payments continue through the existing M-Pesa checkout." });
    const packageKey = req.user.selectedPackage;
    const allPrices = await getVipPrices();
    const prices = allPrices[country];
    if (!prices || !prices[packageKey]) return res.status(400).json({ success: false, message: "Choose a valid VIP package before paying." });
    const phone = normalizePhoneForCountry(req.body.phone || req.user.phoneNumber, country);
    if (!phone) return res.status(400).json({ success: false, message: `Enter a valid ${country === "TZ" ? "Tanzanian" : "Ugandan"} mobile number in local or international format.` });
    const providerCode = country === "TZ" ? String(req.body.provider || req.user.mobileMoneyProvider || "").toUpperCase() : null;
    if (country === "TZ" && !["VODACOM", "YAS", "AIRTEL", "HALOTEL"].includes(providerCode)) return res.status(400).json({ success: false, message: "Select Vodacom, YAS, Airtel or Halotel before continuing." });
    const currency = country === "TZ" ? "TZS" : "UGX";
    const amount = prices[packageKey];
    const reference = `BT${country}${Date.now().toString(36).toUpperCase()}${crypto.randomBytes(4).toString("hex").toUpperCase()}`.slice(0, 50);
    payment = await Payment.create({ user: req.user._id, package: packageKey, amount, phone, country, currency, provider: country === "TZ" ? "optimapay_tanzania" : "optimapay_uganda", providerCode, reference, status: "initiating" });
    const endpoint = country === "TZ" ? "godigital/tz/collect" : "collecto/initiate";
    const payload = country === "TZ"
      ? { providerCode, phone, amount, reference, description: `Banker Tips ${packageKey} VIP membership` }
      : { phone, amount, reference, description: `Banker Tips ${packageKey} VIP membership` };
    const result = await optimapayGlobalRequest("POST", endpoint, payload);
    const data = result.data || {};
    if (country === "TZ" && !["202", "200"].includes(String(result.http_status || result.status_code || "202"))) {
      throw new Error(result.message || "Tanzania payment request was not accepted.");
    }
    const globalRef = String(data.reference || data.client_reference || reference).slice(0, 100);
    payment.globalReference = globalRef;
    payment.globalTransactionId = data.transaction_id != null ? String(data.transaction_id) : null;
    payment.providerMessage = String(result.message || "Payment prompt submitted. Complete the prompt on your phone; final confirmation is still pending.").slice(0, 300);
    const providerState = String(data.status || "PENDING").toUpperCase();
    payment.status = ["FAILED", "REJECTED", "CANCELLED"].includes(providerState) ? "failed" : "pending";
    await payment.save();
    if (payment.status === "failed") return res.status(400).json({ success: false, message: payment.providerMessage });
    return res.status(202).json({ success: true, message: payment.providerMessage, paymentId: String(payment._id), amount, currency, package: packageKey, status: payment.status });
  } catch (err) {
    console.error("OptimaPay Global initiation error:", err.message);
    const ambiguous = Boolean(payment && (err.status === 502 || err.name === "AbortError" || err.name === "TimeoutError" || /timeout|network|fetch failed|socket/i.test(String(err.message || ""))));
    if (payment && ambiguous) {
      // A timeout does not prove the gateway rejected the collection. Keep the original merchant reference
      // queryable so the next status check reconciles the first request instead of creating a duplicate.
      payment.globalReference = payment.reference;
      payment.status = "pending";
      payment.providerMessage = "The gateway response is not yet confirmed. Checking the original transaction reference; please do not retry payment.";
      await payment.save().catch(() => {});
      return res.status(202).json({ success: true, message: payment.providerMessage, paymentId: String(payment._id), amount: payment.amount, currency: payment.currency, package: payment.package, status: payment.status });
    }
    if (payment) { payment.status = "failed"; payment.providerMessage = String(err.message || "Payment initiation failed.").slice(0, 300); await payment.save().catch(() => {}); }
    return res.status(err.status || 502).json({ success: false, message: "Could not initiate mobile-money payment. " + String(err.message || "Please check the number and try again.") });
  }
});

app.get("/api/payments/:paymentId/status", requireAuth, async (req, res) => {
  try {
    let payment = await Payment.findOne({ _id: req.params.paymentId, user: req.user._id });
    if (!payment) return res.status(404).json({ success: false, message: "Payment not found." });
    const hasProviderIdentifier = Boolean(payment.checkoutRequestId || payment.globalReference || payment.globalTransactionId);
    const staleVerification = payment.status === "verifying" && Date.now() - new Date(payment.updatedAt || payment.createdAt).getTime() > 2 * 60 * 1000;
    if ((payment.status === "pending" || staleVerification) && hasProviderIdentifier) {
      if ((!payment.provider || payment.provider === "kenya_mpesa") && !paymentConfigReady()) return res.status(503).json({ success: false, message: "Payment verification is not configured." });
      const claimFilter = { _id: payment._id, $or: [{ status: "pending" }, ...(staleVerification ? [{ status: "verifying" }] : [])] };
      const claimed = await Payment.findOneAndUpdate(claimFilter, { $set: { status: "verifying", updatedAt: new Date() } }, { new: true });
      if (claimed) {
        payment = await Payment.findById(payment._id);
        try {
          let provider;
          if (!payment.provider || payment.provider === "kenya_mpesa") {
            provider = await optimapayPost("status.php", { checkout_request_id: payment.checkoutRequestId });
          } else {
            const identifier = payment.globalReference || payment.globalTransactionId;
            const statusEndpoint = payment.country === "TZ" ? `godigital/tz/status/${encodeURIComponent(identifier)}` : `collecto/status/${encodeURIComponent(identifier)}`;
            const response = await optimapayGlobalRequest("GET", statusEndpoint);
            // Global API status responses wrap the transaction in `data`; tolerate
            // both the documented wrapper and a direct transaction payload.
            provider = response && response.data && typeof response.data === "object" ? response.data : response;
          }
          const status = String(provider.status || provider.payment_status || "").trim().toLowerCase();
          if (["completed", "successful", "success", "paid"].includes(status)) {
            await activatePaidMembership(payment, provider);
          } else if (["failed", "cancelled", "canceled", "rejected"].includes(status)) {
            payment.status = "failed";
            payment.providerMessage = String(provider.message || provider.ResultDesc || "Payment failed or was cancelled.").slice(0, 300);
            payment.updatedAt = new Date();
            await payment.save();
          } else {
            payment.status = "pending";
            payment.providerMessage = String(provider.message || provider.ResultDesc || "Payment is still pending.").slice(0, 300);
            payment.updatedAt = new Date();
            await payment.save();
          }
        } catch (providerError) {
          payment.status = "pending";
          payment.updatedAt = new Date();
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
  res.set("Cache-Control", "private, no-store, max-age=0");
  res.set("Pragma", "no-cache");
  try {
    const type = String(req.query.type || "free").toLowerCase();
    const date = String(req.query.date || footballDateISO());
    if (!["free", "premium", "two_plus"].includes(type)) {
      return res.status(400).json({ success: false, message: "Invalid tips type." });
    }
    if (type === "premium" || type === "two_plus") {
      const token = req.cookies[COOKIE_NAME];
      if (!token) return res.status(401).json({ success: false, message: "Log in to access these tips." });
      let decoded;
      try { decoded = jwt.verify(token, JWT_SECRET); }
      catch { clearSession(res); return res.status(401).json({ success: false, message: "Please log in again." }); }
      const user = await User.findById(decoded.sub);
      if (!user) return res.status(401).json({ success: false, message: "Your account could not be verified." });
      await expireUserIfNeeded(user);
      const allowed = type === "premium" ? hasActiveVip(user) : hasTwoPlusOddsAccess(user);
      if (!allowed) {
        const message = type === "two_plus"
          ? "2+ Odds is available to Admin, active Weekly and active Monthly subscribers only."
          : "VIP access is not active. Contact the administrator after payment.";
        return res.status(403).json({ success: false, authorized: false, message });
      }
    }
    const now = new Date();
    const tips = await Tip.find({ type, date, ...(type === "two_plus" ? { odds: { $gte: 2 } } : {}), $or: [
      { publicationStatus: { $exists: false } },
      { publicationStatus: "published" },
      { publicationStatus: "scheduled", publishAt: { $lte: now } }
    ] }).sort({ createdAt: 1 }).lean();
    res.json({ success: true, authorized: true, tips: tips.map(publicTip) });
  } catch (err) {
    console.error("Tips error:", err.message);
    res.status(500).json({ success: false, message: "Could not load tips." });
  }
});

app.get("/api/tips/history", async (req, res) => {
  res.set("Cache-Control", "private, no-store, max-age=0");
  res.set("Pragma", "no-cache");
  try {
    const type = String(req.query.type || "free").toLowerCase();
    if (!["free", "premium", "two_plus"].includes(type)) {
      return res.status(400).json({ success: false, authorized: false, message: "Invalid tips type." });
    }
    let authorized = type === "free";
    if (type === "premium" || type === "two_plus") {
      const token = req.cookies[COOKIE_NAME];
      if (!token) return res.status(401).json({ success: false, authorized: false, message: "Log in to access this tips history." });
      let decoded;
      try { decoded = jwt.verify(token, JWT_SECRET); }
      catch {
        clearSession(res);
        return res.status(401).json({ success: false, authorized: false, message: "Your session has expired. Please log in again." });
      }
      const user = await User.findById(decoded.sub);
      if (!user) return res.status(401).json({ success: false, authorized: false, message: "Your account could not be verified." });
      await expireUserIfNeeded(user);
      const allowed = type === "premium" ? hasActiveVip(user) : hasTwoPlusOddsAccess(user);
      if (!allowed) {
        const message = type === "two_plus"
          ? "2+ Odds history is available to Admin, active Weekly and active Monthly subscribers only."
          : "Active VIP membership is required to view premium history.";
        return res.status(403).json({ success: false, authorized: false, message });
      }
      authorized = true;
    }
    const tips = await Tip.find({ type, ...(type === "two_plus" ? { odds: { $gte: 2 } } : {}), $or: [
      { publicationStatus: { $exists: false } },
      { publicationStatus: "published" },
      { publicationStatus: "scheduled", publishAt: { $lte: new Date() } }
    ] }).sort({ date: -1, createdAt: 1, _id: 1 }).limit(500).lean();
    return res.json({ success: true, authorized, type, count: tips.length, tips: tips.map(publicTip) });
  } catch (err) {
    console.error("History error:", err.message);
    return res.status(500).json({ success: false, authorized: false, message: "Could not load history." });
  }
});

// Public homepage advertisement: only the currently published homepage ad is returned.
app.get("/api/advertisements/active", async (req, res) => {
  try {
    res.set("Cache-Control", "no-store, max-age=0");
    const ad = await Advertisement.findOne({ position: "home_vip", status: "active" })
      .sort({ updatedAt: -1, createdAt: -1 }).lean();
    res.json({ success: true, advertisement: ad ? publicAdvertisement(ad) : null });
  } catch (err) {
    console.error("Public advertisement lookup error:", err.message);
    res.status(500).json({ success: false, message: "Could not load homepage advertisement." });
  }
});

// Advertisement management is restricted to authenticated administrators.
app.get("/api/admin/advertisements", requireAuth, requireAdmin, async (req, res) => {
  try {
    const ads = await Advertisement.find({}).sort({ updatedAt: -1, createdAt: -1 }).limit(500).lean();
    res.set("Cache-Control", "private, no-store, max-age=0");
    res.json({ success: true, advertisements: ads.map(publicAdvertisement) });
  } catch (err) {
    console.error("Admin advertisement list error:", err.message);
    res.status(500).json({ success: false, message: "Could not load advertisements." });
  }
});

app.post("/api/admin/advertisements", requireAuth, requireAdmin, csrfCheck, async (req, res) => {
  try {
    const data = cleanAdvertisementInput(req.body);
    const ad = await Advertisement.create({ ...data, createdBy: req.user._id });
    if (ad.status === "active") await publishSingleHomepageAdvertisement(ad._id);
    await recordAudit(req, "advertisement.created", "advertisement", ad._id, `Created homepage advertisement: ${ad.title} (${ad.status})`);
    res.status(201).json({ success: true, message: "Advertisement created.", advertisement: publicAdvertisement(ad) });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message || "Could not create advertisement." });
  }
});

app.put("/api/admin/advertisements/:id", requireAuth, requireAdmin, csrfCheck, async (req, res) => {
  try {
    const data = cleanAdvertisementInput(req.body);
    const ad = await Advertisement.findByIdAndUpdate(
      req.params.id,
      { ...data, updatedAt: new Date() },
      { new: true, runValidators: true }
    );
    if (!ad) return res.status(404).json({ success: false, message: "Advertisement not found." });
    if (ad.status === "active") await publishSingleHomepageAdvertisement(ad._id);
    await recordAudit(req, "advertisement.updated", "advertisement", ad._id, `Updated homepage advertisement: ${ad.title} (${ad.status})`);
    res.json({ success: true, message: "Advertisement updated.", advertisement: publicAdvertisement(ad) });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message || "Could not update advertisement." });
  }
});

app.delete("/api/admin/advertisements/:id", requireAuth, requireAdmin, csrfCheck, async (req, res) => {
  try {
    const ad = await Advertisement.findByIdAndDelete(req.params.id);
    if (!ad) return res.status(404).json({ success: false, message: "Advertisement not found." });
    await recordAudit(req, "advertisement.deleted", "advertisement", ad._id, `Deleted homepage advertisement: ${ad.title}`);
    res.json({ success: true, message: "Advertisement deleted." });
  } catch (err) {
    res.status(400).json({ success: false, message: "Could not delete advertisement." });
  }
});

app.get("/api/admin/users", requireAuth, requireAdmin, async (req, res) => {
  const users = await User.find({}).sort({ createdAt: -1 }).limit(1000).lean();
  res.json({ success: true, users: users.map(u => ({
    id: String(u._id), email: u.email, phoneNumber: u.phoneNumber, country: u.country || "KE",
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
    await recordAudit(req, `membership.${action}`, "user", user._id, `${action} membership for ${user.email}`);
    res.json({ success: true, message: action === "approve" ? "Membership approved and activated." : action === "reject" ? "Membership request rejected." : "VIP access revoked.", user: safeUser(user) });
  } catch (err) {
    console.error("VIP membership update error:", err.message);
    res.status(400).json({ success: false, message: "Could not update VIP membership." });
  }
});

app.get("/api/payments/history", requireAuth, async (req, res) => {
  try {
    const payments = await Payment.find({ user: req.user._id }).sort({ createdAt: -1 }).limit(100).lean();
    res.json({ success: true, payments: payments.map(p => ({ id: String(p._id), package: p.package, amount: p.amount, currency: p.currency || "KES", country: p.country || "KE", provider: p.provider || "kenya_mpesa", phone: p.phone, reference: p.reference, status: p.status, transactionCode: p.transactionCode, message: p.providerMessage, createdAt: p.createdAt, completedAt: p.completedAt })) });
  } catch (err) { res.status(500).json({ success: false, message: "Could not load payment history." }); }
});

app.get("/api/stats/performance", async (req, res) => {
  try {
    const rows = await Tip.aggregate([{ $match: { result: { $in: ["Win", "Lose", "Void"] } } }, { $group: { _id: "$type", total: { $sum: 1 }, wins: { $sum: { $cond: [{ $eq: ["$result", "Win"] }, 1, 0] } }, losses: { $sum: { $cond: [{ $eq: ["$result", "Lose"] }, 1, 0] } }, voids: { $sum: { $cond: [{ $eq: ["$result", "Void"] }, 1, 0] } } } }]);
    const total = rows.reduce((a, r) => ({ settled: a.settled + r.total, wins: a.wins + r.wins, losses: a.losses + r.losses, voids: a.voids + r.voids }), { settled: 0, wins: 0, losses: 0, voids: 0 });
    res.set("Cache-Control", "public, max-age=60");
    res.json({ success: true, ...total, winRate: total.wins + total.losses ? Math.round(total.wins / (total.wins + total.losses) * 1000) / 10 : null, methodology: "Settled recorded tips only; void tips excluded from win-rate denominator. " });
  } catch (err) { res.status(500).json({ success: false, message: "Performance statistics unavailable." }); }
});

// Record a page view. Admin sessions are deliberately excluded server-side.
app.post("/api/analytics/visit", apiLimiter, async (req, res) => {
  try {
    const token = req.cookies?.[COOKIE_NAME];
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const account = await User.findById(decoded.sub).select("role").lean();
        if (account?.role === "admin") return res.status(204).end();
      } catch (_) { /* Expired/invalid sessions are treated as anonymous visitors. */ }
    }
    let visitorId = req.cookies?.bt_visitor_id;
    if (!visitorId || !/^[a-f0-9]{64}$/.test(visitorId)) {
      visitorId = crypto.randomBytes(32).toString("hex");
      res.cookie("bt_visitor_id", visitorId, {
        httpOnly: true, secure: process.env.NODE_ENV === "production",
        sameSite: "lax", maxAge: 365 * 24 * 60 * 60 * 1000, path: "/"
      });
    }
    const rawPath = typeof req.body?.path === "string" ? req.body.path : "/";
    const pagePath = rawPath.startsWith("/") && !rawPath.startsWith("//")
      ? rawPath.split(/[?#]/)[0].slice(0, 180) || "/" : "/";
    const seenAt = new Date();
    await VisitorPresence.updateOne({ visitorId }, { $set: { lastSeen: seenAt } }, { upsert: true });
    if (req.body?.heartbeat !== true) {
      await VisitorEvent.create({ visitorId, path: pagePath, createdAt: seenAt });
    }
    return res.status(204).end();
  } catch (err) {
    console.error("Visitor tracking failed:", err.message);
    return res.status(204).end(); // Analytics must never interrupt the website.
  }
});

app.get("/api/admin/visitors", requireAuth, requireAdmin, async (req, res) => {
  try {
    const now = new Date();
    const since30 = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const todayParts = nairobiDateParts(now);
    const sinceToday = new Date(Date.UTC(todayParts.year, todayParts.month - 1, todayParts.day, -3, 0, 0, 0));
    const sinceOnline = new Date(now.getTime() - 5 * 60 * 1000);
    const [totals, today, online, daily, topPages] = await Promise.all([
      VisitorEvent.aggregate([
        { $group: { _id: null, pageViews: { $sum: 1 }, visitors: { $addToSet: "$visitorId" } } },
        { $project: { _id: 0, pageViews: 1, uniqueVisitors: { $size: "$visitors" } } }
      ]),
      VisitorEvent.aggregate([
        { $match: { createdAt: { $gte: sinceToday } } },
        { $group: { _id: null, pageViews: { $sum: 1 }, visitors: { $addToSet: "$visitorId" } } },
        { $project: { _id: 0, pageViews: 1, uniqueVisitors: { $size: "$visitors" } } }
      ]),
      VisitorPresence.countDocuments({ lastSeen: { $gte: sinceOnline } }),
      VisitorEvent.aggregate([
        { $match: { createdAt: { $gte: since30 } } },
        { $group: { _id: { $dateToString: { date: "$createdAt", format: "%Y-%m-%d", timezone: "Africa/Nairobi" } }, pageViews: { $sum: 1 }, visitors: { $addToSet: "$visitorId" } } },
        { $project: { date: "$_id", _id: 0, pageViews: 1, uniqueVisitors: { $size: "$visitors" } } },
        { $sort: { date: 1 } }
      ]),
      VisitorEvent.aggregate([
        { $match: { createdAt: { $gte: since30 } } },
        { $group: { _id: "$path", pageViews: { $sum: 1 } } },
        { $sort: { pageViews: -1 } }, { $limit: 8 },
        { $project: { _id: 0, path: "$_id", pageViews: 1 } }
      ])
    ]);
    res.set("Cache-Control", "no-store");
    return res.json({
      success: true,
      totals: totals[0] || { pageViews: 0, uniqueVisitors: 0 },
      today: today[0] || { pageViews: 0, uniqueVisitors: 0 },
      onlineNow: online,
      daily, topPages,
      period: "Last 30 days",
      note: "Unique visitors are estimated using an anonymous first-party browser identifier. Online means activity in the last 5 minutes."
    });
  } catch (err) {
    console.error("Admin visitor analytics failed:", err.message);
    return res.status(500).json({ success: false, message: "Visitor analytics are temporarily unavailable." });
  }
});

app.get("/api/admin/overview", requireAuth, requireAdmin, async (req, res) => {
  try {
    const now = new Date();
    const [userRows, paymentRows, tips] = await Promise.all([
      User.aggregate([
        { $match: { role: "user" } },
        { $group: {
          _id: "$country",
          users: { $sum: 1 },
          activeVip: { $sum: { $cond: [
            { $and: [
              { $eq: ["$isActivated", true] },
              { $eq: ["$membershipStatus", "active"] },
              { $gt: ["$vipExpiresAt", now] }
            ] }, 1, 0
          ] } }
        } }
      ]),
      Payment.aggregate([
        { $match: { status: "completed" } },
        { $group: {
          _id: { country: "$country", currency: "$currency" },
          verifiedPayments: { $sum: 1 },
          verifiedAmount: { $sum: "$amount" }
        } }
      ]),
      Tip.aggregate([{ $group: { _id: "$result", count: { $sum: 1 } } }])
    ]);
    const countries = {
      KE: { currency: "KES", users: 0, activeVip: 0, verifiedPayments: 0, verifiedAmount: 0 },
      TZ: { currency: "TZS", users: 0, activeVip: 0, verifiedPayments: 0, verifiedAmount: 0 },
      UG: { currency: "UGX", users: 0, activeVip: 0, verifiedPayments: 0, verifiedAmount: 0 }
    };
    for (const row of userRows) {
      const code = String(row._id || "KE").toUpperCase();
      if (countries[code]) {
        countries[code].users = row.users || 0;
        countries[code].activeVip = row.activeVip || 0;
      }
    }
    for (const row of paymentRows) {
      const code = String(row._id?.country || "KE").toUpperCase();
      if (countries[code]) {
        countries[code].currency = row._id?.currency || countries[code].currency;
        countries[code].verifiedPayments += row.verifiedPayments || 0;
        countries[code].verifiedAmount += row.verifiedAmount || 0;
      }
    }
    res.json({ success: true, countries, tips: tips.map(t => ({ result: t._id, count: t.count })) });
  } catch (err) {
    console.error("Admin overview failed:", err.message);
    res.status(500).json({ success: false, message: "Admin overview unavailable." });
  }
});
app.get("/api/admin/payments", requireAuth, requireAdmin, async (req, res) => {
  try {
    const payments = await Payment.find({}).populate("user", "email phoneNumber").sort({ createdAt: -1 }).limit(500).lean();
    res.json({ success: true, payments: payments.map(p => ({ id: String(p._id), email: p.user?.email || "Deleted user", userPhone: p.user?.phoneNumber || "", phone: p.phone, package: p.package, amount: p.amount, currency: p.currency || "KES", country: p.country || "KE", provider: p.provider || "kenya_mpesa", reference: p.reference, transactionCode: p.transactionCode, status: p.status, createdAt: p.createdAt, completedAt: p.completedAt, message: p.providerMessage })) });
  } catch (err) { res.status(500).json({ success: false, message: "Could not load payment ledger." }); }
});

app.get("/api/admin/audit-logs", requireAuth, requireAdmin, async (req, res) => {
  try {
    const logs = await AuditLog.find({}).sort({ createdAt: -1 }).limit(200).lean();
    res.json({ success: true, logs: logs.map(x => ({ id: String(x._id), actorEmail: x.actorEmail, action: x.action, entityType: x.entityType, entityId: x.entityId, summary: x.summary, createdAt: x.createdAt })) });
  } catch (err) { res.status(500).json({ success: false, message: "Could not load administrator activity." }); }
});

async function findDuplicateTip(data, excludeId = null) {
  const query = {
    date: data.date,
    type: data.type,
    homeTeam: data.homeTeam,
    awayTeam: data.awayTeam,
    tip: data.tip
  };
  if (excludeId) query._id = { $ne: excludeId };
  return Tip.findOne(query).collation({ locale: "en", strength: 2 }).select("_id match tip date type").lean();
}

app.get("/api/admin/tips", requireAuth, requireAdmin, async (req, res) => {
  const tips = await Tip.find({}).sort({ date: -1, createdAt: 1 }).limit(2000).lean();
  res.json({ success: true, tips: tips.map(publicTip) });
});

app.post("/api/admin/tips", requireAuth, requireAdmin, csrfCheck, async (req, res) => {
  try {
    const data = cleanTipInput(req.body);
    const duplicate = await findDuplicateTip(data);
    if (duplicate) return res.status(409).json({ success: false, code: "DUPLICATE_TIP", message: `This ${data.type === "two_plus" ? "2+ Odds" : data.type === "premium" ? "VIP" : "Free"} tip already exists for ${data.match} on ${data.date}. Change the match, selection, date or category.` });
    const tip = await Tip.create({ ...data, createdBy: req.user._id });
    await recordAudit(req, "tip.created", "tip", tip._id, `${tip.type} tip for ${tip.match}`);
    if (tip.publicationStatus === "published") sendPushToAll({ title: tip.type === "two_plus" ? "New 2+ Odds selections available" : tip.type === "premium" ? "New VIP tips available" : "New free tips published", body: "Open Banker Tips to view the latest football selections.", url: tip.type === "two_plus" ? "/2-plus-odds" : tip.type === "premium" ? "/premium-tips" : "/free-tips" }).catch(err => console.warn("Tip notification failed:", err.message));
    res.status(201).json({ success: true, tip: publicTip(tip) });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ success: false, code: "DUPLICATE_TIP", message: "This tip already exists for the selected date and category. Duplicate tips are not allowed." });
    res.status(400).json({ success: false, message: err.message || "Could not create tip." });
  }
});

app.put("/api/admin/tips/:id", requireAuth, requireAdmin, csrfCheck, async (req, res) => {
  try {
    const data = cleanTipInput(req.body);
    const duplicate = await findDuplicateTip(data, req.params.id);
    if (duplicate) return res.status(409).json({ success: false, code: "DUPLICATE_TIP", message: `Another ${data.type === "two_plus" ? "2+ Odds" : data.type === "premium" ? "VIP" : "Free"} tip already exists for ${data.match} on ${data.date}.` });
    const tip = await Tip.findByIdAndUpdate(req.params.id, { ...data, updatedAt: new Date() }, { new: true, runValidators: true, collation: { locale: "en", strength: 2 } });
    if (!tip) return res.status(404).json({ success: false, message: "Tip not found." });
    await recordAudit(req, "tip.updated", "tip", tip._id, `${tip.type} tip for ${tip.match}`);
    res.json({ success: true, tip: publicTip(tip) });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ success: false, code: "DUPLICATE_TIP", message: "This tip already exists for the selected date and category. Duplicate tips are not allowed." });
    res.status(400).json({ success: false, message: err.message || "Could not update tip." });
  }
});

app.delete("/api/admin/tips/:id", requireAuth, requireAdmin, csrfCheck, async (req, res) => {
  const tip = await Tip.findByIdAndDelete(req.params.id);
  if (!tip) return res.status(404).json({ success: false, message: "Tip not found." });
  await recordAudit(req, "tip.deleted", "tip", tip._id, `Deleted ${tip.type} tip: ${tip.match}`);
  res.json({ success: true, message: "Tip deleted." });
});

const FRONTEND_ROUTES = new Set([
  "/", "/register", "/login", "/free-tips", "/free-tips-history",
  "/vip-packages", "/subscription", "/my-account", "/payment-history", "/checkout",
  "/contact", "/premium-tips", "/vip-tips-history", "/2-plus-odds", "/match-centre", "/admin"
]);
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/") || req.path.includes(".")) return next();
  if (!FRONTEND_ROUTES.has(req.path)) return res.status(404).type("text").send("404 — Page not found");
  res.set("Cache-Control", "no-cache");
  res.sendFile(path.join(__dirname, "public", "index.html"), err => {
    if (err && !res.headersSent) res.status(404).type("text").send("Frontend not found. Add Banker Tips HTML to the public folder.");
  });
});
app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) return res.status(404).json({ success: false, message: "API endpoint not found." });
  next();
});

async function verifyGlobalPaymentRecord(payment) {
  const identifier = payment.globalReference || payment.globalTransactionId;
  if (!identifier || !["TZ", "UG"].includes(payment.country)) return;
  const statusEndpoint = payment.country === "TZ"
    ? `godigital/tz/status/${encodeURIComponent(identifier)}`
    : `collecto/status/${encodeURIComponent(identifier)}`;
  const response = await optimapayGlobalRequest("GET", statusEndpoint);
  const provider = response && response.data && typeof response.data === "object" ? response.data : response;
  const status = String(provider.status || provider.payment_status || "").trim().toUpperCase();
  if (["SUCCESSFUL", "COMPLETED", "SUCCESS", "PAID"].includes(status)) {
    await activatePaidMembership(payment, provider);
  } else if (["FAILED", "CANCELLED", "CANCELED", "REJECTED"].includes(status)) {
    payment.status = "failed";
    payment.providerMessage = String(provider.message || `Payment ${status.toLowerCase()}.`).slice(0, 300);
    payment.updatedAt = new Date();
    await payment.save();
  } else {
    payment.status = "pending";
    payment.providerMessage = String(provider.message || "Payment is still pending confirmation.").slice(0, 300);
    payment.updatedAt = new Date();
    await payment.save();
  }
}

async function sweepGlobalPayments() {
  // The API documentation does not guarantee merchant webhook delivery, so the
  // server independently polls pending Tanzania/Uganda transactions. This keeps
  // activation working even if the customer closes the checkout page.
  const staleBefore = new Date(Date.now() - 2 * 60 * 1000);
  const candidates = await Payment.find({
    country: { $in: ["TZ", "UG"] },
    $and: [
      { $or: [
        { status: "pending" },
        { status: "verifying", updatedAt: { $lte: staleBefore } }
      ] },
      { $or: [
        { globalReference: { $ne: null } },
        { globalTransactionId: { $ne: null } }
      ] }
    ]
  }).sort({ createdAt: 1 }).limit(25);
  for (const candidate of candidates) {
    const claimed = await Payment.findOneAndUpdate(
      { _id: candidate._id, $or: [{ status: "pending" }, { status: "verifying", updatedAt: { $lte: staleBefore } }] },
      { $set: { status: "verifying", updatedAt: new Date() } },
      { new: true }
    );
    if (!claimed) continue;
    try {
      await verifyGlobalPaymentRecord(claimed);
    } catch (err) {
      claimed.status = "pending";
      claimed.updatedAt = new Date();
      claimed.providerMessage = "Automatic verification will retry. " + String(err.message || "Gateway unavailable.").slice(0, 180);
      await claimed.save().catch(() => {});
      console.error(`Automatic ${claimed.country} payment verification failed:`, err.message);
    }
  }
}

async function publishScheduledTips() {
  const now = new Date();
  const result = await Tip.updateMany(
    { publicationStatus: "scheduled", publishAt: { $lte: now } },
    { $set: { publicationStatus: "published", updatedAt: now } }
  );
  if (result.modifiedCount) console.log(`Published ${result.modifiedCount} scheduled tip(s).`);
  return result.modifiedCount || 0;
}

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
    admin = await User.create({
      email, passwordHash, role: "admin", isActivated: true,
      membershipStatus: "active", selectedPackage: null, vipExpiresAt: null
    });
    console.log(`Bootstrapped admin account: ${email}`);
  } else {
    admin.role = "admin";
    admin.isActivated = true;
    admin.membershipStatus = "active";
    admin.selectedPackage = null;
    admin.vipExpiresAt = null;
    admin.passwordHash = passwordHash;
    await admin.save();
    console.log(`Admin account verified/updated from environment: ${email}`);
  }
}

mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log("MongoDB connected.");
    // Ensure the unique email constraint exists before accepting registrations.
    // If legacy duplicate rows already exist, keep the server online: the
    // registration endpoint still checks case-insensitively before creating users.
    try {
      await User.createIndexes();
    } catch (indexError) {
      console.error("Email unique index could not be verified. Check for existing duplicate email records:", indexError.message);
    }
    // Existing duplicate tip rows can prevent MongoDB from building this index;
    // the API also performs a duplicate check and reports a clear 409 response.
    try {
      await Tip.collection.createIndex(
        { date: 1, type: 1, homeTeam: 1, awayTeam: 1, tip: 1 },
        { unique: true, collation: { locale: "en", strength: 2 }, name: "unique_tip_selection_per_day" }
      );
    } catch (indexError) {
      console.error("Tip duplicate-protection index could not be created. Check for existing duplicate tips:", indexError.message);
    }
    await bootstrapAdmin();
    const repairedAdmins = await User.updateMany(
      { role: "admin" },
      { $set: { isActivated: true, membershipStatus: "active", vipExpiresAt: null, selectedPackage: null } }
    );
    if (repairedAdmins.modifiedCount) {
      console.log(`Restored permanent active status for ${repairedAdmins.modifiedCount} admin account(s).`);
    }
    await expireMemberships().catch(err => console.error("Initial membership expiry sweep failed:", err.message));
    await publishScheduledTips().catch(err => console.error("Initial scheduled-tip publication sweep failed:", err.message));
    const expirySweep = setInterval(() => {
      expireMemberships().catch(err => console.error("Membership expiry sweep failed:", err.message));
    }, MEMBERSHIP_SWEEP_INTERVAL_MS);
    if (typeof expirySweep.unref === "function") expirySweep.unref();
    const scheduledTipSweep = setInterval(() => {
      publishScheduledTips().catch(err => console.error("Scheduled-tip publication sweep failed:", err.message));
    }, 30 * 1000);
    if (typeof scheduledTipSweep.unref === "function") scheduledTipSweep.unref();
    await sweepGlobalPayments().catch(err => console.error("Initial Global API payment sweep failed:", err.message));
    const globalPaymentSweep = setInterval(() => {
      sweepGlobalPayments().catch(err => console.error("Global API payment sweep failed:", err.message));
    }, 20 * 1000);
    if (typeof globalPaymentSweep.unref === "function") globalPaymentSweep.unref();
    app.listen(PORT, () => console.log(`Banker Tips server listening on port ${PORT}`));
  })
  .catch(err => {
    console.error("MongoDB connection failed:", err.message);
    process.exit(1);
  });

process.on("unhandledRejection", err => console.error("Unhandled rejection:", err));
