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
const OPTIMAPAY_BASE_URL = "https://optimapaybridge.co.ke/api/v2";
const PACKAGE_PRICES = Object.freeze({ daily: 150, weekly: 1500, monthly: 3500 });
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
  market: { type: String, trim: true, maxlength: 40, default: "auto" },
  fixtureId: { type: Number, default: null, index: true },
  homeScore: { type: Number, default: null },
  awayScore: { type: Number, default: null },
  fixtureStatus: { type: String, trim: true, maxlength: 40, default: "" },
  fixtureStatusShort: { type: String, trim: true, maxlength: 12, default: "" },
  elapsedMinute: { type: Number, default: null },
  lastSyncedAt: { type: Date, default: null },
  lastSyncAttemptAt: { type: Date, default: null },
  settlementNote: { type: String, trim: true, maxlength: 240, default: "" },
  settlementSource: { type: String, enum: ["manual", "automatic", "pending"], default: "pending" },
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

async function recordAudit(req, action, entityType, entityId, summary) {
  try { await AuditLog.create({ actor: req.user?._id || null, actorEmail: req.user?.email || "system", action, entityType, entityId: String(entityId || ""), summary }); }
  catch (err) { console.error("Audit log write failed:", err.message); }
}

function safeUser(user) {
  return {
    id: String(user._id),
    email: user.email,
    phoneNumber: user.phoneNumber || "",
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
function cleanTipInput(body) {
  const type = body.type;
  const date = String(body.date || "");
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
  const market = String(body.market || "auto").trim().toLowerCase();
  const allowedMarkets = new Set([
    "auto", "home_win", "draw", "away_win", "home_or_draw", "draw_or_away", "home_or_away",
    "btts_yes", "btts_no", "over_0_5", "under_0_5", "over_1_5", "under_1_5",
    "over_2_5", "under_2_5", "over_3_5", "under_3_5", "over_4_5", "under_4_5",
    "over_5_5", "under_5_5", "home_dnb", "away_dnb"
  ]);
  if (!allowedMarkets.has(market)) throw new Error("Choose a supported prediction market.");
  const fixtureIdValue = body.fixtureId == null || body.fixtureId === "" ? null : Number(body.fixtureId);
  if (fixtureIdValue !== null && (!Number.isSafeInteger(fixtureIdValue) || fixtureIdValue <= 0)) {
    throw new Error("Fixture ID must be a positive whole number.");
  }
  return {
    type, date, homeTeam, awayTeam, match, time, tip, odds, result, market,
    fixtureId: fixtureIdValue,
    settlementSource: result === "Pending" ? "pending" : "manual",
    settlementNote: "",
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

function paymentConfigReady() {
  const accountId = Number(process.env.OPTIMAPAY_PAYMENT_ACCOUNT_ID);
  return Boolean(process.env.OPTIMAPAY_API_KEY && process.env.OPTIMAPAY_API_SECRET && Number.isInteger(accountId) && accountId > 0);
}
async function optimapayPost(endpoint, payload) {
  const response = await fetch(`${OPTIMAPAY_BASE_URL}/${endpoint}`, {
    method: "POST",
    headers: {
      "X-API-Key": process.env.OPTIMAPAY_API_KEY,
      "X-API-Secret": process.env.OPTIMAPAY_API_SECRET,
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
  const reportedPhone = normalizeKenyanPhone(providerStatus.phone);
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
  const { publicationStatus, publishAt, ...tipFields } = obj;
  return {
    ...tipFields,
    id: String(obj._id || obj.id || ""),
    status: resultToStatus[obj.result] || obj.status || "Pending",
    fixtureStatusLabel: fixtureStatusLabel(obj.fixtureStatusShort, obj.elapsedMinute),
  };
}


// API-Football result synchronization. The API key stays server-side in .env.
const FOOTBALL_API_BASE = String(process.env.FOOTBALL_API_BASE_URL || "https://v3.football.api-sports.io").replace(/\/+$/, "");
const footballDateCache = new Map();
const FOOTBALL_TIME_ZONE = String(process.env.FOOTBALL_API_TIMEZONE || "Africa/Nairobi");
const configuredFootballInterval = Number(process.env.FOOTBALL_SYNC_INTERVAL_MS || 60 * 1000);
// Keep live score/status refresh responsive while allowing deployments to increase this
// interval to stay within their API-Football plan allowance. Never poll more often than 60s.
const FOOTBALL_SYNC_INTERVAL_MS = Number.isFinite(configuredFootballInterval)
  ? Math.max(60 * 1000, configuredFootballInterval) : 60 * 1000;

function footballDateISO(date = new Date()) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: FOOTBALL_TIME_ZONE, year: "numeric", month: "2-digit", day: "2-digit"
  }).formatToParts(date);
  const values = Object.fromEntries(parts.map(p => [p.type, p.value]));
  return `${values.year}-${values.month}-${values.day}`;
}
function shiftISODate(iso, days) {
  const d = new Date(`${iso}T12:00:00Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}
function normalizeTeamName(value) {
  let name = String(value || "").replace(/[ıİşŞğĞüÜöÖçÇæÆøØłŁđĐ]/g, ch => ({
    "ı":"i","İ":"i","ş":"s","Ş":"s","ğ":"g","Ğ":"g","ü":"u","Ü":"u","ö":"o","Ö":"o",
    "ç":"c","Ç":"c","æ":"ae","Æ":"ae","ø":"o","Ø":"o","ł":"l","Ł":"l","đ":"d","Đ":"d"
  }[ch] || ch)).normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
    .toLowerCase().replace(/&/g, " and ").replace(/['’]/g, "")
    .replace(/[^a-z0-9]+/g, " ").trim();
  name = name.replace(/\b(football club|association football club|fc|afc|cf|sc|club|sk|jk|fk|ks|as|ac|bk|nk|fk|cd|ud|ss|sv|tsv|vfb|vfl|the)\b/g, " ")
    .replace(/\s+/g, " ").trim();
  const aliases = {
    "man utd": "manchester united", "man united": "manchester united",
    "man city": "manchester city", "spurs": "tottenham hotspur",
    "psg": "paris saint germain", "paris sg": "paris saint germain",
    "inter": "internazionale", "inter milan": "internazionale",
    "ath madrid": "atletico madrid", "atletico": "atletico madrid",
    "besiktas": "besiktas", "kasimpasa": "kasimpasa",
    "bayern": "bayern munich", "bayern munchen": "bayern munich",
    "real": "real madrid", "barca": "barcelona",
    "sporting lisbon": "sporting cp", "sporting clube de portugal": "sporting cp",
    "red bull salzburg": "salzburg", "rb salzburg": "salzburg",
    "a villa": "aston villa", "bvb": "borussia dortmund", "b dortmund": "borussia dortmund",
    "ath bilbao": "athletic bilbao", "athletic club": "athletic bilbao",
    "nottm forest": "nottingham forest", "wolves": "wolverhampton wanderers",
    "west ham": "west ham united", "newcastle": "newcastle united",
    "leverkusen": "bayer leverkusen", "gladbach": "borussia monchengladbach",
    "m gladbach": "borussia monchengladbach", "sporting lisbon": "sporting cp",
    "olympiakos": "olympiacos"
  };
  return aliases[name] || name;
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

function teamNameSimilarity(left, right) {
  const a = normalizeTeamName(left), b = normalizeTeamName(right);
  if (!a || !b) return 0;
  if (a === b) return 1;
  const at = new Set(a.split(" ")), bt = new Set(b.split(" "));
  const intersection = [...at].filter(token => bt.has(token)).length;
  const dice = (2 * intersection) / (at.size + bt.size);
  // Prefix tolerance handles provider variants such as "Besiktas JK" after suffix cleanup.
  const compactA = a.replace(/\s/g, ""), compactB = b.replace(/\s/g, "");
  const prefix = compactA.startsWith(compactB) || compactB.startsWith(compactA);
  return Math.max(dice, prefix ? Math.min(compactA.length, compactB.length) / Math.max(compactA.length, compactB.length) : 0);
}
function resolveTipMarket(tip) {
  const explicit = String(tip.market || "auto").toLowerCase();
  if (explicit && explicit !== "auto") return { code: explicit };
  const raw = String(tip.tip || "").toLowerCase().replace(/[–—]/g, "-").trim();
  const compact = raw.replace(/[\s_-]+/g, "");
  if (/^(1|home|homewin|1x2\s*1)$/.test(compact)) return { code: "home_win" };
  if (/^(x|draw|tie|1x2x)$/.test(compact)) return { code: "draw" };
  if (/^(2|away|awaywin|1x22)$/.test(compact)) return { code: "away_win" };
  if (/^(1x|hom or draw|homeordraw)$/.test(compact)) return { code: "home_or_draw" };
  if (/^(x2|draworaway)$/.test(compact)) return { code: "draw_or_away" };
  if (/^(12|homeoraway)$/.test(compact)) return { code: "home_or_away" };
  if (/^(gg|bttyes|bothteamstoscoreyes|yesbtts)$/.test(compact) || /both teams to score\s*[:\-]?\s*yes|btts\s*[:\-]?\s*yes/i.test(raw)) return { code: "btts_yes" };
  if (/^(ng|bttsno|bothteamstoscoreno|nobtts)$/.test(compact) || /both teams to score\s*[:\-]?\s*no|btts\s*[:\-]?\s*no/i.test(raw)) return { code: "btts_no" };
  const total = raw.match(/\b(over|under)\s*(0\.5|1\.5|2\.5|3\.5|4\.5|5\.5)\b/);
  if (total) return { code: `${total[1]}_${total[2].replace(".", "_")}` };
  if (/\b(home|1)\s*(draw no bet|dnb)\b|\bhome dnb\b/i.test(raw)) return { code: "home_dnb" };
  if (/\b(away|2)\s*(draw no bet|dnb)\b|\baway dnb\b/i.test(raw)) return { code: "away_dnb" };
  return null;
}
function evaluateTipResult(tip, homeGoals, awayGoals) {
  const market = resolveTipMarket(tip);
  if (!market) return null;
  const total = homeGoals + awayGoals;
  let won;
  switch (market.code) {
    case "home_win": won = homeGoals > awayGoals; break;
    case "draw": won = homeGoals === awayGoals; break;
    case "away_win": won = awayGoals > homeGoals; break;
    case "home_or_draw": won = homeGoals >= awayGoals; break;
    case "draw_or_away": won = awayGoals >= homeGoals; break;
    case "home_or_away": won = homeGoals !== awayGoals; break;
    case "btts_yes": won = homeGoals > 0 && awayGoals > 0; break;
    case "btts_no": won = homeGoals === 0 || awayGoals === 0; break;
    case "home_dnb": if (homeGoals === awayGoals) return "Void"; won = homeGoals > awayGoals; break;
    case "away_dnb": if (homeGoals === awayGoals) return "Void"; won = awayGoals > homeGoals; break;
    default: {
      const totalMarket = market.code.match(/^(over|under)_(\d)_(\d)$/);
      if (!totalMarket) return null;
      const line = Number(`${totalMarket[2]}.${totalMarket[3]}`);
      won = totalMarket[1] === "over" ? total > line : total < line;
    }
  }
  return won ? "Win" : "Lose";
}
async function fetchFootballFixturesForDate(date, forceRefresh = false) {
  const apiKey = String(process.env.FOOTBALL_API_KEY || "").trim();
  if (!apiKey) throw new Error("FOOTBALL_API_KEY is not configured.");
  const now = Date.now();
  const today = footballDateISO();
  const ttl = date === today
    ? Math.max(15 * 1000, Math.min(FOOTBALL_SYNC_INTERVAL_MS - 5000, 55 * 1000))
    // Yesterday can still contain a match that crossed midnight or was delayed.
    // Do not retain a pre-final live status for a full day.
    : (date < today ? 60 * 1000 : 6 * 60 * 60 * 1000);
  const cached = footballDateCache.get(date);
  if (!forceRefresh && cached && cached.expiresAt > now) {
    if (cached.error) throw new Error(cached.error);
    return cached.fixtures;
  }
  const url = `${FOOTBALL_API_BASE}/fixtures?date=${encodeURIComponent(date)}&timezone=${encodeURIComponent(FOOTBALL_TIME_ZONE)}`;
  try {
    const response = await fetch(url, {
      headers: { "x-apisports-key": apiKey, "Accept": "application/json" },
      signal: AbortSignal.timeout(15000)
    });
    let payload;
    try { payload = await response.json(); } catch { payload = null; }
    if (!response.ok || !payload || (payload.errors && Object.keys(payload.errors).length)) {
      const detail = payload?.message || (payload?.errors ? JSON.stringify(payload.errors) : `HTTP ${response.status}`);
      throw new Error(`API-Football request failed: ${String(detail).slice(0, 240)}`);
    }
    const fixtures = Array.isArray(payload.response) ? payload.response : [];
    fixtures.forEach(fixture => { fixture._bankerFetchedAt = now; });
    footballDateCache.set(date, { fixtures, fetchedAt: now, expiresAt: now + ttl });
    return fixtures;
  } catch (err) {
    const message = String(err.message || "Football provider request failed.").slice(0, 300);
    // Back off on provider/auth errors so a bad key cannot burn the free request allowance.
    footballDateCache.set(date, { error: message, expiresAt: now + 30 * 1000 });
    throw err;
  }
}
const footballFixtureIdCache = new Map();
async function fetchFootballFixtureById(fixtureId, forceRefresh = false) {
  const id = Number(fixtureId);
  if (!Number.isSafeInteger(id) || id <= 0) return null;
  const cached = footballFixtureIdCache.get(id);
  if (!forceRefresh && cached && cached.expiresAt > Date.now()) return cached.fixture;
  const apiKey = String(process.env.FOOTBALL_API_KEY || "").trim();
  if (!apiKey) throw new Error("FOOTBALL_API_KEY is not configured.");
  const response = await fetch(`${FOOTBALL_API_BASE}/fixtures?id=${encodeURIComponent(id)}&timezone=${encodeURIComponent(FOOTBALL_TIME_ZONE)}`, {
    headers: { "x-apisports-key": apiKey, "Accept": "application/json" },
    signal: AbortSignal.timeout(15000)
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok || !payload || (payload.errors && Object.keys(payload.errors).length)) {
    throw new Error(`API-Football fixture lookup failed (HTTP ${response.status}).`);
  }
  const fixture = Array.isArray(payload.response) ? payload.response[0] || null : null;
  if (fixture) fixture._bankerFetchedAt = Date.now();
  footballFixtureIdCache.set(id, { fixture, expiresAt: Date.now() + 2 * 60 * 1000 });
  return fixture;
}

function findMatchingFixture(tip, fixtures) {
  const list = Array.isArray(fixtures) ? fixtures : [];
  if (tip.fixtureId) {
    const byId = list.find(f => Number(f.fixture?.id) === Number(tip.fixtureId));
    if (byId && teamNameSimilarity(tip.homeTeam, byId.teams?.home?.name) >= 0.88 &&
        teamNameSimilarity(tip.awayTeam, byId.teams?.away?.name) >= 0.88) return byId;
  }
  const targetHome = normalizeTeamName(tip.homeTeam);
  const targetAway = normalizeTeamName(tip.awayTeam);
  if (!targetHome || !targetAway) return null;
  const candidates = list.map(f => {
    const home = teamNameSimilarity(tip.homeTeam, f.teams?.home?.name);
    const away = teamNameSimilarity(tip.awayTeam, f.teams?.away?.name);
    // Home/away orientation is mandatory; reversed fixtures are never accepted.
    const orientation = home >= 0.88 && away >= 0.88;
    const exact = home === 1 && away === 1;
    const targetTime = tip.time && /^\d{1,2}:\d{2}$/.test(tip.time)
      ? zonedDateTimeToEpoch(tip.date, tip.time, FOOTBALL_TIME_ZONE) : null;
    const fixtureTime = Number.isFinite(Number(f.fixture?.timestamp))
      ? Number(f.fixture.timestamp) * 1000 : new Date(f.fixture?.date || 0).getTime();
    const timeDistance = targetTime && Number.isFinite(fixtureTime) ? Math.abs(fixtureTime - targetTime) : null;
    return { fixture: f, home, away, score: (home + away) / 2, orientation, exact, timeDistance };
  }).filter(x => x.orientation);
  if (!candidates.length) return null;
  candidates.sort((a, b) => {
    if (a.exact !== b.exact) return a.exact ? -1 : 1;
    if (b.score !== a.score) return b.score - a.score;
    return (a.timeDistance ?? Infinity) - (b.timeDistance ?? Infinity);
  });
  const best = candidates[0], second = candidates[1];
  if (second && best.score - second.score < 0.035 && best.timeDistance === second.timeDistance) return null;
  if (best.timeDistance != null && best.timeDistance > 12 * 60 * 60 * 1000) return null;
  return best.fixture;
}

function fixtureStatusLabel(short, elapsed) {
  const code = String(short || "").toUpperCase();
  const minute = Number.isFinite(Number(elapsed)) ? `${Number(elapsed)}'` : "";
  if (code === "P") return "PEN";
  if (code === "1H") return minute ? `${minute} · 1st Half` : "1st Half";
  if (code === "2H") return minute ? `${minute} · 2nd Half` : "2nd Half";
  if (["ET", "1ET", "2ET"].includes(code)) return minute ? `${minute} · Extra Time` : "Extra Time";
  return ({ HT: "HT", FT: "FT", AET: "AET", PEN: "PEN", PST: "PST", CANC: "CANC",
    SUSP: "Suspended", INT: "Interrupted", ABD: "Abandoned", AWD: "Awarded", WO: "Walkover",
    TBD: "Time to be determined", NS: "Not started", BT: "Break", LIVE: "Live" })[code] || code || "";
}
async function syncTipResultsForDate(date, { forceRefresh = false } = {}) {
  const fixtures = await fetchFootballFixturesForDate(date, forceRefresh);
  // Refresh all published tips for this date so manually-settled cards still receive
  // current scores/status. Only Pending tips may be automatically settled below.
  const tips = await Tip.find({ date, publicationStatus: { $ne: "draft" } });
  const summary = { date, checked: 0, linked: 0, settled: 0, needsReview: 0, unmatched: 0 };
  for (const tip of tips) {
    summary.checked++;
    let fixture = findMatchingFixture(tip, fixtures);
    if (!fixture && !tip.fixtureId) {
      // Only try adjacent dates for unresolved name matches; date results are cached.
      for (const offset of [-1, 1]) {
        if (fixture) break;
        try {
          const adjacent = await fetchFootballFixturesForDate(shiftISODate(date, offset), forceRefresh);
          fixture = findMatchingFixture(tip, adjacent);
        } catch (adjacentError) {
          console.warn(`Adjacent fixture lookup failed for ${tip.match} (${offset} day):`, adjacentError.message);
        }
      }
    }
    if (!fixture && tip.fixtureId) {
      try {
        const byId = await fetchFootballFixtureById(tip.fixtureId, forceRefresh);
        if (byId && teamNameSimilarity(tip.homeTeam, byId.teams?.home?.name) >= 0.88 &&
            teamNameSimilarity(tip.awayTeam, byId.teams?.away?.name) >= 0.88) fixture = byId;
        else if (byId) tip.settlementNote = "Supplied fixture ID does not match the saved home/away teams; no settlement performed.";
      } catch (lookupError) { tip.settlementNote = `Fixture ID lookup failed: ${lookupError.message}`; }
    }
    if (!fixture) {
      tip.lastSyncAttemptAt = new Date();
      if (!tip.settlementNote) tip.settlementNote = "Fixture not matched. Check team names, date or API fixture ID.";
      await tip.save();
      summary.unmatched++;
      continue;
    }

    const fixtureStatus = String(fixture.fixture?.status?.long || "").slice(0, 40);
    const fixtureStatusShort = String(fixture.fixture?.status?.short || "").slice(0, 12).toUpperCase();
    const isFinished = ["FT", "AET", "PEN"].includes(fixtureStatusShort);
    // Standard markets use the 90-minute score. For AET/PEN, never substitute
    // the aggregate/penalty score when the provider has not supplied full-time score.
    const scoreHome = isFinished
      ? (fixture.score?.fulltime?.home != null ? fixture.score.fulltime.home : (fixtureStatusShort === "FT" ? fixture.goals?.home : null))
      : fixture.goals?.home;
    const scoreAway = isFinished
      ? (fixture.score?.fulltime?.away != null ? fixture.score.fulltime.away : (fixtureStatusShort === "FT" ? fixture.goals?.away : null))
      : fixture.goals?.away;
    const homeScore = scoreHome == null ? null : Number(scoreHome);
    const awayScore = scoreAway == null ? null : Number(scoreAway);

    tip.fixtureId = Number(fixture.fixture?.id) || tip.fixtureId || null;
    tip.homeScore = Number.isFinite(homeScore) ? homeScore : null;
    tip.awayScore = Number.isFinite(awayScore) ? awayScore : null;
    tip.fixtureStatus = fixtureStatus;
    tip.fixtureStatusShort = fixtureStatusShort;
    const elapsed = fixture.fixture?.status?.elapsed;
    tip.elapsedMinute = elapsed == null || !Number.isFinite(Number(elapsed)) ? null : Number(elapsed);
    tip.lastSyncedAt = new Date(Number(fixture._bankerFetchedAt) || Date.now());
    tip.lastSyncAttemptAt = new Date();
    if (tip.result === "Pending") tip.settlementNote = "";
    summary.linked++;

    // Never overwrite a manual or previously recorded result. Still refresh its score/status.
    if (tip.result === "Pending") {
      if (fixtureStatusShort === "CANC") {
        tip.result = "Void";
        tip.settlementSource = "automatic";
        tip.settlementNote = "Automatically voided: fixture cancelled by the provider.";
        summary.settled++;
      } else if (fixtureStatusShort === "ABD") {
        tip.settlementNote = "Match abandoned. Administrator review is required before settlement.";
        summary.needsReview++;
      } else if (isFinished) {
        if (tip.homeScore == null || tip.awayScore == null) {
          tip.settlementNote = "Fixture is marked finished but the 90-minute full-time score is unavailable; manual review required.";
          summary.needsReview++;
        } else {
          const outcome = evaluateTipResult(tip, tip.homeScore, tip.awayScore);
          if (!outcome) {
            tip.settlementNote = "Match finished; prediction market could not be identified safely. Settle this tip manually.";
            summary.needsReview++;
          } else {
            tip.result = outcome;
            tip.settlementSource = "automatic";
            tip.settlementNote = `Automatically settled from full-time score ${tip.homeScore}-${tip.awayScore}.`;
            summary.settled++;
            await AuditLog.create({
              actor: null, actorEmail: "system", action: "tip.auto_settled", entityType: "tip",
              entityId: String(tip._id), summary: `${tip.type} tip ${tip.match} automatically settled as ${outcome} (${tip.homeScore}-${tip.awayScore}).`
            }).catch(err => console.error("Automatic settlement audit failed:", err.message));
          }
        }
      } else if (fixtureStatusShort === "PST") {
        tip.settlementNote = "Match postponed; result remains pending.";
      } else if (["SUSP", "INT"].includes(fixtureStatusShort)) {
        tip.settlementNote = "Match interrupted or suspended; result remains pending.";
      }
    }
    await tip.save();
  }
  return summary;
}

let footballSyncInProgress = false;
let footballDateRotation = 0;
async function syncPendingTipResults({ forceRefresh = false } = {}) {
  if (footballSyncInProgress) return { configured: true, skipped: true, message: "A synchronization is already running." };
  footballSyncInProgress = true;
  try {
    if (!String(process.env.FOOTBALL_API_KEY || "").trim()) {
      return { configured: false, message: "Add FOOTBALL_API_KEY to the server environment to enable automatic results." };
    }
    const today = footballDateISO();
    const priorityDates = [shiftISODate(today, -1), today, shiftISODate(today, 1)];
    const pendingDates = await Tip.distinct("date", {
      result: "Pending", publicationStatus: { $ne: "draft" }
    });
    const publishedPriorityDates = await Tip.distinct("date", {
      date: { $in: priorityDates }, publicationStatus: { $ne: "draft" }
    });
    const remaining = pendingDates.filter(d => !priorityDates.includes(d)).sort();
    // Rotate the older pending-date backlog so a large backlog cannot starve later dates.
    if (remaining.length) {
      const offset = footballDateRotation % remaining.length;
      remaining.push(...remaining.splice(0, offset));
      footballDateRotation = (footballDateRotation + 1) % remaining.length;
    }
    const ordered = [...priorityDates.filter(d => publishedPriorityDates.includes(d)), ...remaining];
    const maxDates = Math.max(1, Math.min(10, Number(process.env.FOOTBALL_MAX_DATES_PER_SYNC) || 5));
    const dates = ordered.slice(0, maxDates);
    const summaries = [];
    for (const date of dates) {
      try { summaries.push(await syncTipResultsForDate(date, { forceRefresh })); }
      catch (err) {
        console.error(`Automatic tip-result sync failed for ${date}:`, err.message);
        summaries.push({ date, error: err.message });
      }
    }
    return {
      configured: true, datesChecked: summaries.length,
      checked: summaries.reduce((n, x) => n + (x.checked || 0), 0),
      linked: summaries.reduce((n, x) => n + (x.linked || 0), 0),
      settled: summaries.reduce((n, x) => n + (x.settled || 0), 0),
      needsReview: summaries.reduce((n, x) => n + (x.needsReview || 0), 0),
      unmatched: summaries.reduce((n, x) => n + (x.unmatched || 0), 0), summaries
    };
  } finally {
    footballSyncInProgress = false;
  }
}

app.use("/api", apiLimiter);

app.get("/api/health", (req, res) => {
  res.json({ success: true, status: "ok", database: mongoose.connection.readyState === 1 ? "connected" : "connecting" });
});

app.post("/api/auth/register", authLimiter, csrfCheck, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const phoneNumber = String(req.body.phoneNumber || "").trim();
    const password = req.body.password;
    const selectedPackage = String(req.body.selectedPackage || "").toLowerCase();
    
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

    // Prevent registration using the example mobile number (+254712345678 and its formatting variations)
    if (normalizeKenyanPhone(phoneNumber) === "254712345678") {
      return res.status(400).json({ 
        success: false, 
        message: "The number +254712345678 serves as an example format and cannot be used to register. Please enter your actual mobile number." 
      });
    }

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ success: false, message: "An account with that email already exists." });
    
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ email, phoneNumber, passwordHash, role: "user", selectedPackage, isActivated: false, membershipStatus: "pending_approval", vipExpiresAt: null });
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
  res.set("Cache-Control", "private, no-store, max-age=0");
  res.json({ success: true, user: safeUser(req.user) });
});

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

app.post("/api/payments/optimapay/stkpush", requireAuth, csrfCheck, async (req, res) => {
  let payment;
  try {
    if (req.user.role === "admin") return res.status(400).json({ success: false, message: "Admin accounts do not need a VIP payment." });
    if (!paymentConfigReady()) return res.status(503).json({ success: false, message: "M-Pesa payments are not configured yet. Please contact support." });
    const packageKey = req.user.selectedPackage;
    if (!PACKAGE_PRICES[packageKey]) return res.status(400).json({ success: false, message: "Choose a VIP package before paying." });
    const phone = normalizeKenyanPhone(req.body.phone || req.user.phoneNumber);
    if (!phone) return res.status(400).json({ success: false, message: "Enter a valid Kenyan M-Pesa number, e.g. 0712345678 or 254712345678." });
    const reference = `BT${Date.now().toString(36).toUpperCase()}${crypto.randomBytes(3).toString("hex").toUpperCase()}`.slice(0, 30);
    payment = await Payment.create({ user: req.user._id, package: packageKey, amount: PACKAGE_PRICES[packageKey], phone, reference, status: "initiating" });
    const provider = await optimapayPost("stkpush.php", {
      payment_account_id: Number(process.env.OPTIMAPAY_PAYMENT_ACCOUNT_ID),
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

app.get("/api/payments/:paymentId/status", requireAuth, async (req, res) => {
  try {
    let payment = await Payment.findOne({ _id: req.params.paymentId, user: req.user._id });
    if (!payment) return res.status(404).json({ success: false, message: "Payment not found." });
    if (payment.status === "pending" && payment.checkoutRequestId) {
      if (!paymentConfigReady()) return res.status(503).json({ success: false, message: "Payment verification is not configured." });
      const claimed = await Payment.findOneAndUpdate({ _id: payment._id, status: "pending" }, { $set: { status: "verifying" } }, { new: true });
      if (claimed) {
        payment = await Payment.findById(payment._id);
        try {
          const provider = await optimapayPost("status.php", { checkout_request_id: payment.checkoutRequestId });
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
    res.json({ success: true, payment: { id: String(payment._id), package: payment.package, amount: payment.amount, status: payment.status, message: payment.providerMessage, transactionCode: payment.transactionCode }, user: user ? safeUser(user) : undefined });
  } catch (err) {
    res.status(400).json({ success: false, message: "Could not check payment status." });
  }
});

app.get("/api/tips", async (req, res) => {
  res.set("Cache-Control", "private, no-store, max-age=0");
  res.set("Pragma", "no-cache");
  try {
    const type = String(req.query.type || "free");
    const date = String(req.query.date || footballDateISO());
    if (!["free", "premium"].includes(type)) return res.status(400).json({ success: false, message: "Invalid tips type." });
    if (type === "premium") {
      const token = req.cookies[COOKIE_NAME];
      if (!token) return res.status(401).json({ success: false, message: "Log in to access premium tips." });
      let decoded;
      try { decoded = jwt.verify(token, JWT_SECRET); } catch { return res.status(401).json({ success: false, message: "Please log in again." }); }
      const user = await User.findById(decoded.sub);
      if (!user || !hasActiveVip(user)) return res.status(403).json({ success: false, message: "VIP access is not active. Contact the administrator after payment." });
    }
    const tips = await Tip.find({ type, date, publicationStatus: { $ne: "draft" } }).sort({ createdAt: 1 }).lean();
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

    const tips = await Tip.find({ type, publicationStatus: { $ne: "draft" } })
      .sort({ date: -1, createdAt: 1, _id: 1 })
      .limit(500)
      .lean();
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
    res.json({ success: true, payments: payments.map(p => ({ id: String(p._id), package: p.package, amount: p.amount, phone: p.phone, reference: p.reference, status: p.status, transactionCode: p.transactionCode, message: p.providerMessage, createdAt: p.createdAt, completedAt: p.completedAt })) });
  } catch (err) { res.status(500).json({ success: false, message: "Could not load payment history." }); }
});

app.get("/api/stats/performance", async (req, res) => {
  try {
    const rows = await Tip.aggregate([{ $match: { result: { $in: ["Win", "Lose", "Void"] } } }, { $group: { _id: "$type", total: { $sum: 1 }, wins: { $sum: { $cond: [{ $eq: ["$result", "Win"] }, 1, 0] } }, losses: { $sum: { $cond: [{ $eq: ["$result", "Lose"] }, 1, 0] } }, voids: { $sum: { $cond: [{ $eq: ["$result", "Void"] }, 1, 0] } } } }]);
    const total = rows.reduce((a, r) => ({ settled: a.settled + r.total, wins: a.wins + r.wins, losses: a.losses + r.losses, voids: a.voids + r.voids }), { settled: 0, wins: 0, losses: 0, voids: 0 });
    res.set("Cache-Control", "public, max-age=60");
    res.json({ success: true, ...total, winRate: total.wins + total.losses ? Math.round(total.wins / (total.wins + total.losses) * 1000) / 10 : null, methodology: "Settled recorded tips only; void tips excluded from win-rate denominator. Historical results do not guarantee future outcomes." });
  } catch (err) { res.status(500).json({ success: false, message: "Performance statistics unavailable." }); }
});

app.get("/api/admin/overview", requireAuth, requireAdmin, async (req, res) => {
  try {
    const [users, payments, tips] = await Promise.all([
      User.aggregate([{ $group: { _id: null, total: { $sum: 1 }, active: { $sum: { $cond: [{ $or: [
        { $eq: ["$role", "admin"] },
        { $and: [
          { $eq: ["$isActivated", true] },
          { $eq: ["$membershipStatus", "active"] },
          { $gt: ["$vipExpiresAt", new Date()] }
        ] }
      ] }, 1, 0] } } } }]),
      Payment.aggregate([{ $group: { _id: "$status", count: { $sum: 1 }, amount: { $sum: "$amount" } } }]),
      Tip.aggregate([{ $group: { _id: "$result", count: { $sum: 1 } } }])
    ]);
    res.json({ success: true, users: users[0] || { total: 0, active: 0 }, payments: payments.map(p => ({ status: p._id, count: p.count, amount: p.amount })), tips: tips.map(t => ({ result: t._id, count: t.count })) });
  } catch (err) { res.status(500).json({ success: false, message: "Admin overview unavailable." }); }
});
app.get("/api/admin/payments", requireAuth, requireAdmin, async (req, res) => {
  try {
    const payments = await Payment.find({}).populate("user", "email phoneNumber").sort({ createdAt: -1 }).limit(500).lean();
    res.json({ success: true, payments: payments.map(p => ({ id: String(p._id), email: p.user?.email || "Deleted user", userPhone: p.user?.phoneNumber || "", phone: p.phone, package: p.package, amount: p.amount, reference: p.reference, transactionCode: p.transactionCode, status: p.status, createdAt: p.createdAt, completedAt: p.completedAt, message: p.providerMessage })) });
  } catch (err) { res.status(500).json({ success: false, message: "Could not load payment ledger." }); }
});

app.get("/api/admin/audit-logs", requireAuth, requireAdmin, async (req, res) => {
  try {
    const logs = await AuditLog.find({}).sort({ createdAt: -1 }).limit(200).lean();
    res.json({ success: true, logs: logs.map(x => ({ id: String(x._id), actorEmail: x.actorEmail, action: x.action, entityType: x.entityType, entityId: x.entityId, summary: x.summary, createdAt: x.createdAt })) });
  } catch (err) { res.status(500).json({ success: false, message: "Could not load administrator activity." }); }
});

app.get("/api/admin/tips", requireAuth, requireAdmin, async (req, res) => {
  const tips = await Tip.find({}).sort({ date: -1, createdAt: 1 }).limit(2000).lean();
  res.json({ success: true, tips: tips.map(publicTip) });
});

app.post("/api/admin/tips/sync-results", requireAuth, requireAdmin, csrfCheck, async (req, res) => {
  try {
    const summary = await syncPendingTipResults({ forceRefresh: true });
    if (!summary.configured) return res.status(503).json({ success: false, message: summary.message, summary });
    await recordAudit(req, "tips.results_sync", "tip", "", `Manual result sync: ${summary.settled} settled, ${summary.needsReview} need review, ${summary.unmatched} unmatched.`);
    res.json({ success: true, message: `Checked ${summary.checked} pending tip(s): ${summary.settled} settled, ${summary.needsReview} need review, ${summary.unmatched} unmatched.`, summary });
  } catch (err) {
    console.error("Manual tip-result sync error:", err.message);
    res.status(502).json({ success: false, message: "Could not synchronize tip results. Check the API key and server logs." });
  }
});

app.post("/api/admin/tips", requireAuth, requireAdmin, csrfCheck, async (req, res) => {
  try {
    const data = cleanTipInput(req.body);
    const tip = await Tip.create({ ...data, createdBy: req.user._id });
    await recordAudit(req, "tip.created", "tip", tip._id, `${tip.type} tip for ${tip.match}`);
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
    await recordAudit(req, "tip.updated", "tip", tip._id, `${tip.type} tip for ${tip.match}`);
    res.json({ success: true, tip: publicTip(tip) });
  } catch (err) {
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
  "/contact", "/premium-tips", "/vip-tips-history", "/admin"
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
    await bootstrapAdmin();
    const repairedAdmins = await User.updateMany(
      { role: "admin" },
      { $set: { isActivated: true, membershipStatus: "active", vipExpiresAt: null, selectedPackage: null } }
    );
    if (repairedAdmins.modifiedCount) {
      console.log(`Restored permanent active status for ${repairedAdmins.modifiedCount} admin account(s).`);
    }
    await expireMemberships().catch(err => console.error("Initial membership expiry sweep failed:", err.message));
    if (String(process.env.FOOTBALL_API_KEY || "").trim()) {
      syncPendingTipResults().then(result => console.log("Initial automatic tip-result sync:", result)).catch(err => console.error("Initial automatic tip-result sync failed:", err.message));
      const footballSyncTimer = setInterval(() => {
        syncPendingTipResults().then(result => {
          if (result.settled || result.needsReview || result.unmatched) console.log("Automatic tip-result sync:", result);
        }).catch(err => console.error("Automatic tip-result sync failed:", err.message));
      }, FOOTBALL_SYNC_INTERVAL_MS);
      if (typeof footballSyncTimer.unref === "function") footballSyncTimer.unref();
    } else {
      console.warn("FOOTBALL_API_KEY not set; automatic tip-result settlement is disabled.");
    }
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
