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
const OPTIMAPAY_GLOBAL_BASE_URL = "https://global.optimapaybridge.co.ke/api/v2";
const DEFAULT_VIP_PRICES = Object.freeze({
  KE: Object.freeze({ daily: 250, weekly: 1500, monthly: 3500 }),
  TZ: Object.freeze({ daily: 5000, weekly: 35000, monthly: 75000 }),
  UG: Object.freeze({ daily: 5000, weekly: 50000, monthly: 110000 })
});
const PACKAGE_DAYS = Object.freeze({ daily: 1, weekly: 7, monthly: 30 });
const MEMBERSHIP_TIME_ZONE = "Africa/Nairobi";

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("FATAL: Set JWT_SECRET to a random secret of at least 32 characters.");
}
if (!process.env.MONGODB_URI) {
  console.error("FATAL: Set MONGODB_URI in your environment.");
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

const User = mongoose.models.User || mongoose.model("User", userSchema);
const Tip = mongoose.models.Tip || mongoose.model("Tip", tipSchema);
const Payment = mongoose.models.Payment || mongoose.model("Payment", paymentSchema);

const vipPricingSchema = new mongoose.Schema({
  key: { type: String, unique: true, default: "default" },
  prices: { type: mongoose.Schema.Types.Mixed, required: true }
}, { timestamps: true, versionKey: false });
const VipPricing = mongoose.models.VipPricing || mongoose.model("VipPricing", vipPricingSchema);

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
const AuditLog = mongoose.models.AuditLog || mongoose.model("AuditLog", auditLogSchema);

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
const Advertisement = mongoose.models.Advertisement || mongoose.model("Advertisement", advertisementSchema);

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
function setSession(res, user) {
  res.cookie(COOKIE_NAME, signToken(user), {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === "true" || process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 12 * 60 * 60 * 1000
  });
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

function hasActiveVip(user) {
  if (user.role === "admin") return true;
  const validStatus = user.membershipStatus === "active" || (!user.membershipStatus && user.isActivated);
  const notExpired = !user.vipExpiresAt || new Date(user.vipExpiresAt).getTime() > Date.now();
  return Boolean(user.isActivated && validStatus && notExpired);
}

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
  if (!["free", "premium"].includes(type)) throw new Error("Type must be free or premium.");
  const parsedDate = new Date(`${date}T00:00:00.000Z`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !Number.isFinite(parsedDate.getTime()) || parsedDate.toISOString().slice(0, 10) !== date) throw new Error("Date must be a valid calendar date in YYYY-MM-DD format.");
  if (!homeTeam || !awayTeam || !match || !tip || !Number.isFinite(odds) || odds < 1 || odds > 1000) {
    throw new Error("Match must include both teams, a tip, and valid odds. Enter it as Home Team - Away Team.");
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

// Mongoose Connection Management for Serverless / Vercel
let isConnected = false;
async function connectDB() {
  if (isConnected && mongoose.connection.readyState === 1) return;
  try {
    await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
    isConnected = true;
    console.log("MongoDB connected.");
  } catch (err) {
    console.error("MongoDB connection failed:", err.message);
    throw err;
  }
}

// Middleware to ensure DB connection per request
app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    res.status(500).json({ success: false, message: "Database connection error." });
  }
});

app.use("/api", apiLimiter);

app.get("/api/health", (req, res) => {
  res.json({ success: true, status: "ok", database: mongoose.connection.readyState === 1 ? "connected" : "connecting" });
});

app.get("/api/pricing", async (req, res) => {
  try {
    res.set("Cache-Control", "no-store, max-age=0");
    res.json({ success: true, prices: await getVipPrices() });
  } catch (err) {
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
    await recordAudit(req, "vip-prices.updated", "vip-pricing", "default", "Updated VIP package prices.");
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
    if (!normalizedRegistrationPhone) return res.status(400).json({ success: false, message: `Enter a valid mobile number.` });

    const exists = await User.findOne({ email: new RegExp("^" + email.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "$", "i") }).select("_id");
    if (exists) return res.status(409).json({ success: false, code: "EMAIL_ALREADY_EXISTS", message: "This email address is already registered." });
    
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ email, phoneNumber: "+" + normalizedRegistrationPhone, country, mobileMoneyProvider: country === "TZ" ? mobileMoneyProvider : "", passwordHash, role: "user", selectedPackage, isActivated: false, membershipStatus: "pending_approval", vipExpiresAt: null });
    setSession(res, user);
    res.status(201).json({ success: true, message: "Account created.", user: safeUser(user) });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ success: false, code: "EMAIL_ALREADY_EXISTS", message: "This email address is already registered." });
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

app.get("/api/tips", async (req, res) => {
  res.set("Cache-Control", "private, no-store, max-age=0");
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
      if (!user || !hasActiveVip(user)) return res.status(403).json({ success: false, message: "VIP access is not active." });
    }
    const now = new Date();
    const tips = await Tip.find({ type, date, $or: [
      { publicationStatus: { $exists: false } },
      { publicationStatus: "published" },
      { publicationStatus: "scheduled", publishAt: { $lte: now } }
    ] }).sort({ createdAt: 1 }).lean();
    res.json({ success: true, authorized: true, tips: tips.map(publicTip) });
  } catch (err) {
    res.status(500).json({ success: false, message: "Could not load tips." });
  }
});

app.get("/api/advertisements/active", async (req, res) => {
  try {
    res.set("Cache-Control", "no-store, max-age=0");
    const ad = await Advertisement.findOne({ position: "home_vip", status: "active" })
      .sort({ updatedAt: -1, createdAt: -1 }).lean();
    res.json({ success: true, advertisement: ad ? publicAdvertisement(ad) : null });
  } catch (err) {
    res.status(500).json({ success: false, message: "Could not load homepage advertisement." });
  }
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
    if (err && !res.headersSent) res.status(404).type("text").send("Frontend not found.");
  });
});

app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) return res.status(404).json({ success: false, message: "API endpoint not found." });
  next();
});

// Export app for Vercel serverless functions
module.exports = app;
