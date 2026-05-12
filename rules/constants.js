/**
 * constants.js — ShadowLink Phishing Detection
 *
 * Shared lookup tables used across the detection engine.
 * Loaded first (per manifest.json load order) so all subsequent rule files
 * can reference these globals safely.
 */

// ---------------------------------------------------------------------------
// trustedDomains
//
// Bare second-level labels (no scheme, no TLD) for well-known brands.
// Used by loginDetector.js to skip trusted sites and by homoglyph.js as the
// set of impersonation targets.
// ---------------------------------------------------------------------------
const trustedDomains = [
  // Search / productivity
  "google",
  "gmail",
  "youtube",
  "outlook",
  "yahoo",

  // Social media
  "facebook",
  "instagram",
  "twitter",
  "linkedin",
  "reddit",
  "tiktok",
  "snapchat",
  "pinterest",
  "tumblr",
  "twitch",
  "discord",

  // E-commerce / payments
  "amazon",
  "paypal",
  "stripe",
  "shopify",
  "ebay",
  "etsy",

  // Cloud / SaaS
  "microsoft",
  "apple",
  "google",
  "cloudflare",
  "dropbox",
  "adobe",
  "salesforce",
  "hubspot",
  "zendesk",
  "atlassian",
  "slack",
  "zoom",
  "github",
  "gitlab",
  "bitbucket",
  "wordpress",
  "squarespace",

  // Streaming / entertainment
  "netflix",
  "spotify",
  "hulu",
  "disneyplus",

  // Reference / infra
  "wikipedia",
  "archive",
];

// ---------------------------------------------------------------------------
// suspiciousTLDs
//
// TLDs statistically associated with phishing, spam, and malware campaigns.
// Source: Spamhaus Domain Block List research + Google Safe Browsing data.
//
// NOTE: These are matched against parsed.hostname only (see urlAnalyzer.js),
// so a URL like "example.com/page.xyz" will NOT incorrectly trigger ".xyz".
// ---------------------------------------------------------------------------
const suspiciousTLDs = [
  // Historically abused free TLDs
  ".tk",
  ".gq",
  ".ml",
  ".cf",
  ".ga",

  // High-abuse generic TLDs
  ".xyz",
  ".top",
  ".click",
  ".work",
  ".support",
  ".buzz",
  ".review",
  ".win",
  ".loan",
  ".trade",
  ".download",
  ".stream",
  ".country",
  ".xin",
  ".zip",

  // Open / cheap registration TLDs commonly exploited
  ".online",
  ".site",
  ".space",
  ".club",
  ".info",

  // Newly observed in phishing campaigns
  ".surf",
  ".icu",
  ".cam",
  ".cyou",
  ".sbs",
];

// ---------------------------------------------------------------------------
// suspiciousKeywords
//
// Words that appear in phishing domain names to lend false authority.
// These are matched against the HOSTNAME only (not the full URL path)
// to avoid false positives on legitimate sites like github.com/login.
// ---------------------------------------------------------------------------
const suspiciousKeywords = [
  // Authentication / identity
  "login",
  "signin",
  "sign-in",
  "auth",
  "sso",

  // Account management
  "account",
  "verify",
  "validate",
  "confirm",
  "update",
  "secure",
  "security",
  "password",
  "recover",
  "unlock",
  "reset",
  "suspend",
  "suspended",

  // Financial
  "banking",
  "wallet",
  "payment",
  "billing",
  "invoice",

  // Urgency / alert language
  "unusual",
  "activity",
  "alert",
  "notice",
  "urgent",
];
