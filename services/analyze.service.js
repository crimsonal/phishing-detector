import axios from "axios";
import whois from "whois-json";
import sslChecker from "ssl-checker";
import * as cheerio from "cheerio";



// Constants
const OPENPHISH_FEED = "https://openphish.com/feed.txt";

const SUSPICIOUS_KEYWORDS = [
    "verify", "secure", "login", "update", "confirm",
    "account", "banking", "paypal", "apple", "microsoft"
];

const URGENCY_PHRASES = [
    "act now", "verify your account", "suspended", "unusual activity",
    "confirm your identity", "click here immediately", "your account will be closed",
    "update your information", "unauthorized access", "limited time"
];

const SUSPICIOUS_TLDS = [".xyz", ".tk", ".top", ".gq", ".cf", ".ml"];

const KNOWN_BRANDS = {
    "paypal":    "paypal.com",
    "apple":     "apple.com",
    "microsoft": "microsoft.com",
    "google":    "google.com",
    "amazon":    "amazon.com",
    "facebook":  "facebook.com",
    "netflix":   "netflix.com",
    "instagram": "instagram.com",
    "bankofamerica": "bankofamerica.com",
    "chase":     "chase.com",
};

const SIGNAL_WEIGHTS = {
    high:   30,
    medium: 15,
    low:    5,
};

// OpenPhish feed management
let phishingUrls = new Set();

async function refreshFeed() {
    try {
        const response = await axios.get(OPENPHISH_FEED);
        phishingUrls = new Set(response.data.split("\n").map(u => u.trim()));
        console.log(`OpenPhish feed loaded: ${phishingUrls.size} entries`);
    } catch (err) {
        console.error("Failed to refresh OpenPhish feed:", err.message);
    }
}

refreshFeed();
setInterval(refreshFeed, 30 * 60 * 1000);

// URL Heuristics
function checkHeuristics(targetUrl) {
    const signals = [];

    try {
        const parsed = new URL(targetUrl);
        const hostname = parsed.hostname.toLowerCase();
        const parts = hostname.split(".");
        const subdomain = parts.slice(0, -2).join(".");

        if (SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld)))
            signals.push({ name: "suspicious_tld", weight: "high" });

        if (SUSPICIOUS_KEYWORDS.some(kw => subdomain.includes(kw)))
            signals.push({ name: "brand_keyword_in_subdomain", weight: "high" });

        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname))
            signals.push({ name: "ip_as_host", weight: "high" });

        if (parts.length > 4)
            signals.push({ name: "excessive_subdomains", weight: "medium" });

        if (targetUrl.length > 100)
            signals.push({ name: "long_url", weight: "low" });

    } catch {
        signals.push({ name: "invalid_url", weight: "high" });
    }

    return signals;
}

// Brand Spoofing Detection
function checkBrandSpoofing(hostname) {
    const signals = [];
    for (const [brand, legitDomain] of Object.entries(KNOWN_BRANDS)) {
        if (hostname.includes(brand) && !hostname.endsWith(legitDomain)) {
            signals.push({ name: `brand_spoof_${brand}`, weight: "high" });
        }
    }
    return signals;
}

// Domain Age Analysis
async function checkDomainAge(hostname) {
    const signals = [];
    let ageDays = null;

    try {
        const data = await whois(hostname);
        const creationDate = data.creationDate || data.created || data.registrationTime;
        if (creationDate) {
            ageDays = (Date.now() - new Date(creationDate)) / (1000 * 60 * 60 * 24);
            if (ageDays < 30)
                signals.push({ name: "domain_very_new", weight: "high" });
            else if (ageDays < 90)
                signals.push({ name: "domain_recently_registered", weight: "medium" });
        }
    } catch (err) {
        console.error("WHOIS lookup failed:", err.message);
    }

    return { signals, ageDays: ageDays ? Math.floor(ageDays) : null };
}

// SSL Checker
async function checkSSL(hostname) {
    const signals = [];
    let sslInfo = null;

    try {
        const data = await sslChecker(hostname);
        sslInfo = {
            valid: data.valid,
            days_remaining: data.daysRemaining,
            issuer: data.issuer,
        };

        if (!data.valid)
            signals.push({ name: "invalid_ssl", weight: "high" });
        else if (data.daysRemaining < 10)
            signals.push({ name: "ssl_expiring_soon", weight: "medium" });

    } catch (err) {
        // No SSL at all
        signals.push({ name: "no_ssl", weight: "high" });
    }

    return { signals, sslInfo };
}

// NLP Content Analysis
function analyzePageContent(html) {
    const signals = [];

    try {
        const $ = cheerio.load(html);
        const text = $("body").text().toLowerCase();
        const title = $("title").text();

        if (URGENCY_PHRASES.some(p => text.includes(p)))
            signals.push({ name: "urgency_language", weight: "high" });

        if ($('input[type="password"]').length > 0)
            signals.push({ name: "credential_form", weight: "high" });

        if ($('input[type="email"]').length > 0 && $('input[type="password"]').length > 0)
            signals.push({ name: "login_form", weight: "high" });

        // Hidden elements; common in phishing pages to hide from scanners
        if ($('[style*="display:none"], [style*="display: none"]').length > 5)
            signals.push({ name: "excessive_hidden_elements", weight: "medium" });

        // Checks for external form submission to a different domain
        $("form").each((_, form) => {
            const action = $(form).attr("action") || "";
            if (action.startsWith("http") && !action.includes(title))
                signals.push({ name: "form_submits_externally", weight: "high" });
        });

        return { signals, title };

    } catch (err) {
        console.error("Content analysis failed:", err.message);
        return { signals, title: null };
    }
}

// Score Fusion
function calculateScore(allSignals) {
    const raw = allSignals.reduce((acc, s) => acc + (SIGNAL_WEIGHTS[s.weight] || 0), 0);
    const score = Math.min(raw, 100);
    const verdict = score >= 60 ? "phishing" : score >= 30 ? "suspicious" : "safe";

    // Confidence: how far the score is from the nearest threshold
    const nearestThreshold = score >= 60 ? 60 : score >= 30 ? 30 : 30;
    const confidence = Math.min(Math.abs(score - nearestThreshold) / 30 + 0.5, 1).toFixed(2);

    return { score, verdict, confidence: parseFloat(confidence) };
}


// Main Analyzer
async function analyzeUrl(targetUrl, html = null) {
    let hostname;

    try {
        hostname = new URL(targetUrl).hostname;
    } catch {
        return {
            verdict: "phishing",
            score: 100,
            confidence: 1.0,
            signals: [{ name: "invalid_url", weight: "high" }],
            openphish_match: false,
            domain_age_days: null,
            ssl: null,
        };
    }

    // Run all checks in parallel where possible
    const [domainResult, sslResult] = await Promise.all([
        checkDomainAge(hostname),
        checkSSL(hostname),
    ]);

    const urlSignals = checkHeuristics(targetUrl, hostname);
    const brandSignals = checkBrandSpoofing(hostname);
    const contentResult = html ? analyzePageContent(html) : { signals: [], title: null };

    // OpenPhish check
    const inFeed = phishingUrls.has(targetUrl.trim());
    const feedSignals = inFeed ? [{ name: "openphish_match", weight: "high" }] : [];

    const allSignals = [
        ...urlSignals,
        ...brandSignals,
        ...domainResult.signals,
        ...sslResult.signals,
        ...contentResult.signals,
        ...feedSignals,
    ];

    const { score, verdict, confidence } = calculateScore(allSignals);

    return {
        verdict,
        score,
        confidence,
        signals: allSignals,
        openphish_match: inFeed,
        domain_age_days: domainResult.ageDays,
        ssl: sslResult.sslInfo,
        page_title: contentResult.title,
    };

}


export default analyzeUrl

