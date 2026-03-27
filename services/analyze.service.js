
const url = "http://checkurl.staging.phishtank.com/checkurl/"
import axios from "axios";

const OPENPHISH_FEED = "https://openphish.com/feed.txt";

const SUSPICIOUS_KEYWORDS = [
    "verify", "secure", "login", "update", "confirm",
    "account", "banking", "paypal", "apple", "microsoft"
];

const SUSPICIOUS_TLDS = [".xyz", ".tk", ".top", ".gq", ".cf", ".ml"];

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

async function analyzeUrl(targetUrl) {
    // const data = {url: url, format: 'json'}
    const signals = checkHeuristics(targetUrl);

    const inFeed = phishingUrls.has(targetUrl.trim());
    if (inFeed)
        signals.push({ name: "openphish_match", weight: "high" });

    const score = Math.min(
        signals.reduce((acc, s) => acc + (s.weight === "high" ? 30 : s.weight === "medium" ? 15 : 5), 0),
        100
    );

    return {
        verdict: score >= 60 ? "phishing" : score >= 30 ? "suspicious" : "safe",
        score,
        signals,
        openphish_match: inFeed,
    };

}


export default analyzeUrl

