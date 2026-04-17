require("dotenv").config(); // Load environment variables
const express = require("express");
const fetch = require("node-fetch");
const path = require("path");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

// Security Middleware - Helmet adds various HTTP headers for security
app.use(helmet());

// Content Security Policy - Restrict script execution sources
app.use(
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"], // For inline scripts only if necessary
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://api.abuseipdb.com", "https://www.virustotal.com"],
        },
    })
);

// Additional security headers
app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    next();
});

// CORS - Restrict to localhost only
const corsOptions = {
    origin: ["http://localhost:3000", "http://localhost:5000"],
    credentials: true,
    optionsSuccessStatus: 200,
};
app.use(cors(corsOptions));

// Rate Limiting - Prevent API abuse
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: "Too many requests from this IP, please try again later.",
    standardHeaders: true,
    legacyHeaders: false,
});

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 10, // Limit each IP to 10 API requests per minute
    message: "Too many API requests from this IP, please try again later.",
    standardHeaders: true,
    legacyHeaders: false,
});

app.use(limiter);
app.use("/api/", apiLimiter);

// Serve static files (for assets like CSS, JS, images) from the 'public' folder
app.use(express.static(path.join(__dirname, "public")));

// Serve the index.html file located outside the 'public' folder
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// Validate IP address format (IPv4 and IPv6)
const isValidIP = (ip) => {
    // IPv4 validation
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    
    // IPv6 validation (basic)
    const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})$/;
    
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
};

// Sanitize error responses to avoid information disclosure
const sanitizeError = (error) => {
    // Don't expose internal error details
    return { error: "An error occurred while processing your request. Please try again." };
};

// AbuseIPDB API Route
app.get("/api/abuseipdb", async (req, res) => {
    const { ip } = req.query;
    const abuseKey = process.env.ABUSEIPDB_API_KEY;

    console.log("=== API Request: /api/abuseipdb ===");
    console.log("IP:", ip);
    console.log("API Key configured:", !!abuseKey);

    // Validate API key is configured
    if (!abuseKey) {
        console.error("ABUSEIPDB_API_KEY is not configured");
        return res.status(500).json(sanitizeError(new Error("Service unavailable")));
    }

    // Validate IP format
    if (!ip || !isValidIP(ip)) {
        return res.status(400).json({ error: "Valid IP address (IPv4 or IPv6) is required." });
    }

    // Limit IP length to prevent abuse
    if (ip.length > 45) {
        return res.status(400).json({ error: "Invalid IP address format." });
    }

    try {
        const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}`, {
            headers: {
                "Key": abuseKey,
                "Accept": "application/json"
            },
            timeout: 5000 // 5 second timeout
        });

        if (!response.ok) {
            console.error(`AbuseIPDB API error: ${response.statusText}`);
            return res.status(500).json(sanitizeError(new Error("External API error")));
        }

        const data = await response.json();
        res.json(data);
    } catch (error) {
        console.error("AbuseIPDB fetch error:", error.message);
        res.status(500).json(sanitizeError(error));
    }
});

// VirusTotal API Route
app.get("/api/virustotal", async (req, res) => {
    const { ip } = req.query;
    const virusKey = process.env.VIRUSTOTAL_API_KEY;

    console.log("=== API Request: /api/virustotal ===");
    console.log("IP:", ip);
    console.log("API Key configured:", !!virusKey);

    // Validate API key is configured
    if (!virusKey) {
        console.error("VIRUSTOTAL_API_KEY is not configured");
        return res.status(500).json(sanitizeError(new Error("Service unavailable")));
    }

    // Validate IP format
    if (!ip || !isValidIP(ip)) {
        return res.status(400).json({ error: "Valid IP address (IPv4 or IPv6) is required." });
    }

    // Limit IP length to prevent abuse
    if (ip.length > 45) {
        return res.status(400).json({ error: "Invalid IP address format." });
    }

    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, {
            headers: {
                "x-apikey": virusKey,
                "Accept": "application/json"
            },
            timeout: 5000 // 5 second timeout
        });

        if (!response.ok) {
            console.error(`VirusTotal API error: ${response.statusText}`);
            return res.status(500).json(sanitizeError(new Error("External API error")));
        }

        const data = await response.json();
        res.json(data);
    } catch (error) {
        console.error("VirusTotal fetch error:", error.message);
        res.status(500).json(sanitizeError(error));
    }
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: "Not found" });
});

// Error handler
app.use((err, req, res, next) => {
    console.error("Server error:", err);
    res.status(500).json(sanitizeError(err));
});

// Start the server
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
