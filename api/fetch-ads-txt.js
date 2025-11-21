// Vercel Serverless Function to fetch ads.txt files
// This bypasses CORS issues by making server-side requests

export default async function handler(req, res) {
    // Enable CORS for the frontend
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    // Only allow GET requests
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { domain } = req.query;

    if (!domain) {
        return res.status(400).json({ error: 'Domain parameter is required' });
    }

    // Sanitize domain - remove protocol, www, paths
    let cleanDomain = domain
        .toLowerCase()
        .trim()
        .replace(/^https?:\/\//, '')
        .replace(/^www\./, '')
        .split('/')[0]
        .split('?')[0]
        .split('#')[0];

    if (!cleanDomain || !cleanDomain.includes('.')) {
        return res.status(400).json({ error: 'Invalid domain' });
    }

    // URLs to try (with and without www)
    const urlsToTry = [
        `https://${cleanDomain}/ads.txt`,
        `https://www.${cleanDomain}/ads.txt`,
        `http://${cleanDomain}/ads.txt`,
        `http://www.${cleanDomain}/ads.txt`
    ];

    // Try each URL
    for (const url of urlsToTry) {
        try {
            const response = await fetchWithTimeout(url, 15000);

            if (response.ok) {
                const content = await response.text();

                // Validate it's actually ads.txt content (not HTML error page)
                if (isValidAdsTxt(content)) {
                    return res.status(200).json({
                        success: true,
                        url: url,
                        content: content
                    });
                }
            }
        } catch (error) {
            // Continue to next URL
            console.log(`Failed to fetch ${url}: ${error.message}`);
        }
    }

    // All attempts failed
    return res.status(404).json({
        success: false,
        error: 'No ads.txt found for this domain'
    });
}

// Fetch with timeout
async function fetchWithTimeout(url, timeoutMs) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const response = await fetch(url, {
            signal: controller.signal,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/plain, text/html, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Cache-Control': 'no-cache'
            },
            redirect: 'follow'
        });
        clearTimeout(timeoutId);
        return response;
    } catch (error) {
        clearTimeout(timeoutId);
        throw error;
    }
}

// Validate if content is a valid ads.txt file
function isValidAdsTxt(content) {
    if (!content || typeof content !== 'string') {
        return false;
    }

    const trimmedContent = content.trim().toLowerCase();

    // Quick rejection: if it starts with < it's likely HTML/XML
    if (trimmedContent.startsWith('<')) {
        return false;
    }

    // Check for HTML/error indicators
    const invalidIndicators = [
        '<!doctype', '<html', '<head', '<body', '<meta', '<script',
        '<div', '<title', '<span', '<p>', '<?xml', '<error',
        '404 not found', 'page not found', 'not found', 'access denied',
        'forbidden', 'unauthorized', "you don't have permission",
        'error 404', 'error 403', 'error 500', 'internal server error',
        'bad gateway', 'service unavailable', 'cloudflare', 'just a moment',
        'checking your browser', 'reference #', 'errors.edgesuite.net'
    ];

    for (const indicator of invalidIndicators) {
        if (trimmedContent.includes(indicator)) {
            return false;
        }
    }

    // Positive validation: check for ads.txt patterns
    const lines = content.split('\n').filter(line => line.trim().length > 0);

    if (lines.length === 0) {
        return false;
    }

    const validPatterns = [
        /^#/,                                                           // Comments
        /^[a-z0-9.-]+\s*,\s*[a-z0-9_-]+\s*,\s*(DIRECT|RESELLER)/i,     // Standard ads.txt
        /^[a-z0-9.-]+\s*,\s*pub-\d+\s*,\s*(DIRECT|RESELLER)/i,         // Google format
        /^CONTACT=/i, /^SUBDOMAIN=/i, /^OWNERDOMAIN=/i,                 // Directives
        /^MANAGERDOMAIN=/i, /^INVENTORYPARTNERDOMAIN=/i
    ];

    let validLineCount = 0;
    for (const line of lines) {
        if (validPatterns.some(pattern => pattern.test(line.trim()))) {
            validLineCount++;
        }
    }

    return validLineCount > 0;
}
