// PubSearch - Website Analyzer
// Main application logic

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const websiteInput = document.getElementById('website-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const resultsSection = document.getElementById('results-section');
    const loadingSection = document.getElementById('loading');
    const errorSection = document.getElementById('error-section');
    const errorMessage = document.getElementById('error-message');

    // Result Elements
    const analyzedUrl = document.getElementById('analyzed-url');
    const domainValue = document.getElementById('domain-value');
    const protocolValue = document.getElementById('protocol-value');
    const tldValue = document.getElementById('tld-value');
    const httpsValue = document.getElementById('https-value');
    const securityRating = document.getElementById('security-rating');
    const domainAge = document.getElementById('domain-age');
    const domainType = document.getElementById('domain-type');
    const subdomainValue = document.getElementById('subdomain-value');
    const pathValue = document.getElementById('path-value');
    const paramsValue = document.getElementById('params-value');
    const fragmentValue = document.getElementById('fragment-value');
    const summaryText = document.getElementById('summary-text');

    // Ads.txt Elements
    const adsTxtBtn = document.getElementById('ads-txt-btn');
    const adsTxtSection = document.getElementById('ads-txt-section');
    const adsTxtUrl = document.getElementById('ads-txt-url');
    const adsTxtContent = document.getElementById('ads-txt-content');

    // Example buttons
    const exampleButtons = document.querySelectorAll('.example-btn');

    // Event Listeners
    analyzeBtn.addEventListener('click', handleAnalyze);
    adsTxtBtn.addEventListener('click', handleExtractAdsTxt);
    websiteInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            handleAnalyze();
        }
    });

    // Example button click handlers
    exampleButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const url = btn.getAttribute('data-url');
            websiteInput.value = url;
            websiteInput.focus();
        });
    });

    // Main analyze handler
    async function handleAnalyze() {
        const input = websiteInput.value.trim();

        if (!input) {
            showError('Please enter a website URL to analyze');
            return;
        }

        // Reset UI
        hideAllSections();
        showLoading();

        try {
            // Normalize the URL
            const normalizedUrl = normalizeUrl(input);

            // Simulate analysis delay for better UX
            await delay(800);

            // Analyze the URL
            const analysis = analyzeUrl(normalizedUrl);

            // Display results
            displayResults(analysis);
        } catch (error) {
            showError(error.message || 'Failed to analyze the website');
        }
    }

    // URL normalization
    function normalizeUrl(input) {
        let url = input.trim();

        // Add protocol if missing
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }

        try {
            return new URL(url);
        } catch (e) {
            throw new Error('Invalid URL format. Please enter a valid website address.');
        }
    }

    // Main URL analysis function
    function analyzeUrl(url) {
        const hostname = url.hostname;
        const parts = hostname.split('.');

        // Extract TLD
        const tld = parts[parts.length - 1];

        // Extract domain and subdomain
        let domain, subdomain;
        if (parts.length >= 2) {
            // Handle common multi-part TLDs
            const multiPartTlds = ['co.uk', 'com.au', 'co.nz', 'co.in', 'com.br'];
            const lastTwoParts = parts.slice(-2).join('.');

            if (multiPartTlds.includes(lastTwoParts) && parts.length >= 3) {
                domain = parts[parts.length - 3];
                subdomain = parts.length > 3 ? parts.slice(0, -3).join('.') : null;
            } else {
                domain = parts[parts.length - 2];
                subdomain = parts.length > 2 ? parts.slice(0, -2).join('.') : null;
            }
        } else {
            domain = hostname;
            subdomain = null;
        }

        // Determine domain type
        const domainTypes = {
            'com': 'Commercial',
            'org': 'Organization',
            'net': 'Network',
            'edu': 'Educational',
            'gov': 'Government',
            'mil': 'Military',
            'io': 'Tech/Startup',
            'co': 'Company',
            'app': 'Application',
            'dev': 'Developer',
            'ai': 'Artificial Intelligence'
        };
        const type = domainTypes[tld] || 'Generic';

        // Security analysis
        const isHttps = url.protocol === 'https:';
        const hasWww = hostname.startsWith('www.');

        // Calculate security rating
        let securityScore = 0;
        if (isHttps) securityScore += 50;
        if (['gov', 'edu', 'mil'].includes(tld)) securityScore += 20;
        if (!hostname.includes('-')) securityScore += 10;
        if (domain.length > 3) securityScore += 10;
        if (!url.search) securityScore += 10;

        let rating;
        if (securityScore >= 70) rating = 'High';
        else if (securityScore >= 40) rating = 'Medium';
        else rating = 'Low';

        // Mock domain age (in real app, would use WHOIS API)
        const ages = ['< 1 year', '1-2 years', '2-5 years', '5-10 years', '10+ years'];
        const ageIndex = Math.min(domain.length % 5, 4);

        return {
            originalUrl: url.href,
            domain: domain,
            fullDomain: hostname,
            protocol: url.protocol.replace(':', ''),
            tld: '.' + tld,
            isHttps: isHttps,
            securityRating: rating,
            domainAge: ages[ageIndex],
            domainType: type,
            subdomain: subdomain || (hasWww ? 'www' : 'None'),
            path: url.pathname === '/' ? '/' : url.pathname,
            queryParams: url.search ? url.search.substring(1) : 'None',
            fragment: url.hash ? url.hash.substring(1) : 'None'
        };
    }

    // Display results
    function displayResults(analysis) {
        hideLoading();

        // Update URL display
        analyzedUrl.textContent = analysis.originalUrl;

        // General Information
        domainValue.textContent = analysis.fullDomain;
        protocolValue.textContent = analysis.protocol.toUpperCase();
        tldValue.textContent = analysis.tld;

        // Security Status
        httpsValue.textContent = analysis.isHttps ? 'Yes (Secure)' : 'No (Not Secure)';
        httpsValue.className = 'value ' + (analysis.isHttps ? 'secure' : 'insecure');
        securityRating.textContent = analysis.securityRating;
        securityRating.className = 'value ' + (analysis.securityRating === 'High' ? 'secure' :
                                               analysis.securityRating === 'Low' ? 'insecure' : '');

        // Domain Analysis
        domainAge.textContent = analysis.domainAge;
        domainType.textContent = analysis.domainType;
        subdomainValue.textContent = analysis.subdomain;

        // URL Structure
        pathValue.textContent = analysis.path;
        paramsValue.textContent = analysis.queryParams;
        fragmentValue.textContent = analysis.fragment;

        // Summary
        const summaryParts = [
            `The website "${analysis.fullDomain}" is a ${analysis.domainType.toLowerCase()} domain`,
            `using the ${analysis.protocol.toUpperCase()} protocol.`,
            analysis.isHttps
                ? 'The connection is encrypted and secure.'
                : 'Warning: The connection is not encrypted.',
            `The domain has a ${analysis.securityRating.toLowerCase()} security rating`,
            `and appears to be ${analysis.domainAge} old.`
        ];
        summaryText.textContent = summaryParts.join(' ');

        // Show results
        resultsSection.classList.remove('hidden');
    }

    // UI Helper functions
    function hideAllSections() {
        resultsSection.classList.add('hidden');
        loadingSection.classList.add('hidden');
        errorSection.classList.add('hidden');
        adsTxtSection.classList.add('hidden');
    }

    function showLoading() {
        loadingSection.classList.remove('hidden');
    }

    function hideLoading() {
        loadingSection.classList.add('hidden');
    }

    function showError(message) {
        hideLoading();
        errorMessage.textContent = message;
        errorSection.classList.remove('hidden');

        // Auto-hide error after 5 seconds
        setTimeout(() => {
            errorSection.classList.add('hidden');
        }, 5000);
    }

    function delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // Extract ads.txt handler
    async function handleExtractAdsTxt() {
        const input = websiteInput.value.trim();

        if (!input) {
            showError('Please enter a website URL to extract ads.txt');
            return;
        }

        // Reset UI
        hideAllSections();
        showLoading();

        try {
            // Extract domain from input
            const domain = extractDomain(input);

            // Fetch ads.txt with robust retry logic
            const result = await fetchAdsTxtWithRetry(domain);

            // Display results
            displayAdsTxtResults(result.url, result.content);
        } catch (error) {
            showError(error.message || 'Failed to extract ads.txt');
        }
    }

    // Extract base domain from URL input (keeps www if present for retry logic)
    function extractDomain(input) {
        let url = input.trim();

        // Remove protocol
        url = url.replace(/^https?:\/\//, '');

        // Remove path, query, and fragment
        url = url.split('/')[0].split('?')[0].split('#')[0];

        // Remove www. prefix for base domain
        url = url.replace(/^www\./, '');

        if (!url) {
            throw new Error('Invalid URL. Please enter a valid domain.');
        }

        return url;
    }

    // CORS Proxies to try (in order of preference)
    const CORS_PROXIES = [
        (url) => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
        (url) => `https://corsproxy.io/?${encodeURIComponent(url)}`,
        (url) => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(url)}`
    ];

    // Fetch ads.txt with multiple fallbacks and retry logic
    async function fetchAdsTxtWithRetry(baseDomain) {
        // Domain variants to try (without www first, then with www)
        const domainVariants = [
            baseDomain,
            `www.${baseDomain}`
        ];

        const errors = [];

        // Try each domain variant
        for (const domain of domainVariants) {
            const adsTxtUrl = `https://${domain}/ads.txt`;

            // Try each CORS proxy
            for (let proxyIndex = 0; proxyIndex < CORS_PROXIES.length; proxyIndex++) {
                try {
                    const proxyUrl = CORS_PROXIES[proxyIndex](adsTxtUrl);
                    const content = await fetchWithTimeout(proxyUrl, 10000);

                    // Validate the content is actually ads.txt
                    if (isValidAdsTxt(content)) {
                        return { url: adsTxtUrl, content };
                    }
                } catch (error) {
                    errors.push(`${domain} (proxy ${proxyIndex + 1}): ${error.message}`);
                    // Continue to next proxy/domain
                }
            }
        }

        // All attempts failed
        throw new Error('No ads.txt found.');
    }

    // Fetch with timeout
    async function fetchWithTimeout(url, timeoutMs) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        try {
            const response = await fetch(url, {
                signal: controller.signal,
                headers: {
                    'Accept': 'text/plain, */*'
                }
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const content = await response.text();

            if (!content || content.trim().length === 0) {
                throw new Error('Empty response');
            }

            return content;
        } catch (error) {
            clearTimeout(timeoutId);
            if (error.name === 'AbortError') {
                throw new Error('Request timed out');
            }
            throw error;
        }
    }

    // Validate if content is a valid ads.txt file (not HTML or error page)
    function isValidAdsTxt(content) {
        if (!content || typeof content !== 'string') {
            return false;
        }

        const trimmedContent = content.trim().toLowerCase();

        // Check for HTML indicators (error pages, redirects, etc.)
        const htmlIndicators = [
            '<!doctype',
            '<html',
            '<head',
            '<body',
            '<meta',
            '<script',
            '<div',
            '<title',
            '<?xml',
            '<error',
            '404 not found',
            'page not found',
            'access denied',
            'forbidden'
        ];

        for (const indicator of htmlIndicators) {
            if (trimmedContent.includes(indicator)) {
                return false;
            }
        }

        // Positive validation: ads.txt should contain typical patterns
        // Lines with commas (domain, publisher-id, relationship)
        // Or comment lines starting with #
        // Or CONTACT/SUBDOMAIN/OWNERDOMAIN/MANAGERDOMAIN directives
        const lines = content.split('\n').filter(line => line.trim().length > 0);

        if (lines.length === 0) {
            return false;
        }

        // Check if at least some lines look like ads.txt entries
        const validPatterns = [
            /^#/,                                           // Comments
            /^[a-z0-9.-]+\s*,\s*[a-z0-9-]+\s*,\s*(DIRECT|RESELLER)/i,  // Standard ads.txt line
            /^CONTACT=/i,                                   // Contact directive
            /^SUBDOMAIN=/i,                                 // Subdomain directive
            /^OWNERDOMAIN=/i,                               // Owner domain directive
            /^MANAGERDOMAIN=/i,                             // Manager domain directive
            /^INVENTORYPARTNERDOMAIN=/i                     // Inventory partner directive
        ];

        let validLineCount = 0;
        for (const line of lines) {
            const trimmedLine = line.trim();
            if (validPatterns.some(pattern => pattern.test(trimmedLine))) {
                validLineCount++;
            }
        }

        // At least 1 valid line or mostly valid content
        return validLineCount > 0;
    }

    // Display ads.txt results
    function displayAdsTxtResults(url, content) {
        hideLoading();

        // Update URL display
        adsTxtUrl.textContent = url;

        // Display raw content exactly as received
        adsTxtContent.textContent = content;

        // Show ads.txt section
        adsTxtSection.classList.remove('hidden');
    }
});
