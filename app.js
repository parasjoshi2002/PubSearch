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

    // Ads.txt Search Elements
    const adsTxtSearchInput = document.getElementById('ads-txt-search-input');
    const adsTxtMatchCount = document.getElementById('ads-txt-match-count');
    const adsTxtPrevBtn = document.getElementById('ads-txt-prev-btn');
    const adsTxtNextBtn = document.getElementById('ads-txt-next-btn');
    const adsTxtClearBtn = document.getElementById('ads-txt-clear-btn');

    // Search state
    let originalAdsTxtContent = '';
    let currentSearchMatches = [];
    let currentMatchIndex = -1;

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

    // Ads.txt Search Event Listeners
    adsTxtSearchInput.addEventListener('input', handleAdsTxtSearch);
    adsTxtSearchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            if (e.shiftKey) {
                navigateToPrevMatch();
            } else {
                navigateToNextMatch();
            }
        } else if (e.key === 'Escape') {
            clearAdsTxtSearch();
            adsTxtSearchInput.blur();
        }
    });
    adsTxtPrevBtn.addEventListener('click', navigateToPrevMatch);
    adsTxtNextBtn.addEventListener('click', navigateToNextMatch);
    adsTxtClearBtn.addEventListener('click', () => {
        clearAdsTxtSearch();
        adsTxtSearchInput.focus();
    });

    // Global Ctrl+F handler for ads.txt search
    document.addEventListener('keydown', (e) => {
        // Check if Ctrl+F (or Cmd+F on Mac) is pressed and ads.txt section is visible
        if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
            if (!adsTxtSection.classList.contains('hidden')) {
                e.preventDefault();
                adsTxtSearchInput.focus();
                adsTxtSearchInput.select();
            }
        }
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

    // CORS Proxies to try as fallback - only reliable, working proxies
    // Note: allorigins /get endpoint returns JSON, /raw returns raw content
    const CORS_PROXIES = [
        {
            name: 'allorigins-json',
            url: (targetUrl) => `https://api.allorigins.win/get?url=${encodeURIComponent(targetUrl)}`,
            parseResponse: async (response) => {
                const json = await response.json();
                return json.contents;
            }
        },
        {
            name: 'allorigins-raw',
            url: (targetUrl) => `https://api.allorigins.win/raw?url=${encodeURIComponent(targetUrl)}`,
            parseResponse: async (response) => response.text()
        },
        {
            name: 'corsproxy',
            url: (targetUrl) => `https://corsproxy.io/?${encodeURIComponent(targetUrl)}`,
            parseResponse: async (response) => response.text()
        }
    ];

    // Fetch ads.txt - tries serverless API first, then falls back to CORS proxies
    async function fetchAdsTxtWithRetry(baseDomain) {
        const normalizedDomain = baseDomain.toLowerCase().trim();

        // STEP 1: Try our own serverless API first (most reliable, no CORS issues)
        try {
            const result = await fetchFromServerlessAPI(normalizedDomain);
            if (result) {
                return result;
            }
        } catch (error) {
            console.log('Serverless API failed, trying CORS proxies:', error.message);
        }

        // STEP 2: Fallback to CORS proxies
        const domainVariants = [normalizedDomain, `www.${normalizedDomain}`];
        const errors = [];

        for (const domain of domainVariants) {
            const adsTxtUrl = `https://${domain}/ads.txt`;

            for (const proxy of CORS_PROXIES) {
                try {
                    const proxyUrl = proxy.url(adsTxtUrl);
                    const content = await fetchWithProxy(proxyUrl, proxy.parseResponse);

                    if (isValidAdsTxt(content)) {
                        return { url: adsTxtUrl, content };
                    } else {
                        errors.push(`${proxy.name}: Invalid content`);
                    }
                } catch (error) {
                    errors.push(`${proxy.name}: ${error.message}`);
                }
            }
        }

        throw new Error('No ads.txt found.');
    }

    // Fetch from our Vercel Serverless API
    async function fetchFromServerlessAPI(domain) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 20000); // 20s timeout for server

        try {
            const apiUrl = `/api/fetch-ads-txt?domain=${encodeURIComponent(domain)}`;
            const response = await fetch(apiUrl, { signal: controller.signal });
            clearTimeout(timeoutId);

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `HTTP ${response.status}`);
            }

            const data = await response.json();

            if (data.success && data.content) {
                return { url: data.url, content: data.content };
            }

            throw new Error(data.error || 'No content returned');
        } catch (error) {
            clearTimeout(timeoutId);
            if (error.name === 'AbortError') {
                throw new Error('Server request timed out');
            }
            throw error;
        }
    }

    // Simple fetch with CORS proxy - no extra headers that trigger preflight
    async function fetchWithProxy(url, parseResponse) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);

        try {
            const response = await fetch(url, {
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const content = await parseResponse(response);

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

        // Quick rejection: if it starts with < it's likely HTML/XML
        if (trimmedContent.startsWith('<')) {
            return false;
        }

        // Check for HTML/error indicators (comprehensive list)
        const invalidIndicators = [
            '<!doctype',
            '<html',
            '<head',
            '<body',
            '<meta',
            '<script',
            '<div',
            '<title',
            '<span',
            '<p>',
            '<?xml',
            '<error',
            '<response',
            '404 not found',
            'page not found',
            'not found',
            'access denied',
            'forbidden',
            'unauthorized',
            "you don't have permission",
            'permission denied',
            'error 404',
            'error 403',
            'error 500',
            'internal server error',
            'bad gateway',
            'service unavailable',
            'cloudflare',
            'just a moment',
            'checking your browser',
            'enable javascript',
            'cookies are required',
            'reference #',
            'errors.edgesuite.net',
            '{"error',
            '{"message',
            'null',
            'undefined'
        ];

        for (const indicator of invalidIndicators) {
            if (trimmedContent.includes(indicator)) {
                return false;
            }
        }

        // Positive validation: ads.txt should contain typical patterns
        const lines = content.split('\n').filter(line => line.trim().length > 0);

        if (lines.length === 0) {
            return false;
        }

        // Check if at least some lines look like ads.txt entries
        const validPatterns = [
            /^#/,                                                           // Comments
            /^[a-z0-9.-]+\s*,\s*[a-z0-9_-]+\s*,\s*(DIRECT|RESELLER)/i,     // Standard ads.txt line
            /^[a-z0-9.-]+\s*,\s*pub-\d+\s*,\s*(DIRECT|RESELLER)/i,         // Google format
            /^CONTACT=/i,                                                   // Contact directive
            /^SUBDOMAIN=/i,                                                 // Subdomain directive
            /^OWNERDOMAIN=/i,                                               // Owner domain directive
            /^MANAGERDOMAIN=/i,                                             // Manager domain directive
            /^INVENTORYPARTNERDOMAIN=/i,                                    // Inventory partner directive
            /^VARIABLE=/i,                                                  // Variable directive
            /^placeholder/i                                                 // Placeholder (some sites use this)
        ];

        let validLineCount = 0;
        let totalNonEmptyLines = 0;

        for (const line of lines) {
            const trimmedLine = line.trim();
            if (trimmedLine.length > 0) {
                totalNonEmptyLines++;
                if (validPatterns.some(pattern => pattern.test(trimmedLine))) {
                    validLineCount++;
                }
            }
        }

        // At least 1 valid line, or if small file (<=3 lines), at least 30% valid
        if (validLineCount >= 1) {
            return true;
        }

        // For very small files, be more lenient
        if (totalNonEmptyLines <= 3 && totalNonEmptyLines > 0) {
            // Check if any line contains comma (basic ads.txt structure)
            return lines.some(line => line.includes(',') && !line.startsWith('#'));
        }

        return false;
    }

    // Display ads.txt results
    function displayAdsTxtResults(url, content) {
        hideLoading();

        // Update URL display
        adsTxtUrl.textContent = url;

        // Store original content and display it
        originalAdsTxtContent = content;
        adsTxtContent.textContent = content;

        // Reset search state
        clearAdsTxtSearch();

        // Show ads.txt section
        adsTxtSection.classList.remove('hidden');
    }

    // Ads.txt Search Functions
    function handleAdsTxtSearch() {
        const searchTerm = adsTxtSearchInput.value;

        if (!searchTerm) {
            // Clear highlights and reset
            adsTxtContent.textContent = originalAdsTxtContent;
            adsTxtMatchCount.textContent = '';
            adsTxtMatchCount.classList.remove('no-match');
            currentSearchMatches = [];
            currentMatchIndex = -1;
            updateNavButtons();
            return;
        }

        // Perform search and highlight
        highlightMatches(searchTerm);
    }

    function highlightMatches(searchTerm) {
        const content = originalAdsTxtContent;
        const escapedTerm = escapeRegExp(searchTerm);
        const regex = new RegExp(`(${escapedTerm})`, 'gi');

        // Find all matches
        currentSearchMatches = [];
        let match;
        const testRegex = new RegExp(escapedTerm, 'gi');
        while ((match = testRegex.exec(content)) !== null) {
            currentSearchMatches.push({
                index: match.index,
                text: match[0]
            });
        }

        if (currentSearchMatches.length === 0) {
            // No matches found
            adsTxtContent.textContent = originalAdsTxtContent;
            adsTxtMatchCount.textContent = 'No matches';
            adsTxtMatchCount.classList.add('no-match');
            currentMatchIndex = -1;
            updateNavButtons();
            return;
        }

        // Set current match to first one
        currentMatchIndex = 0;

        // Highlight all matches with special marking for current
        updateHighlights();

        // Update match count
        updateMatchCount();
        updateNavButtons();
    }

    function updateHighlights() {
        if (currentSearchMatches.length === 0) return;

        const searchTerm = adsTxtSearchInput.value;
        const escapedTerm = escapeRegExp(searchTerm);
        const content = originalAdsTxtContent;

        // Build highlighted HTML
        let result = '';
        let lastIndex = 0;
        let matchCounter = 0;

        const regex = new RegExp(escapedTerm, 'gi');
        let match;

        while ((match = regex.exec(content)) !== null) {
            // Add text before match
            result += escapeHtml(content.substring(lastIndex, match.index));

            // Add highlighted match
            const isCurrentMatch = matchCounter === currentMatchIndex;
            const highlightClass = isCurrentMatch ? 'search-highlight current' : 'search-highlight';
            result += `<span class="${highlightClass}" data-match-index="${matchCounter}">${escapeHtml(match[0])}</span>`;

            lastIndex = regex.lastIndex;
            matchCounter++;
        }

        // Add remaining text
        result += escapeHtml(content.substring(lastIndex));

        // Update content with highlights
        adsTxtContent.innerHTML = result;

        // Scroll current match into view
        scrollToCurrentMatch();
    }

    function scrollToCurrentMatch() {
        const currentHighlight = adsTxtContent.querySelector('.search-highlight.current');
        if (currentHighlight) {
            currentHighlight.scrollIntoView({
                behavior: 'smooth',
                block: 'center'
            });
        }
    }

    function navigateToNextMatch() {
        if (currentSearchMatches.length === 0) return;

        currentMatchIndex = (currentMatchIndex + 1) % currentSearchMatches.length;
        updateHighlights();
        updateMatchCount();
    }

    function navigateToPrevMatch() {
        if (currentSearchMatches.length === 0) return;

        currentMatchIndex = currentMatchIndex - 1;
        if (currentMatchIndex < 0) {
            currentMatchIndex = currentSearchMatches.length - 1;
        }
        updateHighlights();
        updateMatchCount();
    }

    function updateMatchCount() {
        if (currentSearchMatches.length > 0) {
            adsTxtMatchCount.textContent = `${currentMatchIndex + 1} of ${currentSearchMatches.length}`;
            adsTxtMatchCount.classList.remove('no-match');
        } else {
            adsTxtMatchCount.textContent = 'No matches';
            adsTxtMatchCount.classList.add('no-match');
        }
    }

    function updateNavButtons() {
        const hasMatches = currentSearchMatches.length > 0;
        adsTxtPrevBtn.disabled = !hasMatches;
        adsTxtNextBtn.disabled = !hasMatches;
    }

    function clearAdsTxtSearch() {
        adsTxtSearchInput.value = '';
        adsTxtContent.textContent = originalAdsTxtContent;
        adsTxtMatchCount.textContent = '';
        adsTxtMatchCount.classList.remove('no-match');
        currentSearchMatches = [];
        currentMatchIndex = -1;
        updateNavButtons();
    }

    // Helper function to escape special regex characters
    function escapeRegExp(string) {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    // Helper function to escape HTML characters
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
});
