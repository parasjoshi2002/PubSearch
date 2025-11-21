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

    // Example buttons
    const exampleButtons = document.querySelectorAll('.example-btn');

    // Event Listeners
    analyzeBtn.addEventListener('click', handleAnalyze);
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
});
