const express = require('express');
const cors = require('cors');
const dns = require('dns').promises;
const https = require('https');
const http = require('http');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));

// High-Speed In-Memory Cache (TTL: 10 minutes)
const cache = new Map();
function getCache(key) {
  const item = cache.get(key);
  if (!item) return null;
  if (Date.now() > item.expiry) {
    cache.delete(key);
    return null;
  }
  return item.data;
}
function setCache(key, data, ttlMs = 10 * 60 * 1000) {
  cache.set(key, { data, expiry: Date.now() + ttlMs });
}

// Built-in HTTP helper (Zero external dependency for fetch)
function fetchJson(url, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    if (maxRedirects <= 0) return reject(new Error('Too many redirects'));

    const client = url.startsWith('https') ? https : http;
    const req = client.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Accept': 'application/json, application/rdap+json'
      },
      timeout: 10000
    }, (res) => {
      // Handle redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return resolve(fetchJson(res.headers.location, maxRedirects - 1));
      }

      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          resolve(data);
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
  });
}

function cleanDomain(input) {
  if (!input) return '';
  let domain = input.trim().toLowerCase();
  domain = domain.replace(/^https?:\/\//i, '');
  domain = domain.replace(/\/.*$/, '');
  domain = domain.replace(/:.*$/, '');
  return domain;
}

// 0. API Information
app.get('/api', (req, res) => {
  res.json({
    status: 'online',
    service: 'Pro Zero-API-Key OSINT Engine',
    version: '1.0.0',
    endpoints: [
      '/api/osint/dns?domain=target.com',
      '/api/osint/subdomains?domain=target.com',
      '/api/osint/whois?domain=target.com',
      '/api/osint/headers?domain=target.com',
      '/api/osint/full-scan?domain=target.com'
    ]
  });
});

// 1. DNS Reconnaissance
app.get('/api/osint/dns', async (req, res) => {
  const domain = cleanDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: 'Domain parameter is required' });

  // Use reliable public resolvers (Cloudflare & Google)
  try {
    dns.setServers(['1.1.1.1', '8.8.8.8', '8.8.4.4']);
  } catch (e) {}

  const results = { domain, records: {} };
  try { results.records.A = await dns.resolve4(domain); } catch (e) { results.records.A = []; }
  try { results.records.AAAA = await dns.resolve6(domain); } catch (e) { results.records.AAAA = []; }
  try { results.records.MX = await dns.resolveMx(domain); } catch (e) { results.records.MX = []; }
  try { results.records.TXT = await dns.resolveTxt(domain); } catch (e) { results.records.TXT = []; }
  try { results.records.NS = await dns.resolveNs(domain); } catch (e) { results.records.NS = []; }

  try {
    const dmarc = await dns.resolveTxt(`_dmarc.${domain}`);
    results.records.DMARC = dmarc.flat();
  } catch (e) {
    results.records.DMARC = [];
  }

  const txtFlat = (results.records.TXT || []).flat().join(' ');
  results.mailSecurity = {
    hasSPF: txtFlat.toLowerCase().includes('v=spf1'),
    hasDMARC: (results.records.DMARC && results.records.DMARC.length > 0)
  };

  res.json(results);
});

// 2. Subdomains & Host Discovery (HackerTarget + Fallback)
app.get('/api/osint/subdomains', async (req, res) => {
  const domain = cleanDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: 'Domain parameter is required' });

  // Check in-memory cache first
  const cached = getCache(`subdomains_${domain}`);
  if (cached) return res.json(cached);

  try {
    const rawData = await fetchJson(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`);
    const results = [];
    if (typeof rawData === 'string' && !rawData.includes('error')) {
      const lines = rawData.trim().split('\n');
      lines.forEach(line => {
        const parts = line.split(',');
        if (parts.length >= 2) {
          results.push({ host: parts[0].trim(), ip: parts[1].trim() });
        }
      });
    }

    const payload = {
      domain,
      count: results.length,
      hosts: results,
      cached: false
    };
    setCache(`subdomains_${domain}`, { ...payload, cached: true });

    res.json(payload);
  } catch (error) {
    res.status(500).json({
      domain,
      error: 'Subdomain discovery error',
      details: error.message
    });
  }
});

// 3. WHOIS / RDAP Registration Intelligence
app.get('/api/osint/whois', async (req, res) => {
  const domain = cleanDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: 'Domain parameter is required' });

  try {
    const data = await fetchJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
    const events = {};
    if (data && data.events) {
      data.events.forEach(ev => {
        events[ev.eventAction] = ev.eventDate;
      });
    }

    res.json({
      domain,
      handle: data.handle || null,
      status: data.status || [],
      registrationDate: events.registration || null,
      expirationDate: events.expiration || null,
      lastChanged: events['last changed'] || null,
      nameservers: (data.nameservers || []).map(ns => ns.ldhName || ns.handle)
    });
  } catch (error) {
    res.status(500).json({
      domain,
      error: 'Failed to fetch RDAP/WHOIS data',
      details: error.message
    });
  }
});

// 4. Security Headers
app.get('/api/osint/headers', (req, res) => {
  const domain = cleanDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: 'Domain parameter is required' });

  let responded = false;
  const sendResponse = (statusCode, data) => {
    if (!responded) {
      responded = true;
      res.status(statusCode).json(data);
    }
  };

  const request = https.get(`https://${domain}`, {
    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
    timeout: 8000,
    rejectUnauthorized: false
  }, (response) => {
    const headers = response.headers;
    const securityCheck = {
      'Strict-Transport-Security': headers['strict-transport-security'] || 'MISSING',
      'Content-Security-Policy': headers['content-security-policy'] || 'MISSING',
      'X-Frame-Options': headers['x-frame-options'] || 'MISSING',
      'X-Content-Type-Options': headers['x-content-type-options'] || 'MISSING',
      'Referrer-Policy': headers['referrer-policy'] || 'MISSING',
      'Server': headers['server'] || 'HIDDEN'
    };
    const missingHeaders = Object.keys(securityCheck).filter(h => securityCheck[h] === 'MISSING');

    sendResponse(200, {
      domain,
      statusCode: response.statusCode,
      securityHeaders: securityCheck,
      missingCount: missingHeaders.length,
      missingHeaders
    });
  });

  request.on('error', (err) => {
    sendResponse(500, { domain, error: 'Failed to connect to host', details: err.message });
  });

  request.on('timeout', () => {
    request.destroy();
    sendResponse(504, { domain, error: 'Connection timed out' });
  });
});

app.listen(PORT, () => {
  console.log(`[+] Pro OSINT API Engine is running on http://localhost:${PORT}`);
});
