"""
feature_engineering.py
Extracts lexical & statistical features from a raw URL string.
These are the same categories mentioned in SafeNet's proposal:
subdomain depth, special-char frequency, risky keywords, Shannon entropy.
"""
import re
import math
from urllib.parse import urlparse
import pandas as pd

# Keywords that commonly appear in phishing URLs, trying to impersonate trust/urgency
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
    'suspended', 'billing', 'webscr', 'banking', 'password', 'alert',
    'restricted', 'limited', 'urgent', 'security', 'authenticate'
]

# A short list of well-known brand names that phishing URLs frequently impersonate
BRAND_NAMES = [
    'paypal', 'apple', 'amazon', 'netflix', 'microsoft', 'google', 'facebook',
    'chase', 'wellsfargo', 'bankofamerica', 'instagram', 'linkedin', 'dropbox',
    'icloud', 'ebay', 'coinbase', 'binance', 'hsbc', 'citibank'
]


def shannon_entropy(s: str) -> float:
    """Measures how 'random-looking' a string is. Higher = more random/gibberish."""
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def has_ip_address(netloc: str) -> int:
    """Phishing URLs sometimes use a raw IP instead of a domain name."""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}'
    return 1 if re.match(ip_pattern, netloc) else 0


def brand_impersonation_flag(domain_and_path: str, netloc: str) -> int:
    """
    Flags a URL if a known brand name appears in the domain/path but the domain
    itself isn't that brand's real domain — a classic phishing pattern
    (e.g. 'paypal' appearing inside 'paypal.com.confirm-identity.gq').

    Deliberately scans domain+path only, NOT the query string — a search engine
    results page or a tracking/redirect URL can legitimately carry a brand name
    inside an encoded query parameter without the page itself impersonating
    that brand.
    """
    for brand in BRAND_NAMES:
        if brand in domain_and_path:
            # if the netloc doesn't END with the legit-looking "brand.com" pattern, flag it
            if not re.search(rf'(^|\.){brand}\.(com|org|net|co\.\w+)$', netloc):
                return 1
    return 0


def extract_features(url: str) -> dict:
    parsed = urlparse(url if '://' in url else 'http://' + url)
    netloc = parsed.netloc.lower()
    path = parsed.path
    # Keyword scan is deliberately restricted to domain+path and EXCLUDES the query
    # string. Query strings on legitimate sites (search engines, redirects, tracking
    # links) routinely carry words like "login"/"verify"/"confirm" as encoded
    # parameter VALUES (e.g. a Google search for a phishing URL, or a legitimate
    # "return-to-login-after-verify" redirect chain) without the page itself being
    # suspicious. Scanning the full URL caused real false positives in testing.
    domain_and_path = (netloc + path).lower()
    # Structural counts below (length, dots, hyphens, digits, special chars, slashes)
    # are deliberately measured over domain+path, NOT the query string. Query strings
    # on entirely legitimate URLs (search engines, OAuth redirects, analytics/tracking
    # links) are routinely long and heavy with %-encoding, &, =, digits — none of
    # which reflects anything about domain-spoofing or phishing structure. Measuring
    # these over the full URL caused real false positives on things like Google
    # search-result URLs in testing; phishing structure lives in domain+path.
    structural_basis = netloc + path

    subdomain_parts = netloc.split('.')
    # crude subdomain depth: number of dot-separated labels before the last two (domain+TLD)
    subdomain_depth = max(0, len(subdomain_parts) - 2)

    features = {
        'url_length': len(structural_basis),
        'num_dots': structural_basis.count('.'),
        'num_hyphens': structural_basis.count('-'),
        'num_underscores': structural_basis.count('_'),
        'num_digits': sum(c.isdigit() for c in structural_basis),
        'num_special_chars': len(re.findall(r'[^a-zA-Z0-9]', structural_basis)),
        'num_subdomains': subdomain_depth,
        'has_ip_address': has_ip_address(netloc),
        'has_at_symbol': 1 if '@' in url else 0,
        'has_https_token_in_path': 1 if 'https' in (path + parsed.query).lower() else 0,
        'suspicious_keyword_count': sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in domain_and_path),
        'brand_impersonation': brand_impersonation_flag(domain_and_path, netloc),
        'is_https_scheme': 1 if parsed.scheme == 'https' else 0,
        'shannon_entropy': round(shannon_entropy(netloc), 3),
        'domain_length': len(netloc),
        'num_slashes': structural_basis.count('/'),
    }
    return features


def build_feature_dataframe(urls: pd.Series) -> pd.DataFrame:
    rows = [extract_features(u) for u in urls]
    return pd.DataFrame(rows)


if __name__ == '__main__':
    # quick manual sanity check on a couple of examples
    examples = [
        'http://paypa1-secure-login.verify-account-update.xyz/signin',
        'https://www.paypal.com/signin',
    ]
    for ex in examples:
        print(ex)
        for k, v in extract_features(ex).items():
            print(f'  {k}: {v}')
        print()
