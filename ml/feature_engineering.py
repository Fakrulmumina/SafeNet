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


def brand_impersonation_flag(url: str, netloc: str) -> int:
    """
    Flags a URL if a known brand name appears in the URL but the domain itself
    isn't that brand's real domain — a classic phishing pattern
    (e.g. 'paypal' appearing inside 'paypal.com.confirm-identity.gq').
    """
    url_lower = url.lower()
    for brand in BRAND_NAMES:
        if brand in url_lower:
            # if the netloc doesn't END with the legit-looking "brand.com" pattern, flag it
            if not re.search(rf'(^|\.){brand}\.(com|org|net|co\.\w+)$', netloc):
                return 1
    return 0


def extract_features(url: str) -> dict:
    parsed = urlparse(url if '://' in url else 'http://' + url)
    netloc = parsed.netloc.lower()
    path = parsed.path
    full = url.lower()

    subdomain_parts = netloc.split('.')
    # crude subdomain depth: number of dot-separated labels before the last two (domain+TLD)
    subdomain_depth = max(0, len(subdomain_parts) - 2)

    features = {
        'url_length': len(url),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_underscores': url.count('_'),
        'num_digits': sum(c.isdigit() for c in url),
        'num_special_chars': len(re.findall(r'[^a-zA-Z0-9]', url)),
        'num_subdomains': subdomain_depth,
        'has_ip_address': has_ip_address(netloc),
        'has_at_symbol': 1 if '@' in url else 0,
        'has_https_token_in_path': 1 if 'https' in (path + parsed.query).lower() else 0,
        'suspicious_keyword_count': sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full),
        'brand_impersonation': brand_impersonation_flag(url, netloc),
        'is_https_scheme': 1 if parsed.scheme == 'https' else 0,
        'shannon_entropy': round(shannon_entropy(netloc), 3),
        'domain_length': len(netloc),
        'num_slashes': url.count('/'),
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
