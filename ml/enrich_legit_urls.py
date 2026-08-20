"""
enrich_legit_urls.py
Real Tranco data only gives bare domains (e.g. "amazon.com"), but real users
constantly visit legitimate URLs WITH paths, query strings, and subdomains
(e.g. amazon.com/gp/orders, github.com/user/repo, mail.google.com/mail/u/0/#inbox).

Training only against bare homepages let the model shortcut on "has a path? -> phishing",
which would fail immediately on real deep-link traffic. This script generates a
realistic MIX of legitimate URL shapes (rule-based, clearly documented as such —
not scraped/live data) so path presence stops being a free discriminator.
"""
import random
import pandas as pd

random.seed(42)

# Path templates grouped by common site archetypes. {slug}/{id}/{q} get filled in.
PATH_TEMPLATES = [
    '/',
    '/',
    '/about',
    '/about-us',
    '/contact',
    '/search?q={q}',
    '/blog/{slug}',
    '/blog/{yyyy}/{mm}/{slug}',
    '/news/{slug}',
    '/products/{slug}',
    '/product/{id}',
    '/category/{slug}',
    '/user/{slug}',
    '/users/{slug}/repos',
    '/questions/{id}/{slug}',
    '/watch?v={id}',
    '/article/{slug}',
    '/docs/{slug}',
    '/help/{slug}',
    '/support/{slug}',
    '/account/settings',
    '/account/orders',
    '/mail/u/0/#inbox',
    '/login',
    '/signin',
    '/dashboard',
    '/pricing',
    '/careers',
    '/{slug}/{slug2}',
    '/en-us/{slug}',
    '/wiki/{slug}',
    '/r/{slug}',
    '/status/{id}',
    '/p/{id}/',
    '/collections/{slug}',
    '/download/{slug}',
]

SLUG_WORDS = [
    'python-tutorial', 'machine-learning-basics', 'best-laptops-2026', 'travel-guide',
    'recipe-ideas', 'home-improvement', 'fitness-tips', 'stock-market-news',
    'climate-change', 'space-exploration', 'wireless-headphones', 'ai-research',
    'data-science', 'web-development', 'electric-vehicles', 'remote-work',
    'productivity-hacks', 'cyber-security', 'cloud-computing', 'startup-funding'
]


def random_slug():
    return random.choice(SLUG_WORDS)


def fill_template(template):
    return template.format(
        slug=random_slug(),
        slug2=random_slug(),
        id=random.randint(1000, 999999),
        q=random.choice(SLUG_WORDS).replace('-', '+'),
        yyyy=random.choice(['2024', '2025', '2026']),
        mm=f"{random.randint(1,12):02d}",
    )


def enrich(domain: str) -> str:
    template = random.choice(PATH_TEMPLATES)
    path = fill_template(template)
    scheme = 'https'
    return f"{scheme}://{domain}{path}"


if __name__ == '__main__':
    tranco = pd.read_csv('tranco_Q2X24.csv', names=['rank', 'domain'], header=None)
    phish = pd.read_csv('verified_online.csv')
    phish = phish[(phish['verified'] == 'yes') & (phish['online'] == 'yes')]
    phish_urls = phish['url'].drop_duplicates()

    n = len(phish_urls)
    legit_domains = tranco.head(n)['domain'].drop_duplicates()
    legit_urls = legit_domains.apply(enrich)

    df = pd.concat([
        pd.DataFrame({'url': phish_urls, 'label': 1}),
        pd.DataFrame({'url': legit_urls, 'label': 0}),
    ], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv('real_dataset_enriched.csv', index=False)

    print(f"Enriched legitimate URL examples:")
    for u in legit_urls.head(8):
        print(f"  {u}")
    print(f"\nFinal dataset: {len(df)} rows, saved to real_dataset_enriched.csv")
