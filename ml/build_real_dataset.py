"""
build_real_dataset.py
Combines real PhishTank (phishing) + real Tranco (legitimate) data
into one balanced, labeled dataset for training.
"""
import pandas as pd

# ---------- Phishing side: PhishTank ----------
phish = pd.read_csv('verified_online.csv')
phish = phish[(phish['verified'] == 'yes') & (phish['online'] == 'yes')]
phish_urls = phish['url'].drop_duplicates()
print(f"PhishTank: {len(phish_urls)} verified, currently-online phishing URLs")

# ---------- Legitimate side: Tranco top sites ----------
tranco = pd.read_csv('tranco_Q2X24.csv', names=['rank', 'domain'], header=None)
# take a large slice of top-ranked (most reputable) domains, matching phishing count
n = len(phish_urls)
legit_domains = tranco.head(n)['domain'].drop_duplicates()
legit_urls = 'https://' + legit_domains
print(f"Tranco: {len(legit_urls)} top-ranked legitimate domains (as URLs)")

# ---------- Combine ----------
df = pd.concat([
    pd.DataFrame({'url': phish_urls, 'label': 1}),
    pd.DataFrame({'url': legit_urls, 'label': 0}),
], ignore_index=True)

df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle
df.to_csv('real_dataset.csv', index=False)

print(f"\nFinal dataset: {len(df)} rows")
print(df['label'].value_counts())
print("\nSaved to real_dataset.csv")
