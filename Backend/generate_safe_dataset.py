import pandas as pd
import random

trusted = pd.read_csv("dataset/trusted_domains.csv")["domain"].tolist()

paths = [
    "", "/home", "/about", "/contact", "/services",
    "/products", "/help", "/support", "/login",
    "/search", "/faq", "/blog", "/news",
    "/dashboard", "/account", "/settings", "/profile"
]

queries = [
    "", "?id=1", "?page=2", "?ref=home",
    "?lang=en", "?user=test", "?mode=light"
]

safe_urls = []

for domain in trusted:
    for _ in range(200):   # 200 variations per domain
        path = random.choice(paths)
        query = random.choice(queries)

        safe_urls.append("https://" + domain + path + query)
        safe_urls.append("https://www." + domain + path + query)

safe_urls = list(set(safe_urls))

safe_df = pd.DataFrame(safe_urls, columns=["url"])
safe_df.to_csv("dataset/safe_urls.csv", index=False)

print("Safe dataset created:", len(safe_urls))
