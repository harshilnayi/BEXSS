"""
xss_crawler.py
Lightweight crawler that discovers URLs (GET) and HTML forms (POST).
Returns two lists: get_urls, post_forms
Each POST form is a tuple: (action_url, {field: default_value, ...})
"""
from collections import deque
from urllib.parse import urljoin, urlparse
import requests, re
from bs4 import BeautifulSoup

def _in_scope(url: str, base_netloc: str) -> bool:
    return urlparse(url).netloc == base_netloc

def crawl(start_url: str, max_depth: int = 2):
    visited, get_urls, post_forms = set(), [], []
    q = deque([(start_url, 0)])
    base_netloc = urlparse(start_url).netloc

    while q:
        url, depth = q.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        try:
            r = requests.get(url, timeout=5)
        except Exception:
            continue

        soup = BeautifulSoup(r.text, "lxml")

        # collect GET URLs with params
        if "?" in urlparse(url).query:
            get_urls.append(url)

        # follow links
        for tag in soup.find_all("a", href=True):
            link = urljoin(url, tag["href"].split("#")[0])
            if link.startswith(("http://", "https://")) and _in_scope(link, base_netloc):
                q.append((link, depth + 1))

        # collect HTML forms
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action") or url)
            method = (form.get("method") or "get").lower()
            fields = {inp.get("name"): (inp.get("value") or "test")
                      for inp in form.find_all(["input", "textarea"]) if inp.get("name")}
            if method == "post" and fields:
                post_forms.append((action, fields))

    return get_urls, post_forms
