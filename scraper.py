import re
import threading
from collections import Counter
from urllib.parse import urlparse, urljoin, urldefrag
from hashlib import sha256

# Optional HTML parser (recommended if installed)
try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

# --------- Analytics state (for report) ---------
_lock = threading.Lock()

unique_urls = set()                 # defragmented URLs
word_freq = Counter()               # global word frequency
subdomain_to_urls = {}              # host -> set(urls)
longest_page = {"url": None, "words": 0}
pages_processed = 0

# content-based duplicate detection
content_hashes = set()

# --------- Configuration / heuristics ---------
STOPWORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are", "as", "at",
    "be", "because", "been", "before", "being", "below", "between", "both", "but", "by",
    "can", "cannot", "could",
    "did", "do", "does", "doing", "down", "during",
    "each",
    "few", "for", "from", "further",
    "had", "has", "have", "having", "he", "her", "here", "hers", "herself", "him", "himself", "his", "how",
    "i", "if", "in", "into", "is", "it", "its", "itself",
    "just",
    "me", "more", "most", "my", "myself",
    "no", "nor", "not", "now",
    "of", "off", "on", "once", "only", "or", "other", "our", "ours", "ourselves", "out", "over", "own",
    "same", "she", "should", "so", "some", "such",
    "than", "that", "the", "their", "theirs", "them", "themselves", "then", "there", "these", "they",
    "this", "those", "through", "to", "too",
    "under", "until", "up",
    "very",
    "was", "we", "were", "what", "when", "where", "which", "while", "who", "whom", "why", "with", "would",
    "you", "your", "yours", "yourself", "yourselves"
}

TOKEN_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)

ALLOWED_SUFFIXES = (
    ".ics.uci.edu",
    ".cs.uci.edu",
    ".informatics.uci.edu",
    ".stat.uci.edu",
)

# HARD block known trap host(s)
BANNED_HOSTS = {
    "gitlab.ics.uci.edu",
}

# Pages with very few words are usually low-value (menus, redirects, login walls)
MIN_WORDS_THRESHOLD = 50

# Avoid very large HTML pages
MAX_CONTENT_SIZE = 10 * 1024 * 1024  # 10MB


# --------- Main scraper hook ---------
def scraper(url: str, resp) -> list:
    """
    Called after downloading a URL.
    Return a list of valid URLs to add to frontier.
    """
    if not resp or resp.status != 200 or not resp.raw_response:
        return []

    # Only HTML
    try:
        content_type = resp.raw_response.headers.get("Content-Type", "")
    except Exception:
        content_type = ""

    if content_type and "text/html" not in content_type.lower():
        return []

    raw_content = getattr(resp.raw_response, "content", None)
    if not raw_content or len(raw_content) == 0:
        return []
    if len(raw_content) > MAX_CONTENT_SIZE:
        return []

    page_url = defragment_url(resp.url if getattr(resp, "url", None) else url)

    # Extract links regardless, but only count analytics if page is valid + useful
    links = extract_next_links(page_url, resp)
    valid_links = [link for link in links if is_valid(link)]

    if not is_valid(page_url):
        return valid_links

    text = extract_text(resp)
    words_all = TOKEN_RE.findall(text)
    if len(words_all) < MIN_WORDS_THRESHOLD:
        return valid_links

    # Content dedupe (prevents near-identical pages inflating stats)
    text_hash = sha256(text.strip().encode("utf-8", errors="ignore")).hexdigest()
    with _lock:
        if text_hash in content_hashes:
            return valid_links
        content_hashes.add(text_hash)

    update_analytics(page_url, text)
    return valid_links


# --------- Link extraction ---------
def extract_next_links(url: str, resp) -> list:
    if not resp or resp.status != 200 or not resp.raw_response:
        return []

    content = getattr(resp.raw_response, "content", None)
    if not content:
        return []

    try:
        html = content.decode("utf-8", errors="ignore") if isinstance(content, (bytes, bytearray)) else str(content)
    except Exception:
        return []

    out = set()

    if BeautifulSoup is not None:
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")

        for a in soup.find_all("a", href=True):
            href = a.get("href")
            normalized = normalize_link(url, href)
            if normalized:
                out.add(normalized)
    else:
        for m in re.finditer(r'href\s*=\s*["\']([^"\']+)["\']', html, flags=re.IGNORECASE):
            normalized = normalize_link(url, m.group(1))
            if normalized:
                out.add(normalized)

    return list(out)


# --------- URL filtering ---------
def is_valid(url: str) -> bool:
    try:
        if not url:
            return False

        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"}:
            return False

        host = (parsed.hostname or "").lower()
        if not host:
            return False

        # HARD BLOCK gitlab (your trap)
        if host in BANNED_HOSTS:
            return False

        # Must be in allowed domains
        if not any(host == suf.lstrip(".") or host.endswith(suf) for suf in ALLOWED_SUFFIXES):
            return False

        # No fragments
        if parsed.fragment:
            return False

        path_lower = (parsed.path or "").lower()

        # Reject non-HTML-ish file extensions
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico|png|tiff?|mid|mp2|mp3|mp4|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            r"|ps|eps|tex|ppt|pptx|ppsx|doc|docx|xls|xlsx|data|dat|exe|bz2|tar|msi|bin|7z|dmg|iso|epub|dll|tgz|sha1"
            r"|rtf|jar|csv|rm|smil|wmv|swf|wma|zip|rar|gz|json|xml|apk|img|war|py|r|m|ipynb)$",
            path_lower
        ):
            return False

        # Avoid obvious login/search/admin areas (common traps)
        if any(x in path_lower for x in ["/login", "/logout", "/signin", "/sign_in", "/admin", "/search"]):
            return False

        # Query traps
        q = (parsed.query or "").lower()
        if q:
            bad_q_substrings = (
                "session", "sid", "phpsessid", "utm_",
                "replytocom",
                "action=edit", "action=login", "action=history",
                "do=edit", "do=login", "do=history",
                "diff=", "oldid=", "rev=",
                "format=print", "print=", "export", "ical=", "outlook-ical="
            )
            if any(b in q for b in bad_q_substrings):
                return False
            if q.count("&") >= 4:
                return False

        # Depth + repetition traps
        segments = [s for s in path_lower.split("/") if s]
        if len(segments) >= 12:
            return False
        if has_repeated_pattern(segments):
            return False

        # URL length (be reasonable)
        if len(url) > 500:
            return False

        return True

    except Exception:
        return False


# --------- Helpers ---------
def defragment_url(u: str) -> str:
    try:
        clean, _ = urldefrag(u)
        return clean
    except Exception:
        return u


def normalize_link(base_url: str, href: str):
    if not href:
        return None

    href = href.strip()
    if not href:
        return None

    if href.startswith(("mailto:", "tel:", "javascript:", "#")):
        return None

    abs_url = urljoin(base_url, href)
    abs_url = defragment_url(abs_url)

    # normalize http -> https
    if abs_url.startswith("http://"):
        abs_url = "https://" + abs_url[7:]

    # normalize trailing slash
    if abs_url.endswith("/") and len(abs_url) > len("https://a.b/"):
        abs_url = abs_url.rstrip("/")

    return abs_url


def extract_text(resp) -> str:
    content = getattr(resp.raw_response, "content", None)
    if not content:
        return ""

    try:
        html = content.decode("utf-8", errors="ignore") if isinstance(content, (bytes, bytearray)) else str(content)
    except Exception:
        return ""

    if BeautifulSoup is None:
        html = re.sub(r"<script.*?>.*?</script>", " ", html, flags=re.IGNORECASE | re.DOTALL)
        html = re.sub(r"<style.*?>.*?</style>", " ", html, flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r"<[^>]+>", " ", html)
        return text

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    for tag in soup(["script", "style", "noscript", "header", "footer", "nav"]):
        tag.decompose()

    return soup.get_text(separator=" ", strip=True)


def update_analytics(page_url: str, text: str) -> None:
    global pages_processed

    tokens = [t.lower() for t in TOKEN_RE.findall(text)]
    tokens = [t for t in tokens if len(t) >= 2 and t not in STOPWORDS]

    subdomain = get_subdomain(page_url)

    with _lock:
        if page_url in unique_urls:
            return

        unique_urls.add(page_url)

        if subdomain:
            subdomain_to_urls.setdefault(subdomain, set()).add(page_url)

        word_freq.update(tokens)

        wc = len(tokens)
        if wc > longest_page["words"]:
            longest_page["url"] = page_url
            longest_page["words"] = wc

        pages_processed += 1

        if pages_processed % 100 == 0:
            write_snapshot()


def get_subdomain(u: str):
    try:
        host = (urlparse(u).hostname or "").lower()
        if host.endswith(".uci.edu"):
            return host
        return None
    except Exception:
        return None


def has_repeated_pattern(segments):
    counts = Counter(segments)
    return any(v >= 3 for v in counts.values())


def write_snapshot() -> None:
    try:
        top50 = word_freq.most_common(50)
        subs = sorted((sd, len(urls)) for sd, urls in subdomain_to_urls.items())

        with open("crawler_report_snapshot.txt", "w", encoding="utf-8") as f:
            f.write(f"Unique pages (URL defragmented): {len(unique_urls)}\n")
            f.write(f"Longest page: {longest_page['url']} ({longest_page['words']} words)\n\n")
            f.write("Top 50 words:\n")
            for w, c in top50:
                f.write(f"{w}, {c}\n")
            f.write("\nSubdomains under uci.edu:\n")
            for sd, n in subs:
                f.write(f"{sd}, {n}\n")
            f.write(f"\nTotal pages processed: {pages_processed}\n")
    except Exception:
        pass
