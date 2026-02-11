import re
import threading
from collections import Counter
from urllib.parse import urlparse, urljoin, urldefrag
from hashlib import sha256

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

_lock = threading.Lock()

unique_urls = set()
word_freq = Counter()
subdomain_to_urls = {}
longest_page = {"url": None, "words": 0}
pages_processed = 0
content_hashes = set()

STOPWORDS = {
    "a","about","above","after","again","against","all","am","an","and","any","are","as","at",
    "be","because","been","before","being","below","between","both","but","by",
    "can","cannot","could",
    "did","do","does","doing","down","during",
    "each",
    "few","for","from","further",
    "had","has","have","having","he","her","here","hers","herself","him","himself","his","how",
    "i","if","in","into","is","it","its","itself",
    "just",
    "me","more","most","my","myself",
    "no","nor","not","now",
    "of","off","on","once","only","or","other","our","ours","ourselves","out","over","own",
    "same","she","should","so","some","such",
    "than","that","the","their","theirs","them","themselves","then","there","these","they",
    "this","those","through","to","too",
    "under","until","up",
    "very",
    "was","we","were","what","when","where","which","while","who","whom","why","with","would",
    "you","your","yours","yourself","yourselves"
}

TOKEN_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)

# Only crawl within the seed families (safer than ".ics.uci.edu" broadly)
ALLOWED_SUFFIXES = (
    ".ics.uci.edu",
    ".cs.uci.edu",
    ".informatics.uci.edu",
    ".stat.uci.edu",
)

# Explicitly banned hosts (the #1 is gitlab)
BANNED_HOSTS = {
    "gitlab.ics.uci.edu",
}

# Trap-ish path keywords that explode URL space or are useless for content
BANNED_PATH_SUBSTRINGS = (
    "/users/sign_in",
    "/users/sign_up",
    "/oauth",
    "/login",
    "/logout",
    "/sessions",
    "/admin",
    "/search",
)

# Common “edit/diff/history/print” style traps
BANNED_QUERY_SUBSTRINGS = (
    "session", "sid", "phpsessid", "utm_",
    "replytocom",
    "action=edit", "action=login", "action=history",
    "do=edit", "do=login", "do=history",
    "diff=", "oldid=", "rev=",
    "format=pdf", "format=print", "print=",
    "ical=", "outlook-ical=", "export",
)

# Content thresholds
MIN_WORDS_THRESHOLD = 50
MAX_CONTENT_SIZE = 10 * 1024 * 1024  # 10MB


def scraper(url, resp):
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
    if not raw_content:
        return []
    if len(raw_content) > MAX_CONTENT_SIZE:
        return []

    page_url = defragment_url(resp.url if getattr(resp, "url", None) else url)

    # Always extract links, but only count analytics if the page is valid + useful
    links = extract_next_links(page_url, resp)
    next_links = [link for link in links if is_valid(link)]

    if not is_valid(page_url):
        return next_links

    text = extract_text(resp)
    word_count = len(TOKEN_RE.findall(text))
    if word_count < MIN_WORDS_THRESHOLD:
        return next_links

    text_hash = sha256(text.strip().encode("utf-8", errors="ignore")).hexdigest()
    with _lock:
        if text_hash in content_hashes:
            return next_links
        content_hashes.add(text_hash)

    update_analytics(page_url, text)
    return next_links


def extract_next_links(url, resp):
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


def is_valid(url):
    try:
        if not url:
            return False

        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"}:
            return False

        host = (parsed.hostname or "").lower()
        if not host:
            return False

        # Block known trap hosts
        if host in BANNED_HOSTS:
            return False

        # Stay in scope: seed families
        if not any(host == suf.lstrip(".") or host.endswith(suf) for suf in ALLOWED_SUFFIXES):
            return False

        # Additional “tool” subdomain blocks (optional but helpful)
        # If you want strict crawling only on the public sites, uncomment:
        # if host.endswith(".ics.uci.edu") and not host.startswith(("www.", "ics.", "cs.", "informatics.", "stat.")):
        #     return False

        # No fragments
        if parsed.fragment:
            return False

        path = (parsed.path or "").lower()

        # Block obvious login/admin/search areas
        for bad in BANNED_PATH_SUBSTRINGS:
            if bad in path:
                return False

        # File extension filter
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico|png|tiff?|mid|mp2|mp3|mp4|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv"
            r"|pdf|ps|eps|tex|ppt|pptx|ppsx|doc|docx|xls|xlsx|data|dat|exe|bz2|tar|msi|bin|7z|dmg|iso|epub|dll"
            r"|tgz|sha1|rtf|jar|csv|rm|smil|wmv|swf|wma|zip|rar|gz|json|xml|apk|img|war|py|r|m|ipynb)$",
            path
        ):
            return False

        # Query traps
        q = (parsed.query or "").lower()
        if q:
            if any(b in q for b in BANNED_QUERY_SUBSTRINGS):
                return False
            # Too many params tends to explode
            if q.count("&") >= 4:
                return False

        # URL length (less strict than 200; 500 is safer for real pages)
        if len(url) > 500:
            return False

        # Depth + repetition traps
        segments = [s for s in path.split("/") if s]
        if len(segments) >= 12:
            return False
        if has_repeated_pattern(segments):
            return False

        return True

    except Exception:
        return False


def defragment_url(u: str) -> str:
    try:
        clean, _ = urldefrag(u)
        return clean
    except Exception:
        return u


def normalize_link(base_url, href):
    if not href:
        return None
    href = href.strip()
    if not href:
        return None

    if href.startswith(("mailto:", "tel:", "javascript:", "#")):
        return None

    abs_url = urljoin(base_url, href)
    abs_url = defragment_url(abs_url)

    # Normalize http -> https
    if abs_url.startswith("http://"):
        abs_url = "https://" + abs_url[7:]

    # Normalize trailing slash
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


def get_subdomain(u):
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
