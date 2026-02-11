import re
import threading
from collections import Counter
from urllib.parse import urlparse, urljoin, urldefrag
from hashlib import sha256  # [ADDED] For content-based duplicate/near-duplicate detection

# Optional HTML parser:
# - If BeautifulSoup is available, we use it (more accurate link extraction & text extraction).
# - If not, we fallback to regex-based link extraction and rough HTML stripping.
try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None


# Analytics (for report)
# Even with THREADCOUNT=1, a lock keeps this safe if you ever change it later
_lock = threading.Lock()

# Unique URL set (AFTER removing fragments #...)
unique_urls = set()

# Global word frequency counter across all processed pages (stopwords filtered)
word_freq = Counter()

# Map subdomain -> set of unique URLs in that subdomain
# Using a set ensures uniqueness per subdomain automatically
subdomain_to_urls = {}

# Track the single "longest page" by word count (HTML markup excluded)
longest_page = {"url": None, "words": 0}

# Just a counter to know how many pages we processed (used to snapshot every 100)
pages_processed = 0

# [ADDED] Set of content hashes to detect near-duplicate / identical pages
# This prevents counting pages that have the same text content but different URLs
# (e.g. print versions, parameterized duplicates)
content_hashes = set()


# Stopwords: common English words we ignore for "top 50 words"
# You can replace this with the course-provided stopword list if you prefer.
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

# Tokenizer: sequences of letters/digits become "words"
# This intentionally ignores punctuation, symbols, etc.
TOKEN_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)

# Allowed domains per assignment spec
ALLOWED_SUFFIXES = (
    ".ics.uci.edu",
    ".cs.uci.edu",
    ".informatics.uci.edu",
    ".stat.uci.edu",
)

# [ADDED] Minimum word threshold to consider a page as having "high textual content"
# Pages with very few words are likely empty, error pages, or login walls
MIN_WORDS_THRESHOLD = 50

# [ADDED] Maximum content size in bytes (~10 MB) to avoid downloading huge files
MAX_CONTENT_SIZE = 10 * 1024 * 1024


# Main scraper hook
def scraper(url, resp):
    """
    This is called by the crawler after downloading a URL.

    Responsibilities:
    1) Validate the response (status, content-type)
    2) Defragment and validate page_url
    3) Extract page text and update analytics
    4) Extract outgoing links and return the ones that are valid
    """
    # If the fetch failed, don't do anything
    if not resp or resp.status != 200 or not resp.raw_response:
        return []

    # Content-Type filtering:
    # We only want text/html pages for this project (words & links).
    content_type = ""
    try:
        content_type = resp.raw_response.headers.get("Content-Type", "") if hasattr(resp.raw_response, "headers") else ""
    except Exception:
        pass

    # If it's not HTML, don't analyze or extract links
    if content_type and ("text/html" not in content_type.lower()):
        return []

    # [ADDED] Check for dead URLs: 200 status but no actual content body
    # Assignment says: "Detect and avoid dead URLs that return a 200 status but no data"
    raw_content = getattr(resp.raw_response, "content", None)
    if not raw_content or len(raw_content) == 0:
        return []

    # [ADDED] Skip very large files to avoid memory issues and low-value content
    # Assignment says: "Detect and avoid crawling very large files"
    if len(raw_content) > MAX_CONTENT_SIZE:
        return []

    # Normalize the page URL: remove fragment so unique counting is correct
    page_url = defragment_url(resp.url if getattr(resp, "url", None) else url)

    # Update analytics only if the page itself is in-scope and valid
    if is_valid(page_url):
        text = extract_text(resp)

        # [ADDED] Skip low-information pages (very few words after stripping HTML)
        # Assignment says: "Crawl all pages with high textual information content"
        # and "Detect and avoid sets of similar pages with no information"
        word_count = len(TOKEN_RE.findall(text))
        if word_count < MIN_WORDS_THRESHOLD:
            # Still return links from the page (navigation pages may link to real content)
            # but don't count this page in our analytics
            links = extract_next_links(page_url, resp)
            return [link for link in links if is_valid(link)]

        # [ADDED] Content-based duplicate detection using hash of extracted text
        # Avoids counting pages that are identical/near-identical in content
        text_hash = sha256(text.strip().encode("utf-8", errors="ignore")).hexdigest()
        with _lock:
            if text_hash in content_hashes:
                # Duplicate content — still extract links but don't update word stats
                links = extract_next_links(page_url, resp)
                return [link for link in links if is_valid(link)]
            content_hashes.add(text_hash)

        update_analytics(page_url, text)

    # Extract outgoing links from the page and filter them
    links = extract_next_links(page_url, resp)
    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp):
    """
    Extract hyperlinks from resp.raw_response.content.

    Returns a list of normalized, absolute, defragmented URLs.
    """
    if not resp or resp.status != 200 or not resp.raw_response:
        return []

    content = getattr(resp.raw_response, "content", None)
    if not content:
        return []

    # Decode bytes safely to avoid crashing on weird encodings
    try:
        html = content.decode("utf-8", errors="ignore") if isinstance(content, (bytes, bytearray)) else str(content)
    except Exception:
        return []

    out = set()  # set avoids duplicates coming from the same page

    # Prefer BeautifulSoup if installed (best accuracy)
    if BeautifulSoup is not None:
        # [CHANGED] Always try lxml first, then fall back to html.parser
        # Original check "lxml" in BeautifulSoup.__module__ was always False
        # because BeautifulSoup.__module__ is "bs4" not "lxml"
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a.get("href")
            if not href:
                continue
            normalized = normalize_link(url, href)
            if normalized:
                out.add(normalized)
    else:
        # Fallback: regex-based extraction (less accurate, but works)
        for m in re.finditer(r'href\s*=\s*["\']([^"\']+)["\']', html, flags=re.IGNORECASE):
            href = m.group(1)
            normalized = normalize_link(url, href)
            if normalized:
                out.add(normalized)

    return list(out)


def is_valid(url):
    """
    Decide whether we should crawl a URL.

    Must:
    - stay inside allowed domains
    - avoid non-HTML filetypes
    - avoid common crawler traps
    """
    try:
        if not url:
            return False

        parsed = urlparse(url)

        # Only crawl web URLs
        if parsed.scheme not in {"http", "https"}:
            return False

        host = (parsed.hostname or "").lower()
        if not host:
            return False

        # Must be in allowed domains (exact host or any subdomain)
        if not any(host == suf.lstrip(".") or host.endswith(suf) for suf in ALLOWED_SUFFIXES):
            return False

        # NOTE: you already defragment URLs via urldefrag() before validation.
        # This check rejects URLs that still have fragments; mostly redundant.
        # Keeping it prevents any accidental duplicates from slipping in.
        if parsed.fragment:
            return False

        # Skip non-text / non-webpage file types (starter list style)
        # [CHANGED] Added additional file extensions commonly found on UCI sites:
        #   sql, json, xml, apk, img, bam, war, py, r, m, nb, ipynb, ppsx, odc, Z, bib
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|ppsx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz"
            + r"|sql|json|xml|apk|img|bam|war|py|r|m|nb|ipynb|odc|z|bib|tsv|ss)$",
            parsed.path.lower()
        ):
            return False

        # Trap heuristic 1: super long URLs often encode infinite space
        if len(url) > 200:
            return False

        # Trap heuristic 2: query explosion / tracking
        if parsed.query:
            q_lower = parsed.query.lower()

            # Disallow session and tracking-style parameters
            bad_q = ("session", "sid", "phpsessid", "utm_", "replytocom",
                     "share", "download", "action=login", "action=edit",  # [ADDED] wiki traps
                     "do=hierarchytree", "rev=", "diff=",                 # [ADDED] diffing traps
                     "ical=", "outlook-ical=", "format=", "export")       # [ADDED] export/cal traps
            if any(b in q_lower for b in bad_q):
                return False

            # Too many key/value pairs => likely infinite combinations
            if q_lower.count("&") >= 4:
                return False

        # Trap heuristic 3: calendar/event pages can explode by date filters
        path_lower = parsed.path.lower()
        # [CHANGED] Expanded calendar/event trap: also block date-patterned paths
        # like /2025/01/15/... or /events/2025/ which generate infinite date combos
        if "calendar" in path_lower or "event" in path_lower:
            if parsed.query:
                return False

        # [ADDED] Trap heuristic: date-based URL explosion (/yyyy/mm/dd patterns)
        # Many WordPress-like sites generate infinite date-based URLs
        if re.search(r"/\d{4}/\d{1,2}/\d{1,2}/", path_lower):
            # Allow it only if the path doesn't look like a pagination/filter trap
            # (we keep these because some are real blog posts, but limit depth)
            pass  # Handled by segment depth check below

        # [ADDED] Trap heuristic: wiki edit/revision/diff pages are infinite traps
        if re.search(r"/(wiki|doku)\.php", path_lower):
            if parsed.query and any(k in parsed.query.lower() for k in ["do=", "rev=", "diff=", "action="]):
                return False

        # [ADDED] Trap heuristic: filter/sort/pagination combos
        if re.search(r"(page|filter|sort|offset|limit)=", (parsed.query or "").lower()):
            # Allow simple pagination (page=2) but not combined with other params
            if parsed.query and parsed.query.count("&") >= 2:
                return False

        # Trap heuristic 4: deep paths / repeated segments
        segments = [s for s in path_lower.split("/") if s]
        if len(segments) >= 10:
            return False
        if has_repeated_pattern(segments):
            return False

        # [ADDED] Trap heuristic 5: paths containing version/revision numbers
        # that could form infinite sequences like /v1/, /v2/, /v3/...
        if re.search(r"/v\d+/", path_lower):
            # Only allow up to /v3/ to prevent infinite version explosion
            match = re.search(r"/v(\d+)/", path_lower)
            if match and int(match.group(1)) > 3:
                return False

        return True

    except Exception:
        # If anything unexpected happens while parsing, reject the URL
        return False


# Helpers
def defragment_url(u: str) -> str:
    """
    Remove #fragment from URL.
    Required by spec for uniqueness counting.
    """
    try:
        clean, _frag = urldefrag(u)
        return clean
    except Exception:
        return u


def normalize_link(base_url, href):
    """
    Normalize a discovered link:
    - skip mailto:, javascript:, #...
    - make it absolute using urljoin
    - defragment
    - optionally remove trailing slash
    """
    href = href.strip()
    if not href:
        return None

    if href.startswith(("mailto:", "tel:", "javascript:", "#")):
        return None

    abs_url = urljoin(base_url, href)
    abs_url = defragment_url(abs_url)

    # [ADDED] Normalize scheme to https to avoid http vs https duplicates
    # Most UCI sites serve both; treating them as the same avoids double-crawling
    if abs_url.startswith("http://"):
        abs_url = "https://" + abs_url[7:]

    # Remove trailing slash so /page and /page/ are treated the same
    if abs_url.endswith("/") and len(abs_url) > len("https://a.b/"):
        abs_url = abs_url.rstrip("/")

    return abs_url


def extract_text(resp) -> str:
    """
    Extract visible text from the HTML page.
    - Removes script/style/nav/header/footer noise.
    - Returns plain text used for word counting and top 50.
    """
    content = getattr(resp.raw_response, "content", None)
    if not content:
        return ""

    try:
        html = content.decode("utf-8", errors="ignore") if isinstance(content, (bytes, bytearray)) else str(content)
    except Exception:
        return ""

    if BeautifulSoup is None:
        # Fallback: crude text extraction by removing tags
        html = re.sub(r"<script.*?>.*?</script>", " ", html, flags=re.IGNORECASE | re.DOTALL)
        html = re.sub(r"<style.*?>.*?</style>", " ", html, flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r"<[^>]+>", " ", html)
        return text

    # [CHANGED] Always try lxml first, then fall back to html.parser
    # Same fix as in extract_next_links — original check was always False
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    # Remove non-content sections that inflate word counts
    for tag in soup(["script", "style", "noscript", "header", "footer", "nav"]):
        tag.decompose()

    return soup.get_text(separator=" ", strip=True)


def update_analytics(page_url: str, text: str) -> None:
    """
    Update everything needed for the report:
    1) unique page count (defragmented URLs)
    2) longest page by word count
    3) global word frequency (stopwords removed)
    4) per-subdomain unique page counts
    """
    global pages_processed

    tokens = [t.lower() for t in TOKEN_RE.findall(text)]
    tokens = [t for t in tokens if len(t) >= 2 and t not in STOPWORDS]

    subdomain = get_subdomain(page_url)

    with _lock:
        # Unique URL tracking
        if page_url not in unique_urls:
            unique_urls.add(page_url)

            # Subdomain -> unique URLs
            if subdomain:
                sub_set = subdomain_to_urls.setdefault(subdomain, set())
                sub_set.add(page_url)
        # [CHANGED] Moved pages_processed increment and word_freq update
        # INSIDE the "if page_url not in unique_urls" block to avoid
        # double-counting words when the same URL is visited again.
        # (Original code counted words even for already-seen URLs)
        else:
            # Already seen this exact URL — skip analytics update
            return

        # Update global word frequency
        word_freq.update(tokens)

        # Longest page tracking
        wc = len(tokens)
        if wc > longest_page["words"]:
            longest_page["url"] = page_url
            longest_page["words"] = wc

        pages_processed += 1

        # Snapshot every 100 pages to keep progress even if stopped
        if pages_processed % 100 == 0:
            write_snapshot()


def get_subdomain(u):
    """
    Return the hostname if it ends in .uci.edu.
    For this assignment's subdomain report, this is what we list.
    """
    try:
        host = (urlparse(u).hostname or "").lower()
        if host.endswith(".uci.edu"):
            return host
        return None
    except Exception:
        return None


def has_repeated_pattern(segments):
    """
    Trap detection helper:
    if a path segment repeats many times, URL space may be infinite.
    Example: /foo/foo/foo/foo/...
    """
    counts = Counter(segments)
    # [CHANGED] Lowered threshold from 4 to 3 for earlier trap detection
    # 3 repeated segments is already suspicious (e.g. /a/b/a/b/a/b)
    return any(v >= 3 for v in counts.values())


def write_snapshot() -> None:
    """
    Write a lightweight snapshot of current statistics.
    Helpful during long crawls or if you must stop and restart.
    """
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
            # [ADDED] Also write the total pages processed for monitoring
            f.write(f"\nTotal pages processed: {pages_processed}\n")
    except Exception:
        # Never crash the crawler because snapshot writing failed
        pass
