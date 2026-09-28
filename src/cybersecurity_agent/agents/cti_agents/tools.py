from typing import Dict, List

import feedparser

RSS_SOURCES: Dict[str, str] = {
    "talos": "https://blog.talosintelligence.com/rss/",
    "bleepingcomputer": "https://www.bleepingcomputer.com/feed/",
}


def fetch_rss_entries(feed_url: str, limit: int = 5) -> List[dict]:
    """Fetch and normalize entries from an RSS/Atom feed."""
    parsed = feedparser.parse(feed_url)
    entries = []
    for entry in parsed.entries[:limit]:
        entries.append({
            "title": entry.get("title", ""),
            "summary": entry.get("summary", entry.get("description", "")),
            "link": entry.get("link", ""),
            "published": entry.get("published", ""),
        })
    return entries


def entry_to_feed_text(entry: dict) -> str:
    """Flatten a normalized RSS entry into raw feed text for the CTI Agent's prompt."""
    return f"{entry['title']}\n{entry['summary']}\nSource: {entry['link']}"
