"""
IP -> website name, learned live from the traffic itself.

Two sources feed HostnameMap:
  * DNS responses: when the phone asks "youtube.com?" and the answer lists
    A records, every answered IP is remembered as belonging to the queried
    name (the name the user actually asked for, not the CNAME chain).
  * TLS ClientHello SNI: the server name sent in cleartext at the start of
    every HTTPS connection. Covers sites whose DNS lookup we never saw
    (cached on the phone, or resolved before capture started).

site_label() turns a raw hostname such as "rr3---sn-abc.googlevideo.com"
into something presentable ("YouTube"), falling back to the registrable
domain ("nytimes.com").

Limits: encrypted DNS (DoH / iCloud Private Relay) hides both sources, and
QUIC (HTTP/3) hides SNI - those flows fall back to the Organisation column.
"""

from __future__ import annotations

from typing import Dict, Optional

from shared.packet_record import PacketRecord

# Suffix -> friendly name. Checked longest-suffix-first via site_label().
FRIENDLY_SITES: Dict[str, str] = {
    "youtube.com": "YouTube",
    "youtu.be": "YouTube",
    "googlevideo.com": "YouTube",
    "ytimg.com": "YouTube",
    "ggpht.com": "YouTube",
    "youtube-nocookie.com": "YouTube",
    "nytimes.com": "NYTimes (Wordle)",
    "nyt.com": "NYTimes (Wordle)",
    "google.com": "Google",
    "gstatic.com": "Google",
    "googleapis.com": "Google",
    "instagram.com": "Instagram",
    "cdninstagram.com": "Instagram",
    "facebook.com": "Facebook",
    "fbcdn.net": "Facebook",
    "whatsapp.net": "WhatsApp",
    "whatsapp.com": "WhatsApp",
    "netflix.com": "Netflix",
    "nflxvideo.net": "Netflix",
    "spotify.com": "Spotify",
    "scdn.co": "Spotify",
    "tiktok.com": "TikTok",
    "tiktokcdn.com": "TikTok",
    "reddit.com": "Reddit",
    "redd.it": "Reddit",
    "redditstatic.com": "Reddit",
    "wikipedia.org": "Wikipedia",
    "amazon.com": "Amazon",
    "apple.com": "Apple",
    "icloud.com": "Apple iCloud",
    "mzstatic.com": "Apple",
    "twitter.com": "X / Twitter",
    "x.com": "X / Twitter",
    "twimg.com": "X / Twitter",
    "snapchat.com": "Snapchat",
    "discord.com": "Discord",
    "github.com": "GitHub",
    "openai.com": "OpenAI",
    "chatgpt.com": "ChatGPT",
    "anthropic.com": "Anthropic",
    "claude.ai": "Claude",
}

# Second-level labels that mean the registrable domain has three parts
# (bbc.co.uk, not co.uk).
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}


def _registrable(hostname: str) -> str:
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    if len(parts[-1]) == 2 and parts[-2] in _SECOND_LEVEL and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def site_label(hostname: str) -> str:
    host = hostname.lower().rstrip(".")
    labels = host.split(".")
    for i in range(len(labels) - 1):
        suffix = ".".join(labels[i:])
        friendly = FRIENDLY_SITES.get(suffix)
        if friendly:
            return friendly
    return _registrable(host)


def _is_reverse_lookup(name: str) -> bool:
    return name.endswith(".arpa")


class HostnameMap:
    def __init__(self) -> None:
        self._by_ip: Dict[str, str] = {}

    def learn(self, record: PacketRecord) -> None:
        """Update the map from one decoded packet. Never raises."""
        try:
            if record.dns_is_response and record.dns_query_name and record.dns_answers:
                name = record.dns_query_name
                if not _is_reverse_lookup(name):
                    for answer in record.dns_answers:
                        _, _, target = answer.partition(" -> ")
                        if target.count(".") == 3 and target.replace(".", "").isdigit():
                            self._by_ip[target] = name

            sni = getattr(record, "tls_sni", None)
            if sni and record.dst_ip:
                self._by_ip[record.dst_ip] = sni
        except Exception:
            pass

    def hostname(self, ip: Optional[str]) -> Optional[str]:
        return self._by_ip.get(ip) if ip else None

    def site(self, *ips: Optional[str]) -> str:
        """Friendly site name for the first IP we know a hostname for, else ''."""
        for ip in ips:
            name = self.hostname(ip)
            if name:
                return site_label(name)
        return ""
