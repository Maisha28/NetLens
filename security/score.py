"""
Per-device security score (A-F) from what NetLens observed - metadata only.

The score is deliberately simple and fully explainable: every device starts at
100 and loses points for specific, observed problems. Each deduction is listed in
the report together with the reason and what to do about it, and the table of
deduction sizes is printed in the report's method note. There is no hidden
weighting and no machine learning, so the grade can be defended line by line.

What it can and cannot say: it grades only what a passive observer on the hotspot
can see - the cleartext TLS handshake, plaintext protocols, and the behaviour
NetLens's three rules flagged. It is not a vulnerability scan and says nothing
about a device's software, patches or what is inside encrypted traffic.
"""

from __future__ import annotations

from typing import Dict, List, Optional

GRADE_BANDS = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]
MIN_PACKETS = 30  # below this a device is "not enough data", not "perfect"

# key -> (points lost, short rule shown in the method note)
DEDUCTIONS: Dict[str, tuple] = {
    "weak_tls_client": (40, "Offers TLS 1.1 or older (RFC 8996 deprecated it)"),
    "weak_tls_ciphers": (15, "Offers broken cipher suites (RC4, 3DES, export, NULL, ...)"),
    "weak_tls_negotiated": (15, "Actually negotiated a broken cipher or old TLS version"),
    "cleartext": (20, "Sends application data without encryption (first protocol)"),
    "cleartext_more": (5, "Each additional unencrypted protocol (cap 10 more)"),
    "port_scan": (25, "Was flagged for scanning other devices' ports"),
    "arp_spoof": (35, "Was flagged for impersonating another device (ARP spoofing)"),
    "arp_victim": (10, "Its address was impersonated by another device"),
    "bandwidth_hog": (10, "Had unusually heavy data use (per rule, cap 20)"),
}

ADVICE = {
    "weak_tls_client": "Update this device's firmware, or replace it. It still speaks protocol versions attackers can break. If it cannot be updated, keep it on a separate guest network.",
    "weak_tls_ciphers": "Update the device or its apps so they stop offering broken encryption options.",
    "weak_tls_negotiated": "The connection actually used weak encryption. Stop using that service from this device, or ask the vendor for a fix.",
    "cleartext": "Use the encrypted version (HTTPS instead of HTTP, SFTP/SSH instead of FTP/Telnet) and never type passwords over an unencrypted connection.",
    "port_scan": "Find out why this device probes other devices. If it is not an administrator's tool, treat it as compromised: disconnect it and scan it for malware.",
    "arp_spoof": "This device pretended to be the gateway. Disconnect it from the network now and investigate - it may be intercepting other devices' traffic.",
    "arp_victim": "Another device claimed this device's address, so its traffic may have been intercepted. Check the Alerts page for who, and reconnect after the culprit is removed.",
    "bandwidth_hog": "Check what is using the data. A backup or update is fine; an unexpected upload to an unknown server is not.",
}

TITLES = {
    "weak_tls_client": "Uses outdated encryption (TLS 1.1 or older)",
    "weak_tls_ciphers": "Offers broken encryption options",
    "weak_tls_negotiated": "Used weak encryption on a real connection",
    "cleartext": "Sends unencrypted data",
    "cleartext_more": "More unencrypted protocols",
    "port_scan": "Scanned other devices",
    "arp_spoof": "Impersonated another device",
    "arp_victim": "Was impersonated by another device",
    "bandwidth_hog": "Unusually heavy data use",
}

LIMITS = [
    "Grades only what a passive observer on the hotspot can see; it is not a vulnerability scan.",
    "Cannot see inside encrypted traffic, so a modern-TLS device can still be compromised.",
    "Devices seen for only a short time may be graded on very little evidence.",
    "A grade describes this observation session, not the device's permanent state.",
]


def grade_for(score: float) -> str:
    for floor, letter in GRADE_BANDS:
        if score >= floor:
            return letter
    return "F"


def _item(key: str, detail: str, points: Optional[int] = None) -> dict:
    return {"key": key, "points": DEDUCTIONS[key][0] if points is None else points,
            "title": TITLES[key], "detail": detail, "advice": ADVICE.get(key, "")}


def assess_device(
    *, ip: str, mac: str, vendor: str, randomized_mac: bool, packets: int, bytes_total: int,
    findings: List[dict], tls_rows: List[dict], alerts: List[dict], posture_bytes: Dict[str, int],
    is_self: bool = False,
) -> dict:
    base = {"ip": ip, "mac": mac, "vendor": vendor, "randomized_mac": randomized_mac,
            "packets": packets, "bytes": bytes_total}
    if is_self:
        return {**base, "assessed": False, "score": None, "grade": "-", "status": "monitoring laptop",
                "deductions": [], "good": [], "note": "This is the machine running NetLens, so it is not graded."}
    if packets < MIN_PACKETS:
        return {**base, "assessed": False, "score": None, "grade": "?", "status": "not enough data",
                "deductions": [], "good": [], "note": f"Only {packets} packets seen so far - too little to judge fairly."}

    deductions: List[dict] = []

    grades = [r["grade"] for r in tls_rows]
    legacy = [r for r in tls_rows if r["grade"] == "F"]
    broken_offer = [r for r in tls_rows if r["grade"] == "C"]
    if legacy:
        sites = ", ".join(sorted({r["sni"] or r["server"] for r in legacy})[:3])
        deductions.append(_item("weak_tls_client", f"Offered {legacy[0]['offered_version']} to {sites}."))
    elif broken_offer:
        sites = ", ".join(sorted({r["sni"] or r["server"] for r in broken_offer})[:3])
        deductions.append(_item("weak_tls_ciphers", f"Offered broken cipher suites to {sites}."))
    negotiated = [f for f in findings if f["title"].startswith("Server negotiated")]
    if negotiated:
        deductions.append(_item("weak_tls_negotiated", negotiated[0]["title"] + "."))

    clear = [f for f in findings if f["title"].startswith("Unencrypted")]
    if clear:
        kinds = sorted({f["title"].replace("Unencrypted ", "").replace(" traffic", "") for f in clear})
        deductions.append(_item("cleartext", f"Sent {', '.join(kinds)} without encryption."))
        extra = min(10, 5 * (len(kinds) - 1))
        if extra:
            deductions.append(_item("cleartext_more", f"{len(kinds)} unencrypted protocols seen.", points=extra))

    scans = [a for a in alerts if a["rule"] == "port_scan" and a["host"] == ip]
    if scans:
        deductions.append(_item("port_scan", f"Tried {scans[0]['evidence'].get('distinct_ports', '?')} ports in one window."))
    hogs = [a for a in alerts if a["rule"] == "bandwidth_hog" and a["host"] == ip]
    if hogs:
        deductions.append(_item("bandwidth_hog", f"{len(hogs)} heavy-use alert(s).", points=min(20, 10 * len(hogs))))
    for a in alerts:
        if a["rule"] != "arp_spoof":
            continue
        ev = a.get("evidence", {})
        if mac and ev.get("new_mac", "").lower() == mac.lower():
            deductions.append(_item("arp_spoof", f"Claimed {ev.get('ip')}, which belongs to another device."))
            break
    if any(a["rule"] == "arp_spoof" and a["host"] == ip for a in alerts):
        deductions.append(_item("arp_victim", "Another device claimed this device's address."))

    lost = min(100, sum(d["points"] for d in deductions))
    score = 100 - lost

    good: List[str] = []
    if tls_rows and not legacy and not broken_offer:
        modern = "TLS 1.3" if all(r["grade"] == "A" for r in tls_rows) else "TLS 1.2 or newer"
        good.append(f"Every secure connection used {modern} with strong ciphers.")
    if not clear:
        good.append("No unencrypted application traffic was seen.")
    if not scans and not hogs and not any(d["key"] in ("arp_spoof", "arp_victim") for d in deductions):
        good.append("No suspicious behaviour was flagged.")
    if randomized_mac:
        good.append("Uses a private (randomised) hardware address, which makes it harder to track.")

    grade = grade_for(score)
    status = {"A": "Healthy", "B": "Good", "C": "Needs attention", "D": "At risk", "F": "Poor"}[grade]
    return {**base, "assessed": True, "score": score, "grade": grade, "status": status,
            "deductions": deductions, "good": good, "tls_handshakes": len(tls_rows),
            "worst_tls_grade": max(grades) if grades else None, "note": ""}


def summarise(devices: List[dict]) -> dict:
    graded = [d for d in devices if d["assessed"]]
    if not graded:
        return {"score": None, "grade": "?", "summary": "No device has been observed long enough to grade yet.",
                "assessed": 0, "weakest": None}
    avg = round(sum(d["score"] for d in graded) / len(graded))
    weakest = min(graded, key=lambda d: d["score"])
    n_issue = sum(1 for d in graded if d["grade"] in ("C", "D", "F"))
    summary = (f"{len(graded)} device(s) graded; {n_issue} need attention." if n_issue
               else f"All {len(graded)} graded device(s) look healthy.")
    return {"score": avg, "grade": grade_for(avg), "summary": summary, "assessed": len(graded),
            "weakest": {"ip": weakest["ip"], "grade": weakest["grade"], "score": weakest["score"]}}


def methodology() -> List[dict]:
    return [{"key": k, "points": v[0], "rule": v[1]} for k, v in DEDUCTIONS.items()]
