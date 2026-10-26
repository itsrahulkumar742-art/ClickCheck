"""
ClickCheck - Digital Safety Toolkit
-----------------------------------
IBM SkillsBuild National Cybersecurity Bootcamp (Oct 2026)
Organised by BharatCares (CSRBOX Group)

Student : Rahul
College : Guru Nanak Dev University College, Jalandhar
Course  : BCA 3rd Year

This script is only for learning. It does not attack any website.
It only looks at the text of a URL / message / file that YOU paste.
Do not use it to scan systems you do not own.
"""

from __future__ import print_function

import hashlib
import json
import os
import re
import string
import sys
from datetime import datetime
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
#  lists I collected while watching the masterclasses and from news examples
# ---------------------------------------------------------------------------

COMMON_PASSWORDS = {
    "123456", "12345678", "123456789", "1234567890", "password", "password1",
    "qwerty", "qwerty123", "admin", "admin123", "welcome", "iloveyou",
    "abc123", "abcd1234", "india123", "rahul123", "passw0rd", "111111",
    "000000", "1q2w3e4r", "zaq12wsx", "letmein", "monkey", "dragon",
}

# shorteners hide the real site, that was shown in Masterclass 2
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "cutt.ly", "rb.gy", "tiny.cc", "shorturl.at", "bl.ink", "rebrand.ly",
}

# cheap / abused TLDs. not always bad, just a warning
SUSPICIOUS_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq", "top", "zip", "mov", "click",
    "link", "work", "rest", "fit", "buzz", "country", "icu", "cam",
    "cfd", "sbs", "cyou", "monster",
}

# brands people in India get fake SMS about
BRAND_WORDS = {
    "sbi", "hdfc", "icici", "axis", "pnb", "canara", "bob", "unionbank",
    "paytm", "phonepe", "gpay", "bhim", "googlepay", "bharatpe",
    "amazon", "flipkart", "myntra", "meesho", "snapdeal",
    "irctc", "uidai", "aadhaar", "aadhar", "incometax", "gst", "epfo",
    "airtel", "jio", "vodafone", "bsnl", "pspcl", "pspclpunjab",
    "whatsapp", "instagram", "facebook", "microsoft", "google", "apple",
    "netflix", "hotstar", "upi", "npci", "kyc",
}

# if the domain is one of these, it is probably the real site
LEGIT_DOMAINS = {
    "sbi.co.in", "onlinesbi.sbi", "bank.sbi", "sbi.bank.in",
    "hdfcbank.com", "icicibank.com", "axisbank.com", "pnbindia.in",
    "paytm.com", "phonepe.com", "google.com", "google.co.in",
    "amazon.in", "amazon.com", "flipkart.com", "irctc.co.in",
    "uidai.gov.in", "incometax.gov.in", "incometaxindia.gov.in",
    "gst.gov.in", "epfindia.gov.in", "npci.org.in", "upi.org.in",
    "microsoft.com", "apple.com", "whatsapp.com", "instagram.com",
    "facebook.com", "airtel.in", "jio.com", "pspcl.in",
    "onlineservices.gst.gov.in", "gndu.ac.in", "gnducjal.org",
}

HOMOGLYPH = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s",
}

URGENCY_WORDS = [
    "immediately", "urgent", "hurry", "last chance", "act now",
    "within 24 hours", "within 24 hrs", "today only", "expire",
    "expires tonight", "limited time", "do it now", "asap",
    "final warning", "last warning", "account will be blocked",
    "will be closed", "will be suspended", "will be disconnected",
    "legal action", "police case", "arrest warrant",
]

THREAT_WORDS = [
    "blocked", "suspended", "disconnected", "cut your electricity",
    "power cut", "gas subsidy", "legal action", "fir will be",
    "cyber cell", "ed freeze", "account freeze", "kyc pending",
    "kyc not updated", "pan linked", "aadhaar not linked",
]

PRIZE_WORDS = [
    "you have won", "lucky winner", "lottery", "jackpot", "scratch card",
    "free iphone", "free laptop", "cashback of", "rs 50,000", "rs 50000",
    "reward points", "gift voucher", "congratulations you",
]

SENSITIVE_ASK = [
    "share otp", "send otp", "tell otp", "otp is", "cvv", "pin number",
    "atm pin", "net banking password", "internet banking",
    "aadhaar number", "aadhar number", "pan number", "ifsc",
    "full card number", "cvv code", "upi pin",
]

UPI_ASK = [
    "send money", "transfer rs", "pay rs", "collect request",
    "paytm number", "scan qr", "scan this qr", "upi id",
    "add money", "send rs", "pay to this number",
]

CLICK_WORDS = [
    "click here", "click the link", "open this link", "tap on",
    "verify now", "update now", "confirm here", "login here",
    "download apk", "download the app",
]

FEE_WORDS = [
    "processing fee", "registration fee", "gst charges", "advance fee",
    "token amount", "small fee", "pay rs 499", "pay rs 99", "pay rs 1",
    "extra charges", "extra charge",
]

COURIER_WORDS = [
    "warehouse", "held at", "package pending", "shipment held",
    "customs fee", "delivery failed", "undelivered item",
]


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _normal(text):
    if text is None:
        return ""
    return str(text).strip()


def _lower(text):
    return _normal(text).lower()


def risk_level(score):
    # I first used 50 as high but too many messages became HIGH
    # so I moved the cut off a bit after testing
    if score >= 45:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def _add(findings, code, detail, points, advice):
    findings.append({
        "code": code,
        "detail": detail,
        "points": points,
        "advice": advice,
    })
    return points


# ---------------------------------------------------------------------------
#  Module 1 - password / digital hygiene   (Masterclass 1)
# ---------------------------------------------------------------------------

def check_password(password):
    """Very basic password advice. This is NOT a password cracker."""
    pwd = _normal(password)
    findings = []
    score = 0  # here higher is better (opposite of phishing score)

    if len(pwd) == 0:
        return {
            "type": "password",
            "score": 0,
            "level": "WEAK",
            "findings": [{"code": "EMPTY", "detail": "No password given", "points": 0,
                          "advice": "Use a long passphrase."}],
            "summary": "Empty password.",
        }

    if len(pwd) >= 12:
        score += 25
        _add(findings, "LENGTH_OK", "Length is %d (12+ is good)" % len(pwd), 25,
             "Keep using a long password or passphrase.")
    elif len(pwd) >= 8:
        score += 12
        _add(findings, "LENGTH_SHORT", "Length is %d. 12+ is safer" % len(pwd), 12,
             "Add a few more words. Example: GreenTea-Jalandhar-2019")
    else:
        _add(findings, "LENGTH_BAD", "Only %d characters" % len(pwd), 0,
             "Too short. Use at least 12 characters.")

    has_u = any(c.isupper() for c in pwd)
    has_l = any(c.islower() for c in pwd)
    has_d = any(c.isdigit() for c in pwd)
    has_s = any(c in string.punctuation for c in pwd)
    mix = sum([has_u, has_l, has_d, has_s])
    score += mix * 8
    _add(findings, "CHARSET", "Character types used: %d/4" % mix, mix * 8,
         "Mix upper, lower, number and a symbol.")

    if _lower(pwd) in COMMON_PASSWORDS or pwd in COMMON_PASSWORDS:
        score = max(0, score - 40)
        _add(findings, "COMMON", "This is a very common password", -40,
             "Never use passwords that are in leak lists.")

    # simple sequence like 1234 or abcd
    seq = "0123456789abcdefghijklmnopqrstuvwxyz"
    low = _lower(pwd)
    for i in range(len(seq) - 3):
        if seq[i:i+4] in low:
            score = max(0, score - 10)
            _add(findings, "SEQUENCE", "Has a simple sequence like 1234/abcd", -10,
                 "Avoid running numbers or letters.")
            break

    if re.search(r"(.)\1\1", pwd):
        score = max(0, score - 8)
        _add(findings, "REPEAT", "Same character repeated 3 times", -8,
             "Repeating characters makes guessing easier.")

    if score >= 45:
        level = "STRONG"
    elif score >= 25:
        level = "FAIR"
    else:
        level = "WEAK"

    summary = "Password looks %s (hygiene score %d/57)." % (level, score)
    return {
        "type": "password",
        "score": score,
        "level": level,
        "findings": findings,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
#  Module 2 - URL check   (Masterclass 2)
# ---------------------------------------------------------------------------

def _fix_url(url):
    url = _normal(url)
    if not url:
        return url
    # urllib.parse is weird if scheme is missing, I got stuck on this
    if "://" not in url:
        url = "http://" + url
    return url


def _host_is_ip(host):
    host = host.strip("[]")
    parts = host.split(".")
    if len(parts) == 4:
        ok = True
        for p in parts:
            if not p.isdigit() or int(p) > 255:
                ok = False
                break
        if ok:
            return True
    # very rough IPv6
    if ":" in host and all(c in "0123456789abcdef:" for c in host.lower()):
        return True
    return False


def _looks_like_brand(host):
    """check if a brand name is sitting inside a shady host"""
    h = host.lower()
    # remove dots for matching pay-tm style
    compact = h.replace("-", "").replace(".", "")
    hits = []
    for b in BRAND_WORDS:
        if b in h.split(".")[0] or b in compact:
            # skip if it is actually the legit domain
            hits.append(b)
    return hits


def _is_legit_host(host):
    h = host.lower().rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    for d in LEGIT_DOMAINS:
        if h == d or h.endswith("." + d):
            return True
    return False


def _homoglyph_host(host):
    # replace digits that people use to fake names (paytm -> payt1n etc)
    h = host.lower()
    out = []
    for ch in h:
        out.append(HOMOGLYPH.get(ch, ch))
    return "".join(out)


def analyse_url(url):
    raw = _normal(url)
    findings = []
    score = 0

    if not raw:
        return {
            "type": "url",
            "input": raw,
            "score": 0,
            "level": "LOW",
            "findings": [],
            "cia": [],
            "kill_chain": [],
            "summary": "No URL given.",
        }

    fixed = _fix_url(raw)
    p = urlparse(fixed)
    host = (p.hostname or "").lower()
    path = (p.path or "") + ("?" + p.query if p.query else "")
    scheme = (p.scheme or "").lower()

    if not host:
        score += _add(findings, "BAD_URL", "Could not read a hostname from this text", 15,
                      "The link looks broken. Do not open it.")
        return _pack_url(raw, score, findings)

    if scheme in ("javascript", "data"):
        score += _add(findings, "BAD_SCHEME", "Scheme is %s (can run code in a page)" % scheme, 40,
                      "Never click javascript: or data: links from SMS.")

    if scheme == "http":
        score += _add(findings, "NO_HTTPS", "Uses http, not https", 10,
                      "Real banks in India use https. Check the lock icon.")

    if _host_is_ip(host):
        score += _add(findings, "IP_HOST", "Website address is a raw IP: %s" % host, 25,
                      "Banks do not ask you to open an IP address.")

    if "@" in raw.split("://")[-1].split("/")[0]:
        # user:pass@host trick, or decoy@real.evil.com
        score += _add(findings, "AT_TRICK", "Link contains @ which can hide the real site", 30,
                      "The browser goes to the part AFTER @. Ignore the name before it.")

    if host.endswith(".onion"):
        score += _add(findings, "ONION", "Tor onion address", 20,
                      "Normal banking SMS will not send .onion links.")

    if "xn--" in host:
        score += _add(findings, "PUNYCODE", "International / punycode domain (xn--)", 25,
                      "This can hide look-alike letters. Type the site yourself.")

    labels = host.split(".")
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        score += _add(findings, "ODD_TLD", "Unusual domain ending .%s" % tld, 15,
                      "Govt and banks mostly use .in / .com / .gov.in")

    if host in SHORTENERS or any(host.endswith("." + s) or host == s for s in SHORTENERS):
        score += _add(findings, "SHORTENER", "URL shortener: %s" % host, 15,
                      "Short links hide the real website. Don't login through them.")

    if host.count("-") >= 2:
        score += _add(findings, "MANY_HYPHENS", "Domain has many hyphens: %s" % host, 8,
                      "Fake sites like sbi-kyc-update.in are very common.")

    if len(labels) >= 5:
        score += _add(findings, "DEEP_SUB", "Too many subdomains (%d parts)" % len(labels), 10,
                      "Extra words before the real name are often a trick.")

    if not _is_legit_host(host):
        brands = _looks_like_brand(host)
        # also check homoglyph version
        fake_norm = _homoglyph_host(host)
        extra = _looks_like_brand(fake_norm)
        for b in extra:
            if b not in brands:
                brands.append(b)
        if brands:
            score += _add(
                findings, "BRAND_LOOKALIKE",
                "Looks like it is copying: %s (host is %s)" % (", ".join(brands), host),
                30,
                "Open the official app / type the real website yourself. Do not use this link.",
            )

    # digits mixed into the first label (payt1m, sbi1ndia)
    first = labels[0]
    if re.search(r"[a-z].*\d|\d.*[a-z]", first) and _looks_like_brand(first):
        score += _add(findings, "DIGIT_SWAP", "Numbers mixed in the name: %s" % first, 12,
                      "Real brand names do not put random digits in the domain.")

    low_path = path.lower()
    bait = ["kyc", "verify", "update", "login", "secure", "account", "unlock",
            "refund", "prize", "gift", "otp", "aadhaar", "aadhar", "pan"]
    bait_hit = [w for w in bait if w in low_path]
    if bait_hit and not _is_legit_host(host):
        score += _add(findings, "BAIT_PATH", "Path talks about: %s" % ", ".join(bait_hit), 12,
                      "KYC/login pages on a wrong domain are a classic phishing move.")

    if re.search(r"\.(apk|exe|scr|bat|cmd|js)(\?|$)", low_path):
        score += _add(findings, "BAD_FILE", "Link points to an executable / apk", 22,
                      "Do not install apps from SMS links. Use Play Store only.")

    # very long url
    if len(raw) > 120:
        score += _add(findings, "LONG_URL", "URL is very long (%d chars)" % len(raw), 6,
                      "Long messy links are harder to read on purpose.")

    return _pack_url(raw, score, findings)


def _pack_url(raw, score, findings):
    cia, chain = map_cia_and_chain(findings, kind="url")
    level = risk_level(score)
    if not findings:
        summary = "No obvious phishing signs in the URL text. Still, open only if you trust the sender."
    else:
        summary = "URL risk %s (%d points). %d warning(s) found." % (level, score, len(findings))
    return {
        "type": "url",
        "input": raw,
        "score": score,
        "level": level,
        "findings": findings,
        "cia": cia,
        "kill_chain": chain,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
#  Module 2b - SMS / WhatsApp / email text   (Masterclass 2)
# ---------------------------------------------------------------------------

def analyse_message(text):
    raw = _normal(text)
    msg = _lower(raw)
    findings = []
    score = 0

    if not raw:
        return {
            "type": "message",
            "input": raw,
            "score": 0,
            "level": "LOW",
            "findings": [],
            "cia": [],
            "kill_chain": [],
            "summary": "No message given.",
        }

    def hit(words, code, detail, points, advice, once=True):
        nonlocal score
        found = []
        for w in words:
            if w in msg:
                found.append(w)
        if found:
            shown = ", ".join(found[:4])
            score += _add(findings, code, detail + " [" + shown + "]", points, advice)
            return True
        return False

    hit(URGENCY_WORDS, "URGENCY", "Tries to create panic / hurry", 15,
        "Scammers do not give you time to think. Pause and call the company on the number from their official site.")

    hit(THREAT_WORDS, "THREAT", "Uses fear (block, cut, legal, KYC)", 18,
        "Banks / PSPCL / IT dept do not threaten over random SMS. Ignore and verify in the official app.")

    hit(PRIZE_WORDS, "PRIZE", "Prize / lottery / free gift language", 15,
        "If you did not enter a contest, you did not win. Never pay a 'processing fee'.")

    hit(SENSITIVE_ASK, "SENSITIVE", "Asks for OTP / PIN / Aadhaar / PAN / CVV", 25,
        "NO bank, NO college, NO courier asks for OTP on a call or SMS. OTP is only for you.")

    hit(UPI_ASK, "UPI_MONEY", "Talks about sending money / QR / collect request", 18,
        "A collect request is THEM asking YOU to pay. Decline it. Never scan unknown QR.")

    hit(CLICK_WORDS, "CLICK", "Pushes you to click / verify / download", 10,
        "Type the website yourself or use the official app. Don't tap the SMS link.")

    hit(FEE_WORDS, "FEE_TRAP", "Asks for a processing / registration fee", 12,
        "Paying a fee to get a prize or a job is a standard scam. Stop there.")

    hit(COURIER_WORDS, "COURIER", "Fake courier / warehouse / customs story", 12,
        "Amazon and Flipkart never ask extra fees on WhatsApp or SMS. Check the official app orders page.")

    if "dear customer" in msg or "dear user" in msg or "valued customer" in msg:
        score += _add(findings, "GENERIC", "Starts with Dear Customer / Dear User (no name)", 8,
                      "Real messages from your bank usually show last 4 digits or your name.")

    if "whatsapp" in msg and ("only" in msg or "this number" in msg):
        score += _add(findings, "WHATSAPP_ONLY", "Asks to talk only on WhatsApp", 10,
                      "Official offices do not move a KYC case to a random WhatsApp number.")

    if "work from home" in msg or "part time job" in msg or "data entry job" in msg:
        score += _add(findings, "JOB_SCAM", "Job / WFH offer in a random message", 12,
                      "Fake job scams ask for registration fees. Real HRs don't ask that.")

    if "do not share this" in msg or "dont share this" in msg or "don't share this" in msg:
        score += _add(findings, "SECRECY", "Tells you to keep the message secret", 8,
                      "A real bank will never say 'don't tell anyone'. That is social engineering.")

    # extract urls from the message and scan them too
    url_pat = re.compile(r"(https?://[^\s]+|www\.[^\s]+|[a-z0-9.-]+\.(?:xyz|tk|top|click|in|com|link|icu)/[^\s]+)", re.I)
    urls = url_pat.findall(raw)
    for u in urls[:3]:
        ures = analyse_url(u.rstrip(").,]>"))
        if ures["score"] >= 20:
            score += _add(findings, "BAD_LINK_IN_MSG",
                          "Message contains a risky link: %s (%s)" % (u, ures["level"]),
                          min(20, ures["score"] // 2),
                          "The link inside the SMS is the actual trap.")

    # ALL CAPS shouting
    letters = [c for c in raw if c.isalpha()]
    if len(letters) >= 20:
        caps = sum(1 for c in letters if c.isupper())
        if caps / float(len(letters)) > 0.7:
            score += _add(findings, "ALL_CAPS", "Most of the message is in CAPITAL letters", 6,
                          "Shouting is used to create pressure.")

    cia, chain = map_cia_and_chain(findings, kind="message")
    level = risk_level(score)
    if not findings:
        summary = "No strong scam pattern in this text. Still be careful with any link or OTP."
    else:
        summary = "Message risk %s (%d points). %d warning(s)." % (level, score, len(findings))
    return {
        "type": "message",
        "input": raw,
        "score": score,
        "level": level,
        "findings": findings,
        "cia": cia,
        "kill_chain": chain,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
#  Module 3 - CIA triad + simple kill chain   (Masterclass 3)
# ---------------------------------------------------------------------------

def map_cia_and_chain(findings, kind="url"):
    codes = set(f["code"] for f in findings)
    cia = []
    chain = []

    conf_codes = {"SENSITIVE", "UPI_MONEY", "BRAND_LOOKALIKE", "AT_TRICK", "BAD_SCHEME", "BAIT_PATH"}
    integ_codes = {"BAD_FILE", "PUNYCODE", "DIGIT_SWAP"}
    avail_codes = {"THREAT"}

    if codes & conf_codes:
        cia.append("Confidentiality (they want your login / OTP / money)")
    if codes & integ_codes:
        cia.append("Integrity (file or website may not be what it claims)")
    if codes & avail_codes:
        cia.append("Availability (they threaten to cut service / lock account)")
    if not cia and findings:
        cia.append("Confidentiality (phishing usually aims at your data or money)")

    # very simple mapping of cyber kill chain stages
    if codes & {"BRAND_LOOKALIKE", "PUNYCODE", "DIGIT_SWAP", "ODD_TLD"}:
        chain.append("Weaponization (fake domain is prepared)")
    if kind == "message" or codes & {"CLICK", "SHORTENER", "BAD_LINK_IN_MSG", "URGENCY"}:
        chain.append("Delivery (SMS / WhatsApp / email)")
    if codes & {"CLICK", "BAIT_PATH", "AT_TRICK", "NO_HTTPS", "IP_HOST"}:
        chain.append("Exploitation (you are pushed to open / login)")
    if codes & {"BAD_FILE"}:
        chain.append("Installation (apk / exe on the phone)")
    if codes & {"SENSITIVE", "UPI_MONEY", "PRIZE"}:
        chain.append("Actions on Objectives (OTP, money, KYC data)")

    # unique preserve order
    seen = set()
    cia2 = []
    for x in cia:
        if x not in seen:
            cia2.append(x)
            seen.add(x)
    seen = set()
    chain2 = []
    for x in chain:
        if x not in seen:
            chain2.append(x)
            seen.add(x)
    return cia2, chain2


# ---------------------------------------------------------------------------
#  Module 4 - tiny forensics / hash check   (Masterclass 4)
# ---------------------------------------------------------------------------

def sha256_of_bytes(data):
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def sha256_of_file(path):
    path = _normal(path)
    if not os.path.isfile(path):
        return {"ok": False, "error": "File not found: %s" % path}
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            size += len(chunk)
            h.update(chunk)
    return {
        "ok": True,
        "path": os.path.abspath(path),
        "size": size,
        "sha256": h.hexdigest(),
        "name": os.path.basename(path),
    }


def evidence_demo(folder="."):
    """
    Makes a small fake 'evidence' file, hashes it, changes one byte,
    hashes again. This is the same idea as chain of custody in class.
    """
    folder = folder or "."
    if not os.path.isdir(folder):
        os.makedirs(folder)
    path = os.path.join(folder, "sample_evidence.txt")
    original = (
        "PSPCL bill copy (DEMO - not a real bill)\n"
        "Account: ********4312\n"
        "Name: R. Kumar, Jalandhar\n"
        "Amount: Rs 0 (this file is only for hash demo)\n"
        "Note: created by ClickCheck for IBM SkillsBuild project\n"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(original)

    before = sha256_of_file(path)

    # tamper
    with open(path, "a", encoding="utf-8") as f:
        f.write("TAMPER: amount changed to Rs 90000\n")

    after = sha256_of_file(path)

    same = before["sha256"] == after["sha256"]
    return {
        "type": "forensics",
        "file": path,
        "hash_before": before["sha256"],
        "hash_after": after["sha256"],
        "size_before": before["size"],
        "size_after": after["size"],
        "match": same,
        "summary": (
            "Hashes MATCH. File was not changed."
            if same else
            "Hashes DO NOT match. Even a small edit changes SHA-256. This is how we notice tampering."
        ),
    }


# ---------------------------------------------------------------------------
#  incident report
# ---------------------------------------------------------------------------

def make_incident(url_result=None, msg_result=None, extra_note=""):
    rec = {
        "tool": "ClickCheck",
        "student": "Rahul, GNDU College Jalandhar, BCA 3rd Year",
        "program": "IBM SkillsBuild National Cybersecurity Bootcamp, Oct 2026",
        "created_at": _now(),
        "note": extra_note,
        "url": url_result,
        "message": msg_result,
    }
    # overall
    scores = []
    levels = []
    if url_result:
        scores.append(url_result.get("score", 0))
        levels.append(url_result.get("level"))
    if msg_result:
        scores.append(msg_result.get("score", 0))
        levels.append(msg_result.get("level"))
    overall = max(scores) if scores else 0
    if "HIGH" in levels:
        ol = "HIGH"
    elif "MEDIUM" in levels:
        ol = "MEDIUM"
    else:
        ol = "LOW"
    rec["overall_score"] = overall
    rec["overall_level"] = ol
    rec["recommendation"] = _recommend(ol)
    return rec


def _recommend(level):
    if level == "HIGH":
        return (
            "Do not click, do not share OTP, do not scan any QR. "
            "Report the SMS as spam. If money already left, call your bank helpline "
            "from the number on the back of the card and also report on cybercrime.gov.in"
        )
    if level == "MEDIUM":
        return (
            "Treat this as suspicious. Open the official app yourself. "
            "Do not use the link from the message."
        )
    return "No strong red flag, but still don't share OTP or passwords with anyone."


def save_report(incident, folder="."):
    if not os.path.isdir(folder):
        os.makedirs(folder)
    txt_path = os.path.join(folder, "clickcheck_report.txt")
    json_path = os.path.join(folder, "clickcheck_report.json")

    lines = []
    lines.append("ClickCheck - Incident Note")
    lines.append("Generated: %s" % incident["created_at"])
    lines.append("Student  : %s" % incident["student"])
    lines.append("Program  : %s" % incident["program"])
    lines.append("-" * 60)
    lines.append("Overall  : %s  (score %s)" % (incident["overall_level"], incident["overall_score"]))
    lines.append("Advice   : %s" % incident["recommendation"])
    lines.append("-" * 60)

    def dump_block(title, res):
        if not res:
            return
        lines.append("")
        lines.append(title)
        lines.append("  Input : %s" % (res.get("input", "")[:200]))
        lines.append("  Level : %s (%s pts)" % (res.get("level"), res.get("score")))
        lines.append("  %s" % res.get("summary"))
        for f in res.get("findings", []):
            lines.append("    - [%s] +%s  %s" % (f["code"], f["points"], f["detail"]))
            lines.append("      advice: %s" % f["advice"])
        if res.get("cia"):
            lines.append("  CIA   : " + " | ".join(res["cia"]))
        if res.get("kill_chain"):
            lines.append("  Chain : " + " -> ".join(res["kill_chain"]))

    dump_block("[URL]", incident.get("url"))
    dump_block("[MESSAGE]", incident.get("message"))
    if incident.get("note"):
        lines.append("")
        lines.append("Note: " + incident["note"])
    lines.append("")
    lines.append("This is an educational check, not a police report.")

    text = "\n".join(lines)
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(text)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(incident, f, indent=2, ensure_ascii=False)
    return txt_path, json_path, text


# ---------------------------------------------------------------------------
#  pretty print
# ---------------------------------------------------------------------------

def print_result(res):
    print("")
    print("=" * 64)
    print(" Type : %s" % res.get("type"))
    if res.get("input"):
        shown = res["input"]
        if len(shown) > 90:
            shown = shown[:90] + "..."
        print(" Input: %s" % shown)
    print(" Level: %s   Score: %s" % (res.get("level"), res.get("score")))
    print(" %s" % res.get("summary"))
    print("-" * 64)
    if not res.get("findings"):
        print("  (no extra findings)")
    for f in res.get("findings", []):
        sign = f["points"]
        print("  [%s]  %+d  %s" % (f["code"], sign, f["detail"]))
        print("           -> %s" % f["advice"])
    if res.get("cia"):
        print(" CIA :")
        for c in res["cia"]:
            print("    * %s" % c)
    if res.get("kill_chain"):
        print(" Kill chain : %s" % "  ->  ".join(res["kill_chain"]))
    print("=" * 64)


# ---------------------------------------------------------------------------
#  demo cases (made up - I did not open any live phishing site)
# ---------------------------------------------------------------------------

DEMO_URLS = [
    "https://onlinesbi.sbi",  # should be low
    "http://sbi-kyc-update.xyz/login/verify",
    "http://192.168.5.21/hdfc/secure",
    "https://paytm-refund.top/claim",
    "https://bit.ly/3fakelink",
    "https://incometax.gov.in",
    "http://pspcl-bill-pay.click/kyc",
    "https://amazon.in.account-hold.icu/package",
]

DEMO_MSGS = [
    # 1. PSPCL style (Punjab electricity) - I actually get these kind of SMS
    "Dear Customer, your PSPCL electricity connection will be DISCONNECTED in 24 hours. "
    "Update KYC immediately: http://pspcl-kyc-update.xyz/verify",

    # 2. Fake SBI
    "SBI: Your account will be blocked today. Click here to complete KYC "
    "https://sbi-secure-kyc.top/login and share OTP with us.",

    # 3. Prize
    "CONGRATULATIONS you have won a free iPhone 16. Pay Rs 499 processing fee on UPI "
    "and send screenshot. Do not share this with anyone.",

    # 4. UPI collect
    "Your Amazon order is held at Jalandhar warehouse. Pay Rs 37 extra charges. "
    "Scan this QR / send money to 9876543210. Collect request sent.",

    # 5. fairly normal
    "Hi Rahul, class is at 10 am tomorrow in room 12. Please bring the practical file.",

    # 6. job scam
    "Part time data entry job, work from home, 15000 per week. Pay 999 registration "
    "on this UPI id then we will add you on WhatsApp only.",
]


def run_demo(save_folder="output"):
    print("\n>>> URL demo")
    url_results = []
    for u in DEMO_URLS:
        r = analyse_url(u)
        url_results.append(r)
        print_result(r)

    print("\n>>> Message demo")
    msg_results = []
    for m in DEMO_MSGS:
        r = analyse_message(m)
        msg_results.append(r)
        print_result(r)

    print("\n>>> Password demo")
    for pw in ["123456", "Rahul@2024", "GreenTea-Jalandhar-Rain-2019!"]:
        r = check_password(pw)
        print_result(r)

    print("\n>>> Forensics demo")
    ev = evidence_demo(save_folder)
    print(" File :", ev["file"])
    print(" SHA256 before:", ev["hash_before"])
    print(" SHA256 after :", ev["hash_after"])
    print(" ", ev["summary"])

    # one combined incident (the PSPCL one)
    inc = make_incident(
        url_result=analyse_url("http://pspcl-kyc-update.xyz/verify"),
        msg_result=msg_results[0],
        extra_note="Demo case: fake PSPCL KYC SMS (common in Punjab). Not a real incident.",
    )
    txt, js, _ = save_report(inc, save_folder)
    print("\nSaved:", txt)
    print("Saved:", js)
    return url_results, msg_results, ev, inc


# ---------------------------------------------------------------------------
#  tests  (so I can show it actually works)
# ---------------------------------------------------------------------------

def run_tests():
    tests = []

    def t(name, cond):
        tests.append((name, bool(cond)))

    r = analyse_url("https://onlinesbi.sbi")
    t("real SBI is not HIGH", r["level"] != "HIGH")

    r = analyse_url("http://sbi-kyc-update.xyz/login")
    t("fake SBI xyz is HIGH or MEDIUM", r["score"] >= 20)

    r = analyse_url("http://192.168.5.21/hdfc/secure")
    t("IP host gets IP_HOST", any(f["code"] == "IP_HOST" for f in r["findings"]))

    r = analyse_url("https://bit.ly/abc")
    t("shortener flagged", any(f["code"] == "SHORTENER" for f in r["findings"]))

    r = analyse_url("https://paytm-refund.top/claim")
    t("lookalike brand flagged", any(f["code"] == "BRAND_LOOKALIKE" for f in r["findings"]))

    r = analyse_url("https://example.com")
    t("plain example.com stays LOW", r["level"] == "LOW")

    r = analyse_message("Hi, class at 10 am, bring practical file")
    t("normal college msg is LOW", r["level"] == "LOW")

    r = analyse_message("Share OTP to verify your SBI KYC otherwise account blocked. Click here")
    t("OTP + KYC is HIGH", r["level"] == "HIGH")

    r = analyse_message("you have won a free iPhone, pay processing fee")
    t("prize scam at least MEDIUM", r["score"] >= 20)

    r = analyse_message("Dear Customer update PSPCL KYC immediately http://pspcl-kyc-update.xyz/verify")
    t("PSPCL fake is HIGH or MEDIUM", r["score"] >= 20)

    r = check_password("123456")
    t("123456 is WEAK", r["level"] == "WEAK")

    r = check_password("GreenTea-Jalandhar-Rain-2019!")
    t("long passphrase not WEAK", r["level"] != "WEAK")

    ev = evidence_demo(".")
    t("tamper changes hash", ev["match"] is False)
    t("hash is 64 hex chars", len(ev["hash_before"]) == 64)

    r = analyse_url("https://login.microsoft.com@evil-site.xyz/kyc")
    t("@ trick flagged", any(f["code"] == "AT_TRICK" for f in r["findings"]))

    r = analyse_message("Pay Rs 37 extra. Scan this QR. Collect request sent to your UPI")
    t("UPI collect flagged", any(f["code"] == "UPI_MONEY" for f in r["findings"]))

    passed = sum(1 for _, ok in tests if ok)
    print("\n--- tests ---")
    for name, ok in tests:
        print(("PASS" if ok else "FAIL"), "-", name)
    print("Result: %d/%d passed" % (passed, len(tests)))
    return passed, len(tests), tests


# ---------------------------------------------------------------------------
#  menu
# ---------------------------------------------------------------------------

def _read(prompt):
    try:
        return input(prompt)
    except EOFError:
        return ""


def menu():
    print("")
    print("ClickCheck  |  IBM SkillsBuild Cybersecurity Bootcamp 2026")
    print("Rahul  |  GNDU College, Jalandhar  |  BCA 3rd Year")
    print("This tool only reads text you paste. It does not hack anything.")
    while True:
        print("")
        print("  1. Check a URL")
        print("  2. Check a message (SMS / WhatsApp / email)")
        print("  3. Password hygiene")
        print("  4. File SHA-256")
        print("  5. Run demo + save report")
        print("  6. Run tests")
        print("  7. Exit")
        ch = _read("Choose 1-7: ").strip()
        if ch == "1":
            u = _read("Paste URL: ")
            print_result(analyse_url(u))
        elif ch == "2":
            print("Paste message. End with an empty line:")
            buf = []
            while True:
                line = _read("")
                if line == "":
                    break
                buf.append(line)
            print_result(analyse_message("\n".join(buf)))
        elif ch == "3":
            pw = _read("Type a sample password (do not use your real one): ")
            print_result(check_password(pw))
        elif ch == "4":
            path = _read("File path: ")
            info = sha256_of_file(path)
            print(json.dumps(info, indent=2))
        elif ch == "5":
            run_demo("output")
        elif ch == "6":
            run_tests()
        elif ch == "7" or ch.lower() in ("q", "quit", "exit"):
            print("bye")
            break
        else:
            print("Please enter a number from 1 to 7")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        run_demo("output")
    elif len(sys.argv) > 1 and sys.argv[1] == "test":
        p, n, _ = run_tests()
        sys.exit(0 if p == n else 1)
    else:
        menu()
