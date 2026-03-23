"""
OSINT Auto-Research Tool v5
Unified cross-linked OSINT with email/phone/username search.
FastAPI on port 8000. Single POST /lookup endpoint.
"""

import asyncio
import hashlib
import re
import socket
from datetime import datetime

import httpx
import phonenumbers
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from phonenumbers import carrier, geocoder, timezone
from pydantic import BaseModel

# ─── App Setup ────────────────────────────────────────────────────────────────
app = FastAPI(title="OSINT Tool", version="5.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Models ────────────────────────────────────────────────────────────────────
class LookupRequest(BaseModel):
    query: str
    lookup_type: str  # "email" | "phone" | "username" | "auto"

# ─── Constants ─────────────────────────────────────────────────────────────────
PLATFORMS_HEAD_CHECK = [
    ("Twitter",     "https://twitter.com/{u}"),
    ("Instagram",   "https://instagram.com/{u}"),
    ("Reddit",       "https://reddit.com/user/{u}"),
    ("TikTok",       "https://tiktok.com/@{u}"),
    ("YouTube",      "https://youtube.com/@{u}"),
    ("Telegram",     "https://t.me/{u}"),
    ("GitLab",       "https://gitlab.com/{u}"),
    ("LinkedIn",     "https://www.linkedin.com/in/{u}"),
    ("Pinterest",    "https://www.pinterest.com/{u}"),
    ("Medium",       "https://medium.com/@{u}"),
    ("Steam",        "https://steamcommunity.com/id/{u}"),
    ("Spotify",      "https://open.spotify.com/user/{u}"),
    ("Threads",     "https://threads.net/@{u}"),
    ("Mastodon",     "https://mastodon.social/@{u}"),
]

DISPOSABLE_DOMAINS = {
    "tempmail.com", "guerrillamail.com", "mailinator.com", "10minutemail.com",
    "throwaway.email", "temp-mail.org", "fakeinbox.com", "trashmail.com",
    "guerrillamail.info", "mailnesia.com", "tempr.email", "yopmail.com",
    "sharklasers.com", "guerrillamailblock.com", "pokemail.com", "spam4.me",
    "dispostable.com", "mintemail.com", "maildrop.cc", "getairmail.com",
    "throwawaymail.com", "emailondeck.com",
}

KNOWN_EMAIL_DOMAINS = {
    "gmail.com": "Google/Gmail", "googlemail.com": "Google/Gmail",
    "outlook.com": "Microsoft/Outlook", "hotmail.com": "Microsoft/Outlook",
    "live.com": "Microsoft/Outlook", "msn.com": "Microsoft/Outlook",
    "icloud.com": "Apple iCloud", "apple.com": "Apple ID",
    "yahoo.com": "Yahoo", "aol.com": "AOL",
    "protonmail.com": "ProtonMail", "proton.me": "ProtonMail",
    "me.com": "Apple iCloud", "mac.com": "Apple iCloud",
    "ymail.com": "Yahoo",
}

REQUEST_DELAY = 0.3
HTTP_TIMEOUT = 10.0
CLIENT_TIMEOUT = 60.0

# ─── Helpers ──────────────────────────────────────────────────────────────────
async def http_get(client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response | None:
    await asyncio.sleep(REQUEST_DELAY)
    try:
        return await client.get(url, timeout=kwargs.pop("timeout", HTTP_TIMEOUT), **kwargs)
    except Exception:
        return None

async def http_head(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    await asyncio.sleep(REQUEST_DELAY)
    try:
        return await client.head(url, timeout=HTTP_TIMEOUT, follow_redirects=True)
    except Exception:
        return None

def md5_hash_email(email: str) -> str:
    return hashlib.md5(email.lower().encode()).hexdigest()

def validate_email(q: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", q))

def validate_username(q: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9_\-\.]{1,50}$", q))

def validate_phone(q: str) -> bool:
    stripped = re.sub(r"[\s\-\(\)\.]", "", q)
    return bool(re.match(r"^\+?\d{7,15}$", stripped))

def detect_type(q: str) -> str:
    if validate_email(q):
        return "email"
    if validate_phone(q):
        return "phone"
    if validate_username(q):
        return "username"
    return "unknown"

def add_entity(entities: dict, category: str, item: dict):
    """Add an entity to the appropriate category list."""
    if category not in entities:
        entities[category] = []
    # Avoid duplicates by value
    if category == "usernames":
        if not any(e.get("value") == item.get("value") for e in entities[category]):
            entities[category].append(item)
    elif category == "emails":
        if not any(e.get("value") == item.get("value") for e in entities[category]):
            entities[category].append(item)
    elif category == "phones":
        if not any(e.get("value") == item.get("value") for e in entities[category]):
            entities[category].append(item)
    elif category == "accounts":
        key = f"{item.get('platform')}:{item.get('username')}"
        if not any(f"{e.get('platform')}:{e.get('username')}" == key for e in entities[category]):
            entities[category].append(item)

def add_cross_ref(cross_refs: list, frm: str, to: str, reason: str):
    key = f"{frm}|{to}"
    if not any(f"{c['from']}|{c['to']}" == key for c in cross_refs):
        cross_refs.append({"from": frm, "to": to, "reason": reason})

def add_raw(raw_results: list, source: str, status: str, title: str, detail: str = "",
            url: str = "", data: dict = None, tags: list[str] = None):
    entry = {"source": source, "status": status, "title": title, "detail": detail}
    if url:
        entry["url"] = url
    if data:
        entry["data"] = data
    if tags:
        entry["tags"] = tags
    raw_results.append(entry)

# ─── Email Lookups ─────────────────────────────────────────────────────────────
async def lookup_email(email: str, entities: dict, cross_refs: list, raw: list):
    domain = email.split("@")[1].lower() if "@" in email else ""

    # 1. MX records
    try:
        socket.getaddrinfo(domain, 25)
        add_raw(raw, "MX Records", "found", f"MX verified for {domain}",
                f"Domain '{domain}' accepts email delivery.", tags=["domain"])
    except socket.gaierror:
        add_raw(raw, "MX Records", "not_found", f"No MX for {domain}",
                f"Domain '{domain}' has no MX records — likely invalid.", tags=["domain"])

    # 2. Disposable domain check
    is_disposable = domain in DISPOSABLE_DOMAINS or any(domain.endswith("." + d) for d in DISPOSABLE_DOMAINS)
    if is_disposable:
        add_raw(raw, "Disposable Email", "found", "Disposable email domain detected",
                f"'{domain}' is a known temporary/disposable email service.", tags=["disposable", "warning"])
        add_entity(entities, "emails", {"value": email, "source": "input", "disposable": True, "domain": domain})
    else:
        add_entity(entities, "emails", {"value": email, "source": "input", "disposable": False, "domain": domain})

    # 3. Domain provider identification
    base = domain.split(".")[0] if "." in domain else domain
    provider = KNOWN_EMAIL_DOMAINS.get(base, None)
    if provider:
        add_raw(raw, provider, "found", f"Hosted on {provider}",
                f"Email domain '{domain}' belongs to {provider}.", tags=["domain", provider])
    elif "gmail" in domain:
        add_raw(raw, "Google/Gmail", "found", "Hosted on Google/Gmail",
                f"Email domain '{domain}' belongs to Google.", tags=["domain", "Google"])
    elif any(x in domain for x in ["outlook", "hotmail", "live", "msn"]):
        add_raw(raw, "Microsoft/Outlook", "found", "Hosted on Microsoft/Outlook",
                f"Email domain '{domain}' belongs to Microsoft.", tags=["domain", "Microsoft"])
    elif "icloud" in domain or "apple" in domain:
        add_raw(raw, "Apple iCloud", "found", "Hosted on Apple iCloud",
                f"Email domain '{domain}' belongs to Apple.", tags=["domain", "Apple"])
    elif "proton" in domain:
        add_raw(raw, "ProtonMail", "found", "Hosted on ProtonMail",
                f"Email domain '{domain}' is a ProtonMail encrypted service.", tags=["domain", "ProtonMail"])
    elif "yahoo" in domain:
        add_raw(raw, "Yahoo", "found", "Hosted on Yahoo",
                f"Email domain '{domain}' belongs to Yahoo.", tags=["domain", "Yahoo"])
    elif "tutanota" in domain:
        add_raw(raw, "Tutanota", "found", "Hosted on Tutanota",
                f"Email domain '{domain}' is an encrypted Tutanota service.", tags=["domain", "Tutanota"])

    # 4. HIBP breach check
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await http_get(client,
                f"https://haveibeenpwned.com/unifiedsearch/{email}",
                headers={"User-Agent": "OSINT-Tool-v5", "Accept": "application/json"})
            if resp and resp.status_code == 200:
                breaches = resp.json().get("Breaches", [])
                if breaches:
                    names = [b.get("Name", "?") for b in breaches[:10]]
                    add_raw(raw, "Have I Been Pwned", "found",
                            f"Found in {len(breaches)} breach(es)",
                            f"Breaches: {', '.join(names)}",
                            data={"breach_count": len(breaches), "breaches": breaches[:10]},
                            tags=["breach", "hibp"])
                    # Update email entity with breach count
                    for e in entities.get("emails", []):
                        if e.get("value") == email:
                            e["breach_count"] = len(breaches)

                    # Extract usernames and social profiles from breach data
                    # Some breaches contain usernames and social media info
                    breach_usernames = []
                    breach_platforms = set()
                    for breach in breaches:
                        dc = breach.get("DataClasses", [])
                        if "Usernames" in dc:
                            breach_usernames.append(breach.get("Name", "unknown"))
                        if "Social media profiles" in dc or "Email addresses" in dc:
                            breach_platforms.add(breach.get("Name", ""))
                    
                    # Also try to find "affected systems" — some breaches like Twitter200M
                    # specifically link email → Twitter handle
                    twitter_breach = next((b for b in breaches if "Twitter" in b.get("Name", "") or "twitter" in b.get("Domain", "")), None)
                    if twitter_breach:
                        add_raw(raw, "Twitter Breach Link", "found",
                                "Email found in Twitter breach",
                                f"This email was in the Twitter 200M breach — email was used to look up Twitter accounts.",
                                tags=["breach", "twitter", "social"])
                    
                    if breach_usernames:
                        add_raw(raw, "Breach Username Data", "found",
                                f"Breaches may contain username data",
                                f"These breaches include username fields: {', '.join(breach_usernames[:5])}",
                                tags=["breach", "usernames"])
            
            elif resp and resp.status_code == 404:
                add_raw(raw, "Have I Been Pwned", "not_found",
                        "No breaches found", "Not found in known data breaches.", tags=["breach"])
            elif resp and resp.status_code == 429:
                add_raw(raw, "Have I Been Pwned", "rate_limited",
                        "Rate limited", "HIBP rate limit — try again later.", tags=["breach"])
    except Exception:
        pass

    # 5. Try email local part as potential username — many people use email local part as username
    email_local = email.split("@")[0].lower().strip()
    # Clean: remove dots from gmail, remove +tags, remove common separators
    if "gmail" in domain:
        email_local = email_local.replace(".", "")
        if "+" in email_local:
            email_local = email_local.split("+")[0]
    # Only try if it looks like a username (3-30 chars, alphanumeric + underscore)
    if re.match(r'^[a-z0-9_-]{3,30}$', email_local):
        add_raw(raw, "Email→Username Match", "attempting",
                f"Trying '{email_local}' as potential username",
                f"Email local part as possible social media handle.",
                tags=["crosslink", "username"])
        # Check if this username exists on key platforms
        found_on = []
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            checks = [
                ("GitHub", f"https://api.github.com/users/{email_local}"),
                ("Twitter", f"https://twitter.com/{email_local}"),
                ("Instagram", f"https://instagram.com/{email_local}"),
                ("Reddit", f"https://reddit.com/user/{email_local}"),
                ("TikTok", f"https://tiktok.com/@{email_local}"),
            ]
            for platform, url in checks:
                try:
                    resp = await http_get(client, url,
                        headers={"User-Agent": "OSINT-Tool-v5"})
                    if resp and resp.status_code == 200:
                        found_on.append(platform)
                        if platform == "GitHub":
                            data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                            gh_name = data.get("name") or data.get("login", email_local)
                            gh_bio = data.get("bio") or ""
                            gh_email = data.get("email") or ""
                            add_entity(entities, "usernames", {
                                "value": email_local, "source": "email_local",
                                "platform": "GitHub",
                                "url": f"https://github.com/{email_local}",
                                "bio": gh_bio
                            })
                            if gh_email:
                                add_entity(entities, "emails", {
                                    "value": gh_email, "source": "github_profile_from_email_local",
                                    "domain": gh_email.split("@")[1] if "@" in gh_email else ""
                                })
                                add_cross_ref(cross_refs, email, gh_email,
                                              f"GitHub profile for {email_local} has public email")
                            add_cross_ref(cross_refs, email, email_local,
                                          f"GitHub account '{email_local}' found — email local part matches username")
                        else:
                            add_entity(entities, "accounts", {
                                "platform": platform,
                                "username": email_local,
                                "url": url,
                                "found_via": "email_local"
                            })
                            add_cross_ref(cross_refs, email, email_local,
                                          f"Account '{email_local}' found on {platform} — matches email local part")
                        await asyncio.sleep(0.3)  # rate limit
                except Exception:
                    pass
        
        if found_on:
            add_raw(raw, "Email Local → Username", "found",
                    f"Email local part '{email_local}' found on {', '.join(found_on)}",
                    f"The username '{email_local}' (from {email}) was found on {', '.join(found_on)}.",
                    tags=["crosslink", "found"])
        else:
            add_raw(raw, "Email Local → Username", "not_found",
                    f"'{email_local}' not found on major platforms",
                    f"Email local part doesn't appear to be a username on checked platforms.",
                    tags=["crosslink"])

    # 6. Gravatar check
    md5 = md5_hash_email(email)
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await http_get(client,
                f"https://www.gravatar.com/{md5}.json",
                headers={"User-Agent": "OSINT-Tool-v5"})
            if resp and resp.status_code == 200:
                data = resp.json()
                entry = data.get("entry", [{}])[0]
                display_name = entry.get("displayName", "")
                bio = entry.get("aboutMe", "")
                location = entry.get("currentLocation", "")
                urls = entry.get("urls", [])
                add_raw(raw, "Gravatar", "found", "Gravatar profile found",
                        f"Display name: {display_name or 'N/A'}",
                        data={"display_name": display_name, "bio": bio,
                              "location": location, "urls": urls},
                        tags=["avatar", "profile"])
                if display_name:
                    add_entity(entities, "usernames", {
                        "value": display_name,
                        "source": "gravatar",
                        "platform": "Gravatar",
                        "url": f"https://gravatar.com/{md5}",
                        "bio": bio
                    })
                    add_cross_ref(cross_refs, email, display_name,
                                  "Gravatar display name linked to this email")
    except Exception:
        pass

    # 6. GitHub commit search — email → usernames
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await http_get(client,
                f"https://api.github.com/search/commits?q={email}+author-email:{email}",
                headers={"Accept": "application/vnd.github.cloak-preview+json"})
            if resp and resp.status_code == 200:
                data = resp.json()
                total = data.get("total_count", 0)
                seen = set()
                for item in data.get("items", [])[:30]:
                    author = item.get("author", {})
                    login = author.get("login")
                    name = author.get("name", "")
                    repo = item.get("repository", {}).get("full_name", "?")
                    sha = item.get("sha", "")[:8]
                    if login and login not in seen:
                        seen.add(login)
                        add_entity(entities, "usernames", {
                            "value": login, "source": "github_commits",
                            "platform": "GitHub",
                            "url": f"https://github.com/{login}",
                            "bio": f"Found via commit in {repo} ({sha})"
                        })
                        add_cross_ref(cross_refs, email, login,
                                      f"GitHub commit author — found in repo {repo}")
                        # Try to get email from this GitHub username
                        await fetch_github_email(login, entities, cross_refs, raw)
                if total > 0:
                    add_raw(raw, "GitHub Commits", "found",
                            f"Email found in {total} GitHub commit(s)",
                            f"Discovered {len(seen)} unique GitHub account(s).",
                            data={"total_count": total, "usernames": list(seen)},
                            tags=["github", "commits"])
                else:
                    add_raw(raw, "GitHub Commits", "not_found",
                            "No GitHub commits found", "Email not found in public GitHub commits.", tags=["github"])
            elif resp and resp.status_code == 403:
                add_raw(raw, "GitHub Commits", "rate_limited",
                        "GitHub rate limited", "GitHub API limit reached.", tags=["github"])
    except Exception:
        pass


async def fetch_github_email(username: str, entities: dict, cross_refs: list, raw: list):
    """Fetch a GitHub profile to get public email, then cross-reference."""
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await http_get(client,
                f"https://api.github.com/users/{username}",
                headers={"Accept": "application/vnd.github.v3+json"})
            if resp and resp.status_code == 200:
                data = resp.json()
                public_email = data.get("email")
                name = data.get("name") or ""
                bio = data.get("bio") or ""
                location = data.get("location") or ""
                company = data.get("company") or ""
                blog = data.get("blog") or ""
                twitter = data.get("twitter_username") or ""
                public_repos = data.get("public_repos", 0)
                followers = data.get("followers", 0)
                avatar_url = data.get("avatar_url", "")
                created_at = data.get("created_at", "")[:10]

                if public_email:
                    add_entity(entities, "emails", {
                        "value": public_email,
                        "source": "github_profile",
                        "domain": public_email.split("@")[1] if "@" in public_email else ""
                    })
                    add_cross_ref(cross_refs, username, public_email,
                                  f"Public email on GitHub profile")

                add_raw(raw, f"GitHub: {username}", "found",
                        f"GitHub profile — {name or username}",
                        f"{public_repos} repos, {followers} followers" +
                        (f", public email: {public_email}" if public_email else ""),
                        url=f"https://github.com/{username}",
                        data={
                            "name": name, "bio": bio, "company": company,
                            "location": location, "blog": blog,
                            "twitter": twitter, "public_repos": public_repos,
                            "followers": followers, "created_at": created_at,
                            "avatar_url": avatar_url, "public_email": public_email,
                        },
                        tags=["github", "profile"])
    except Exception:
        pass


# ─── Username Lookups ──────────────────────────────────────────────────────────
async def lookup_username(username: str, entities: dict, cross_refs: list, raw: list):
    add_entity(entities, "usernames", {"value": username, "source": "input", "platform": "input"})

    # 1. GitHub profile
    public_email = await lookup_username_github(username, entities, cross_refs, raw)

    # 2. Platform checks (parallel batches)
    await lookup_username_platforms(username, entities, cross_refs, raw)

    # Cross-link: if we found email from GitHub
    if public_email:
        add_cross_ref(cross_refs, username, public_email,
                      "Public email found on GitHub profile")


async def lookup_username_github(username: str, entities: dict, cross_refs: list, raw: list) -> str | None:
    """Check GitHub and extract profile data + public email."""
    public_email = None
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await http_get(client,
                f"https://api.github.com/users/{username}",
                headers={"Accept": "application/vnd.github.v3+json"})
            if resp and resp.status_code == 200:
                data = resp.json()
                name = data.get("name") or ""
                bio = data.get("bio") or ""
                company = data.get("company") or ""
                location = data.get("location") or ""
                blog = data.get("blog") or ""
                twitter = data.get("twitter_username") or ""
                public_repos = data.get("public_repos", 0)
                followers = data.get("followers", 0)
                following = data.get("following", 0)
                created_at = data.get("created_at", "")[:10]
                avatar_url = data.get("avatar_url", "")
                public_email = data.get("email") or ""

                add_entity(entities, "accounts", {
                    "platform": "GitHub",
                    "username": username,
                    "url": f"https://github.com/{username}",
                    "found_via": "github_profile",
                    "bio": bio,
                    "name": name,
                    "location": location,
                    "public_repos": public_repos,
                    "followers": followers,
                })

                if public_email:
                    add_entity(entities, "emails", {
                        "value": public_email,
                        "source": "github_profile",
                        "domain": public_email.split("@")[1] if "@" in public_email else ""
                    })
                    add_cross_ref(cross_refs, username, public_email,
                                  "Public email on GitHub profile — this is likely their real email")

                add_raw(raw, "GitHub", "found",
                        f"GitHub profile — {name or username}",
                        f"{public_repos} repos, {followers} followers, {following} following" +
                        (f", public email: {public_email}" if public_email else ", no public email"),
                        url=f"https://github.com/{username}",
                        data={
                            "name": name, "bio": bio, "company": company,
                            "location": location, "blog": blog,
                            "twitter": twitter, "public_repos": public_repos,
                            "followers": followers, "following": following,
                            "created_at": created_at, "avatar_url": avatar_url,
                            "public_email": public_email,
                        },
                        tags=["github", "profile"])

                if twitter:
                    add_entity(entities, "accounts", {
                        "platform": "Twitter",
                        "username": twitter,
                        "url": f"https://twitter.com/{twitter}",
                        "found_via": "github_twitter",
                    })
                    add_cross_ref(cross_refs, username, twitter,
                                  "Twitter handle listed on GitHub profile")
                    add_raw(raw, "Twitter (from GitHub)", "found",
                            f"Twitter @{twitter}",
                            "Twitter handle found on GitHub profile.",
                            url=f"https://twitter.com/{twitter}",
                            tags=["twitter", "github_link"])

            elif resp and resp.status_code == 404:
                add_raw(raw, "GitHub", "not_found",
                        f"No GitHub profile for '{username}'",
                        f"Username '{username}' not found on GitHub.", tags=["github"])
            elif resp and resp.status_code == 403:
                add_raw(raw, "GitHub", "rate_limited",
                        "GitHub rate limited", "GitHub API limit reached.", tags=["github"])
    except Exception:
        pass
    return public_email


async def lookup_username_platforms(username: str, entities: dict, cross_refs: list, raw: list):
    """Check username across platforms in parallel batches."""
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        tasks = []
        for platform, url_template in PLATFORMS_HEAD_CHECK:
            url = url_template.format(u=username)
            tasks.append(check_platform(client, platform, url, username, entities, cross_refs, raw))
        await asyncio.gather(*tasks)


async def check_platform(client: httpx.AsyncClient, platform: str, url: str,
                         username: str, entities: dict, cross_refs: list, raw: list):
    resp = await http_head(client, url)
    status = resp.status_code if resp else None
    if status in (200, 301, 302, 303, 307, 308):
        add_entity(entities, "accounts", {
            "platform": platform,
            "username": username,
            "url": url,
            "found_via": "platform_check",
        })
        add_cross_ref(cross_refs, username, f"{platform}@{username}",
                      f"Account found on {platform}")
        add_raw(raw, platform, "found",
                f"{platform} account found",
                f"@{username} is taken on {platform}.",
                url=url, tags=["account", "platform"])
    elif status == 404:
        add_raw(raw, platform, "not_found",
                f"No {platform} account",
                f"@{username} not found on {platform}.", tags=["account"])
    elif status == 429:
        add_raw(raw, platform, "rate_limited",
                f"{platform} rate limited",
                "Rate limit hit for this platform.", tags=["account"])
    else:
        add_raw(raw, platform, "unknown",
                f"{platform} — HTTP {status}",
                f"Unexpected response code {status}.", tags=["account"])


# ─── Phone Lookups ──────────────────────────────────────────────────────────────
async def lookup_phone(phone: str, entities: dict, cross_refs: list, raw: list):
    # Parse and validate
    raw_digits = re.sub(r"\D", "", phone)
    e164 = None
    parsed_obj = None

    for region in ["US", None]:
        try:
            parsed = phonenumbers.parse(f"+{raw_digits}" if not phone.startswith("+") else phone, region if region else None)
            if phonenumbers.is_valid_number(parsed):
                parsed_obj = parsed
                e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
                break
        except Exception:
            pass

    if parsed_obj:
        country_code = phonenumbers.region_code_for_number(parsed_obj)
        intl_fmt = phonenumbers.format_number(parsed_obj, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        national_fmt = phonenumbers.format_number(parsed_obj, phonenumbers.PhoneNumberFormat.NATIONAL)
        carrier_name = carrier.name_for_number(parsed_obj, "en") or "Unknown"
        geo_desc = geocoder.description_for_number(parsed_obj, "en") or "Unknown"
        timezones_list = list(timezone.time_zones_for_number(parsed_obj))

        add_entity(entities, "phones", {
            "value": e164,
            "national": national_fmt,
            "international": intl_fmt,
            "carrier": carrier_name,
            "country": country_code,
            "geocoder": geo_desc,
            "timezones": timezones_list,
            "valid": True,
            "source": "phonenumbers",
        })
        add_cross_ref(cross_refs, phone, e164, "Validated phone number")
        add_raw(raw, "Phone Info", "found",
                f"Valid phone — {intl_fmt}",
                f"{geo_desc}, carrier: {carrier_name}, timezones: {', '.join(timezones_list)}",
                data={
                    "country_code": country_code,
                    "international": intl_fmt,
                    "national": national_fmt,
                    "e164": e164,
                    "carrier": carrier_name,
                    "geocoder": geo_desc,
                    "timezones": timezones_list,
                    "valid": True,
                },
                tags=["phone", "carrier"])
    else:
        add_raw(raw, "Phone Info", "error",
                "Invalid phone number",
                "Could not parse/validate this phone number.", tags=["phone"])
        add_entity(entities, "phones", {
            "value": raw_digits,
            "valid": False,
            "source": "phonenumbers",
        })


# ─── Main ──────────────────────────────────────────────────────────────────────
def build_response(query: str, detected_type: str, entities: dict,
                   cross_refs: list, raw: list) -> dict:
    accounts = entities.get("accounts", [])
    usernames = entities.get("usernames", [])
    emails = entities.get("emails", [])
    phones = entities.get("phones", [])

    found_raw = [r for r in raw if r["status"] == "found"]
    total_found = len(found_raw)

    # Confidence
    if total_found >= 5:
        confidence = "high"
    elif total_found >= 2:
        confidence = "medium"
    else:
        confidence = "low"

    # Summary
    parts = []
    if accounts:
        platforms = list(dict.fromkeys(a["platform"] for a in accounts))
        parts.append(f"Found {len(accounts)} account(s) on {len(platforms)} platform(s): {', '.join(platforms[:6])}{'...' if len(platforms) > 6 else ''}.")
    if usernames:
        parts.append(f"Discovered {len(set(u['value'] for u in usernames))} username(s).")
    if emails:
        parts.append(f"Linked to {len(set(e['value'] for e in emails))} email(s).")
    if phones:
        parts.append(f"Found {len(phones)} phone number(s).")
    if cross_refs:
        parts.append(f"{len(cross_refs)} cross-link(s) between identities.")

    summary = " ".join(parts) if parts else f"No results found for {detected_type} '{query}'."
    if total_found == 0:
        summary = f"No public records found for {detected_type} '{query}'. This may be a private or non-existent identity."

    return {
        "query": query,
        "detected_type": detected_type,
        "summary": summary,
        "confidence": confidence,
        "entities": {
            "usernames": usernames,
            "emails": emails,
            "phones": phones,
            "accounts": accounts,
        },
        "cross_references": cross_refs,
        "raw_results": raw,
        "_debug": {
            "total_raw_results": len(raw),
            "found_count": total_found,
        }
    }


# ─── Routes ────────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "service": "OSINT Tool v5",
        "version": "5.0.0",
        "endpoints": {
            "POST /lookup": {"query": "string", "lookup_type": "email|phone|username|auto"},
            "GET /health": "health check",
        },
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "OSINT Tool v5"}

@app.post("/lookup")
async def lookup(req: LookupRequest):
    q = req.query.strip()
    if not q:
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    lookup_type = req.lookup_type.strip().lower()
    if lookup_type == "auto":
        detected = detect_type(q)
        if detected == "unknown":
            raise HTTPException(status_code=400,
                detail="Could not auto-detect input type. Please specify: email, phone, or username")
        lookup_type = detected
    else:
        if lookup_type not in ("email", "phone", "username"):
            raise HTTPException(status_code=400,
                detail="lookup_type must be: email, phone, username, or auto")
        # Validate format
        if lookup_type == "email" and not validate_email(q):
            raise HTTPException(status_code=400,
                detail="Invalid email format")
        if lookup_type == "username" and not validate_username(q):
            raise HTTPException(status_code=400,
                detail="Invalid username format (1-50 chars: a-zA-Z0-9_.-)")
        if lookup_type == "phone" and not validate_phone(q):
            raise HTTPException(status_code=400,
                detail="Invalid phone format (7-15 digits, optional +)")

    entities = {"usernames": [], "emails": [], "phones": [], "accounts": []}
    cross_refs = []
    raw = []

    try:
        if lookup_type == "email":
            await lookup_email(q, entities, cross_refs, raw)
        elif lookup_type == "username":
            await lookup_username(q, entities, cross_refs, raw)
        elif lookup_type == "phone":
            await lookup_phone(q, entities, cross_refs, raw)

        return JSONResponse(content=build_response(q, lookup_type, entities, cross_refs, raw))
    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(
            status_code=200,
            content={
                "query": q,
                "detected_type": lookup_type,
                "summary": f"Error: {str(e)}",
                "confidence": "unknown",
                "entities": {"usernames": [], "emails": [], "phones": [], "accounts": []},
                "cross_references": [],
                "raw_results": [],
                "_error": str(e),
            }
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
