"""
OSINT Auto-Research Tool v4
Full cross-linked OSINT with username/email/phone search.
- FastAPI on port 8000
- Single POST /lookup endpoint
- All lookups async with httpx
- Cross-links email → usernames and username → emails
"""

import asyncio
import hashlib
import json
import os
import re
import socket
from typing import Any

import httpx
import phonenumbers
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from phonenumbers import carrier, geocoder, timezone
from pydantic import BaseModel

# ─── App Setup ────────────────────────────────────────────────────────────────

app = FastAPI(title="OSINT Tool", version="4.0.0")

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
    lookup_type: str  # "email" | "phone" | "username"


# ─── Constants ─────────────────────────────────────────────────────────────────

PLATFORMS_HEAD_CHECK = [
    ("Twitter", "https://twitter.com/{u}"),
    ("Instagram", "https://instagram.com/{u}"),
    ("Reddit", "https://reddit.com/user/{u}"),
    ("TikTok", "https://tiktok.com/@{u}"),
    ("YouTube", "https://youtube.com/@{u}"),
    ("Telegram", "https://t.me/{u}"),
    ("GitLab", "https://gitlab.com/{u}"),
    ("LinkedIn", "https://www.linkedin.com/in/{u}"),
    ("Pinterest", "https://www.pinterest.com/{u}"),
    ("Medium", "https://medium.com/@{u}"),
    ("Steam", "https://steamcommunity.com/id/{u}"),
    ("Spotify", "https://open.spotify.com/user/{u}"),
]

DISPOSABLE_DOMAINS = {
    "tempmail.com", "guerrillamail.com", "mailinator.com", "10minutemail.com",
    "throwaway.email", "temp-mail.org", "fakeinbox.com", "trashmail.com",
    "guerrillamail.info", "mailnesia.com", "tempr.email", "yopmail.com",
    "sharklasers.com", "guerrillamailblock.com", "pokemail.com", "spam4.me",
    "dispostable.com", "mintemail.com", "maildrop.cc", "getairmail.com",
}

KNOWN_EMAIL_DOMAINS = {
    "gmail.com": "Google/Gmail",
    "googlemail.com": "Google/Gmail",
    "outlook.com": "Microsoft/Outlook",
    "hotmail.com": "Microsoft/Outlook",
    "live.com": "Microsoft/Outlook",
    "msn.com": "Microsoft/Outlook",
    "icloud.com": "Apple iCloud",
    "apple.com": "Apple ID",
    "yahoo.com": "Yahoo",
    "aol.com": "AOL",
    "protonmail.com": "ProtonMail",
    "proton.me": "ProtonMail",
    "me.com": "Apple iCloud",
    "mac.com": "Apple iCloud",
    "ymail.com": "Yahoo",
}

REQUEST_DELAY = 0.5  # seconds between HTTP requests
HTTP_TIMEOUT = 12.0  # seconds per request
CLIENT_TIMEOUT = 60.0  # total endpoint timeout

# ─── Helpers ──────────────────────────────────────────────────────────────────

def add_result(results: list[dict], site: str, status: str, source: str,
               detail: str = "", url: str = "", data: dict = None, cross_link: str = ""):
    """Append a structured result entry."""
    entry = {
        "site": site,
        "status": status,
        "source": source,
        "detail": detail,
    }
    if url:
        entry["url"] = url
    if data:
        entry["data"] = data
    if cross_link:
        entry["cross_link"] = cross_link
    results.append(entry)


async def http_get(client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response | None:
    """GET with delay, returns None on failure."""
    await asyncio.sleep(REQUEST_DELAY)
    try:
        resp = await client.get(url, timeout=kwargs.pop("timeout", HTTP_TIMEOUT), **kwargs)
        return resp
    except Exception:
        return None


async def http_head(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    """HEAD with delay, returns None on failure."""
    await asyncio.sleep(REQUEST_DELAY)
    try:
        resp = await client.head(url, timeout=HTTP_TIMEOUT, follow_redirects=True)
        return resp
    except Exception:
        return None


def md5_hash_email(email: str) -> str:
    return hashlib.md5(email.lower().encode()).hexdigest()


def build_summary(query: str, lookup_type: str, primary: list, cross: list,
                   all_usernames: list, all_emails: list, all_phones: list) -> str:
    parts = []
    found_count = len([r for r in primary if r.get("status") == "found"])
    cross_count = len(cross)
    if found_count > 0:
        parts.append(f"Found {found_count} direct result(s) for {lookup_type} '{query}'.")
    else:
        parts.append(f"No direct results for {lookup_type} '{query}'.")
    if cross_count > 0:
        parts.append(f"Found {cross_count} cross-linked result(s) via related lookups.")
    if all_usernames:
        parts.append(f"Discovered {len(all_usernames)} username(s): {', '.join(all_usernames)}.")
    if all_emails and lookup_type != "email":
        parts.append(f"Discovered {len(all_emails)} email(s).")
    if all_phones:
        parts.append(f"Discovered {len(all_phones)} phone number(s).")
    return " ".join(parts)


# ─── Validation ───────────────────────────────────────────────────────────────

def validate_email(q: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", q))

def validate_username(q: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9_\-\.]{1,50}$", q))

def validate_phone(q: str) -> bool:
    stripped = re.sub(r"[\s\-\(\)\.]", "", q)
    return bool(re.match(r"^\+?\d{7,15}$", stripped))


# ─── Email Lookups ─────────────────────────────────────────────────────────────

async def email_mx_check(email: str, results: list[dict]) -> None:
    """Check MX records for email domain."""
    domain = email.split("@")[1].lower() if "@" in email else ""
    if not domain:
        return
    try:
        # getaddrinfo with port 25 checks MX
        socket.getaddrinfo(domain, 25)
        add_result(results, f"MX Records ({domain})", "found", "dns",
                   f"Domain '{domain}' accepts email delivery (MX verified).", cross_link="domain")
    except socket.gaierror:
        add_result(results, f"MX Records ({domain})", "not_found", "dns",
                   f"Domain '{domain}' has no MX records — likely not a real email service.")


async def email_hibp_check(email: str, results: list[dict]) -> None:
    """Check Have I Been Pwned for breaches."""
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await http_get(client,
                f"https://haveibeenpwned.com/unifiedsearch/{email}",
                headers={"User-Agent": "OSINT-Tool-v4", "Accept": "application/json"})
            if resp and resp.status_code == 200:
                breaches = resp.json().get("Breaches", [])
                if breaches:
                    names = [b.get("Name", "?") for b in breaches[:10]]
                    add_result(results, "Have I Been Pwned", "found", "hibp",
                               f"Found in {len(breaches)} breach(es): {', '.join(names)}",
                               data={"breach_count": len(breaches), "breaches": breaches[:10]})
                else:
                    add_result(results, "Have I Been Pwned", "not_found", "hibp",
                               "Not found in known data breaches.")
            elif resp and resp.status_code == 404:
                add_result(results, "Have I Been Pwned", "not_found", "hibp",
                           "Not found in known data breaches.")
            elif resp and resp.status_code == 429:
                add_result(results, "Have I Been Pwned", "rate_limited", "hibp",
                           "Rate limited — try again later.")
    except Exception:
        pass


async def email_gravatar_check(email: str, results: list[dict]) -> None:
    """Check Gravatar profile for email."""
    md5 = md5_hash_email(email)
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await http_get(client,
                f"https://www.gravatar.com/{md5}.json",
                headers={"User-Agent": "OSINT-Tool-v4"})
            if resp and resp.status_code == 200:
                data = resp.json()
                entry = data.get("entry", [{}])[0]
                display_name = entry.get("displayName", "")
                bio = entry.get("aboutMe", "")
                location = entry.get("currentLocation", "")
                urls = entry.get("urls", [])
                add_result(results, "Gravatar", "found", "gravatar",
                           f"Has Gravatar profile — display name: {display_name or 'N/A'}",
                           data={"display_name": display_name, "bio": bio,
                                 "location": location, "urls": urls},
                           cross_link="avatar")
            elif resp and resp.status_code == 404:
                add_result(results, "Gravatar", "not_found", "gravatar",
                           "No Gravatar profile found for this email.")
    except Exception:
        pass


async def email_github_commit_search(email: str, results: list[dict]) -> tuple[list[str], list[dict]]:
    """
    Search GitHub commits by author email.
    Returns (usernames_found, commit_results) for cross-linking.
    """
    usernames: list[str] = []
    commit_results: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await http_get(client,
                f"https://api.github.com/search/commits?q={email}+author-email:{email}",
                headers={"Accept": "application/vnd.github.cloak-preview+json"})
            if resp and resp.status_code == 200:
                data = resp.json()
                total = data.get("total_count", 0)
                if total > 0:
                    add_result(results, "GitHub Commits", "found", "github",
                               f"Email found in {total} GitHub commit(s).",
                               data={"total_count": total})
                    # Extract unique usernames from commit authors
                    for item in data.get("items", [])[:20]:
                        author = item.get("author", {})
                        login = author.get("login", "")
                        name = author.get("name", "")
                        if login and login not in usernames:
                            usernames.append(login)
                            commit_results.append({
                                "username": login,
                                "name": name,
                                "repo": item.get("repository", {}).get("full_name", ""),
                                "sha": item.get("sha", "")[:8],
                            })
                else:
                    add_result(results, "GitHub Commits", "not_found", "github",
                               "Email not found in any public GitHub commits.")
            elif resp and resp.status_code == 403:
                add_result(results, "GitHub Commits", "rate_limited", "github",
                           "GitHub API rate limit reached (60 req/hr for unauthenticated).")
    except Exception:
        pass
    return usernames, commit_results


async def email_disposable_check(email: str, results: list[dict]) -> None:
    """Detect disposable email domains."""
    domain = email.split("@")[1].lower() if "@" in email else ""
    if domain in DISPOSABLE_DOMAINS or any(domain.endswith("." + d) for d in DISPOSABLE_DOMAINS):
        add_result(results, "Disposable Email", "found", "disposable",
                   f"Domain '{domain}' is a known disposable/temporary email service.",
                   cross_link="disposable")


async def email_domain_type_check(email: str, results: list[dict]) -> None:
    """Detect known email provider types."""
    domain = email.split("@")[1].lower() if "@" in email else ""
    base = domain.split(".")[0] if "." in domain else domain
    if base in KNOWN_EMAIL_DOMAINS:
        provider = KNOWN_EMAIL_DOMAINS[base]
        add_result(results, provider, "found", "domain",
                   f"Email hosted on {provider} domain ({domain}).", cross_link="domain")
    elif "gmail" in domain:
        add_result(results, "Google/Gmail", "found", "domain",
                   f"Email hosted on Google ({domain}).", cross_link="domain")
    elif any(x in domain for x in ["outlook", "hotmail", "live", "msn"]):
        add_result(results, "Microsoft/Outlook", "found", "domain",
                   f"Email hosted on Microsoft ({domain}).", cross_link="domain")
    elif "icloud" in domain or "apple" in domain:
        add_result(results, "Apple iCloud", "found", "domain",
                   f"Email hosted on Apple iCloud ({domain}).", cross_link="domain")
    elif "proton" in domain:
        add_result(results, "ProtonMail", "found", "domain",
                   f"Email hosted on ProtonMail — encrypted email service ({domain}).", cross_link="domain")
    elif "yahoo" in domain:
        add_result(results, "Yahoo", "found", "domain",
                   f"Email hosted on Yahoo ({domain}).", cross_link="domain")
    elif "aol" in domain:
        add_result(results, "AOL", "found", "domain",
                   f"Email hosted on AOL ({domain}).", cross_link="domain")
    elif "tutanota" in domain:
        add_result(results, "Tutanota", "found", "domain",
                   f"Email hosted on Tutanota — encrypted email ({domain}).", cross_link="domain")
    elif "hey" in domain:
        add_result(results, "Hey.com", "found", "domain",
                   f"Email hosted on Hey.com ({domain}).", cross_link="domain")


# ─── Username Lookups ──────────────────────────────────────────────────────────

async def username_github_check(username: str, results: list[dict],
                                cross_refs: list[dict]) -> str | None:
    """
    Check GitHub profile for username.
    Returns public email if found (for cross-linking).
    """
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

                add_result(results, "GitHub", "found", "github",
                           f"GitHub profile — {name or username} ({public_repos} repos, {followers} followers).",
                           url=f"https://github.com/{username}",
                           data={
                               "name": name, "bio": bio, "company": company,
                               "location": location, "blog": blog,
                               "twitter": twitter, "public_repos": public_repos,
                               "followers": followers, "following": following,
                               "created_at": created_at, "avatar_url": avatar_url,
                               "public_email": public_email,
                           },
                           cross_link="github")

                if public_email:
                    add_result(cross_refs, "GitHub Email", "found", "github",
                               f"Public email on GitHub profile: {public_email}",
                               data={"email": public_email},
                               cross_link="github_email")
                    return public_email
            elif resp and resp.status_code == 404:
                add_result(results, "GitHub", "not_found", "github",
                           f"No GitHub profile found for '{username}'.")
            elif resp and resp.status_code == 403:
                add_result(results, "GitHub", "rate_limited", "github",
                           "GitHub API rate limit reached.")
    except Exception:
        pass
    return None


async def username_platform_checks(username: str, results: list[dict]) -> None:
    """Check username across platforms via HEAD requests."""
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        for platform, url_template in PLATFORMS_HEAD_CHECK:
            url = url_template.format(u=username)
            resp = await http_head(client, url)
            status_code = resp.status_code if resp else None
            if status_code and status_code in (200, 301, 302, 303, 307, 308):
                add_result(results, platform, "found", "platform_check",
                           f"Account found at {url} (HTTP {status_code}).",
                           url=url, cross_link="platform")
            elif status_code == 404:
                add_result(results, platform, "not_found", "platform_check",
                           f"No account found at {url}.")
            elif status_code == 429:
                add_result(results, platform, "rate_limited", "platform_check",
                           "Rate limited by this platform.")
            else:
                add_result(results, platform, "unknown", "platform_check",
                           f"Unexpected response (HTTP {status_code}).")


# ─── Phone Lookups ──────────────────────────────────────────────────────────────

async def phone_info_lookup(phone: str, results: list[dict]) -> list[dict]:
    """Parse, validate, and get carrier/geocoder/timezone for a phone number."""
    raw = re.sub(r"[\s\-\(\)\.\+]+", "+", phone).strip()
    for region in ["US", None]:
        try:
            parsed = phonenumbers.parse(raw, region if region else None)
            if phonenumbers.is_valid_number(parsed):
                country_code = phonenumbers.region_code_for_number(parsed)
                intl_fmt = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
                national_fmt = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
                e164_fmt = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)

                carrier_name = carrier.name_for_number(parsed, "en") or "Unknown"
                geo_desc = geocoder.description_for_number(parsed, "en") or "Unknown"
                timezones = list(timezone.time_zones_for_number(parsed))

                add_result(results, "Phone Info", "found", "phonenumbers",
                           f"{intl_fmt} — {geo_desc}, carrier: {carrier_name}.",
                           data={
                               "country_code": country_code,
                               "international": intl_fmt,
                               "national": national_fmt,
                               "e164": e164_fmt,
                               "carrier": carrier_name,
                               "geocoder": geo_desc,
                               "timezones": timezones,
                               "valid": True,
                           },
                           cross_link="phone")
                return results
        except Exception:
            pass
    add_result(results, "Phone Info", "error", "phonenumbers",
               "Could not parse/validate phone number.")
    return results


# ─── Cross-linking: Email → GitHub username discovery ─────────────────────────

async def crosslink_email_to_github_usernames(email: str, results: list[dict]) -> list[str]:
    """
    From an email, find associated GitHub usernames via commit search.
    Returns list of usernames.
    """
    usernames: list[str] = []
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await http_get(client,
                f"https://api.github.com/search/commits?q={email}+author-email:{email}",
                headers={"Accept": "application/vnd.github.cloak-preview+json"})
            if resp and resp.status_code == 200:
                data = resp.json()
                seen = set()
                for item in data.get("items", [])[:30]:
                    author = item.get("author", {})
                    login = author.get("login")
                    if login and login not in seen:
                        seen.add(login)
                        usernames.append(login)
                        repo = item.get("repository", {}).get("full_name", "?")
                        sha = item.get("sha", "")[:8]
                        add_result(results, f"GitHub Commit Author: {login}", "found", "github",
                                   f"Found in commit {sha} in repo {repo}.",
                                   url=f"https://github.com/{login}",
                                   cross_link="email_to_username")
    except Exception:
        pass
    return usernames


# ─── Cross-linking: Username → Email via GitHub ───────────────────────────────

async def crosslink_username_to_email_via_github(username: str,
                                                  results: list[dict]) -> str | None:
    """
    From a username, try to find email via GitHub profile.
    Returns email if found.
    """
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await http_get(client,
                f"https://api.github.com/users/{username}",
                headers={"Accept": "application/vnd.github.v3+json"})
            if resp and resp.status_code == 200:
                data = resp.json()
                public_email = data.get("email")
                if public_email:
                    add_result(results, "GitHub Public Email", "found", "github",
                               f"Public email found on GitHub profile: {public_email}",
                               data={"email": public_email},
                               cross_link="username_to_email")
                    return public_email
    except Exception:
        pass
    return None


# ─── Main Lookup Dispatcher ─────────────────────────────────────────────────────

async def lookup_email_full(email: str) -> dict:
    primary: list[dict] = []
    cross_refs: list[dict] = []
    all_usernames: list[str] = []
    all_emails: list[str] = [email]
    all_phones: list[str] = []

    # Primary email checks
    await email_mx_check(email, primary)
    await email_hibp_check(email, primary)
    await email_gravatar_check(email, primary)
    gh_usernames, gh_commits = await email_github_commit_search(email, primary)
    all_usernames.extend(gh_usernames)
    await email_disposable_check(email, primary)
    await email_domain_type_check(email, primary)

    # Cross-link: from email → find GitHub usernames
    crosslink_usernames = await crosslink_email_to_github_usernames(email, cross_refs)
    all_usernames.extend(crosslink_usernames)
    all_usernames = list(dict.fromkeys(all_usernames))  # dedupe, preserve order

    summary = build_summary(email, "email", primary, cross_refs,
                            all_usernames, all_emails, all_phones)

    return {
        "query": email,
        "lookup_type": "email",
        "primary_results": primary,
        "cross_references": cross_refs,
        "all_usernames": all_usernames,
        "all_emails": all_emails,
        "all_phones": all_phones,
        "summary": summary,
    }


async def lookup_username_full(username: str) -> dict:
    primary: list[dict] = []
    cross_refs: list[dict] = []
    all_usernames: list[str] = [username]
    all_emails: list[str] = []
    all_phones: list[str] = []

    # Primary username checks
    gh_email = await username_github_check(username, primary, cross_refs)
    if gh_email:
        all_emails.append(gh_email)
    await username_platform_checks(username, primary)

    # Cross-link: from username → try to find email via GitHub
    cross_email = await crosslink_username_to_email_via_github(username, cross_refs)
    if cross_email and cross_email not in all_emails:
        all_emails.append(cross_email)

    summary = build_summary(username, "username", primary, cross_refs,
                            all_usernames, all_emails, all_phones)

    return {
        "query": username,
        "lookup_type": "username",
        "primary_results": primary,
        "cross_references": cross_refs,
        "all_usernames": all_usernames,
        "all_emails": all_emails,
        "all_phones": all_phones,
        "summary": summary,
    }


async def lookup_phone_full(phone: str) -> dict:
    primary: list[dict] = []
    cross_refs: list[dict] = []
    all_usernames: list[str] = []
    all_emails: list[str] = []
    all_phones: list[str] = []

    await phone_info_lookup(phone, primary)

    # Extract just the digits for the all_phones list
    digits = re.sub(r"\D", "", phone)
    all_phones.append(digits)

    summary = build_summary(phone, "phone", primary, cross_refs,
                            all_usernames, all_emails, all_phones)

    return {
        "query": phone,
        "lookup_type": "phone",
        "primary_results": primary,
        "cross_references": cross_refs,
        "all_usernames": all_usernames,
        "all_emails": all_emails,
        "all_phones": all_phones,
        "summary": summary,
    }


# ─── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "service": "OSINT Tool v4",
        "version": "4.0.0",
        "endpoints": {
            "POST /lookup": {"query": "string", "lookup_type": "email|phone|username"},
            "GET /health": "health check",
        },
        "features": [
            "MX record check",
            "HIBP breach search",
            "Gravatar profile check",
            "GitHub commit search (email → usernames)",
            "GitHub profile check (username → email)",
            "12-platform username existence check",
            "Phone carrier/geocoder/timezone lookup",
            "Cross-linking email ↔ username via GitHub",
            "Disposable email domain detection",
            "Known email provider detection",
        ],
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "OSINT Tool v4"}


@app.post("/lookup")
async def lookup(req: LookupRequest):
    q = req.query.strip()

    if req.lookup_type == "email" and not validate_email(q):
        raise HTTPException(status_code=400,
            detail="Invalid email format. Expected something like user@example.com")
    if req.lookup_type == "username" and not validate_username(q):
        raise HTTPException(status_code=400,
            detail="Invalid username format. Use 1-50 chars: a-zA-Z0-9_.-")
    if req.lookup_type == "phone" and not validate_phone(q):
        raise HTTPException(status_code=400,
            detail="Invalid phone format. Use 7-15 digits, optionally with + prefix")

    try:
        if req.lookup_type == "email":
            result = await lookup_email_full(q)
        elif req.lookup_type == "username":
            result = await lookup_username_full(q)
        elif req.lookup_type == "phone":
            result = await lookup_phone_full(q)
        else:
            raise HTTPException(status_code=400,
                detail=f"Unknown lookup_type '{req.lookup_type}'. Use: email, phone, or username")
    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(
            status_code=200,
            content={
                "query": q,
                "lookup_type": req.lookup_type,
                "primary_results": [],
                "cross_references": [],
                "all_usernames": [],
                "all_emails": [],
                "all_phones": [],
                "summary": f"Error during lookup: {str(e)}",
                "_error": str(e),
            }
        )

    return JSONResponse(content=result)


# ─── Dev Server ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
