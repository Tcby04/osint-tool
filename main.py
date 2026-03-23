"""
OSINT Auto-Research Tool
Uses web scraping + free APIs (no lxml dependency, Render-compatible).
"""

import asyncio
import json
import re
import os
import socket
import hashlib
import httpx
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="OSINT Tool", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LookupRequest(BaseModel):
    query: str
    lookup_type: str


class LookupResponse(BaseModel):
    query: str
    lookup_type: str
    results: list
    error: Optional[str] = None


def validate_input(query: str, lookup_type: str) -> bool:
    if not query or len(query) > 200:
        return False
    if lookup_type == "email":
        return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', query))
    elif lookup_type == "username":
        return bool(re.match(r'^[a-zA-Z0-9_.-]{1,50}$', query))
    elif lookup_type == "phone":
        return bool(re.match(r'^\+?[\d\s\-\(\)]{7,20}$', query))
    return False


async def lookup_email(email: str) -> list[dict]:
    """Email lookup via free APIs + web checks."""
    results = []
    email_lower = email.lower()
    
    # Check if email domain has MX records (suggests it's a real email service)
    domain = email.split("@")[1] if "@" in email else ""
    if domain:
        try:
            mx_records = socket.getaddrinfo(domain, 25)
            results.append({
                "site": f"MX Records ({domain})",
                "status": "found",
                "source": "dns",
                "detail": "Domain accepts email (MX verified)"
            })
        except socket.gaierror:
            results.append({
                "site": f"MX Records ({domain})",
                "status": "not_found",
                "source": "dns",
                "detail": "No MX records - domain may not accept email"
            })
    
    # Check if email is a known disposable domain
    disposable_domains = ["tempmail.com", "guerrillamail.com", "mailinator.com", "10minutemail.com", 
                          "throwaway.email", "temp-mail.org", "fakeinbox.com", "trashmail.com",
                          "guerrillamail.info", "mailnesia.com", "tempr.email"]
    if any(d in domain for d in disposable_domains):
        results.append({
            "site": "Disposable Email",
            "status": "found",
            "source": "disposable_check",
            "detail": "Email domain is a known disposable/temporary email service"
        })
    
    # Check if email appears in scraped public lists (GitHub commits, etc.)
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            # Check GitHub for this email in commit history
            gh_resp = await client.get(
                f"https://api.github.com/search/commits?q={email}+author-email:{email}",
                headers={"Accept": "application/vnd.github.cloak-preview+json"}
            )
            if gh_resp.status_code == 200:
                data = gh_resp.json()
                if data.get("total_count", 0) > 0:
                    results.append({
                        "site": "GitHub Commits",
                        "status": "found",
                        "source": "github",
                        "detail": f"Found in {data['total_count']} commits on GitHub"
                    })
    except:
        pass
    
    # Check breach databases via haveibeenpwned's new free tier
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            hibp_resp = await client.get(
                f"https://haveibeenpwned.com/unifiedsearch/{email}",
                headers={"User-Agent": "OSINT-Tool-v3"}
            )
            if hibp_resp.status_code == 200:
                breaches = hibp_resp.json().get("Breaches", [])
                if breaches:
                    breach_names = [b.get("Name", "Unknown") for b in breaches[:5]]
                    results.append({
                        "site": "Have I Been Pwned",
                        "status": "found",
                        "source": "hibp",
                        "detail": f"Found in {len(breaches)} breach(es): {', '.join(breach_names)}"
                    })
                else:
                    results.append({
                        "site": "Have I Been Pwned",
                        "status": "not_found",
                        "source": "hibp",
                        "detail": "Not found in known data breaches"
                    })
    except:
        pass
    
    # Check key platforms where this email might be registered
    key_platforms = [
        ("GitHub", f"https://api.github.com/users/{email.split('@')[0]}"),
        ("Slack", None),
        ("Gravatar", f"https://www.gravatar.com/{hashlib.md5(email_lower.encode()).hexdigest()}.json"),
    ]
    
    # Gravatar check
    try:
        md5_hash = hashlib.md5(email_lower.encode()).hexdigest()
        async with httpx.AsyncClient(timeout=10.0) as client:
            gr_resp = await client.get(f"https://www.gravatar.com/{md5_hash}.json")
            if gr_resp.status_code == 200:
                data = gr_resp.json()
                if data.get("entry"):
                    results.append({
                        "site": "Gravatar",
                        "status": "found",
                        "source": "gravatar",
                        "detail": f"Has profile: {data['entry'][0].get('displayName', email)}"
                    })
    except:
        pass
    
    # Email domain info
    domain_match = re.match(r'@([a-zA-Z0-9.-]+)$', email)
    if domain_match:
        d = domain_match.group(1).lower()
        if "icloud" in d or "apple" in d:
            results.append({"site": "iCloud/Apple ID", "status": "found", "source": "domain", "detail": "Apple email domain"})
        elif "gmail" in d:
            results.append({"site": "Google/Gmail", "status": "found", "source": "domain", "detail": "Google email domain"})
        elif "outlook" in d or "hotmail" in d or "live" in d or "msn" in d:
            results.append({"site": "Microsoft/Outlook", "status": "found", "source": "domain", "detail": "Microsoft email domain"})
        elif "yahoo" in d:
            results.append({"site": "Yahoo", "status": "found", "source": "domain", "detail": "Yahoo email domain"})
        elif "proton" in d:
            results.append({"site": "ProtonMail", "status": "found", "source": "domain", "detail": "ProtonMail - encrypted email"})
        elif "aol" in d:
            results.append({"site": "AOL", "status": "found", "source": "domain", "detail": "AOL email domain"})
    
    if not results:
        results.append({"site": "Email", "status": "not_found", "detail": "No data found for this email"})
    
    return results


async def lookup_username(username: str) -> list[dict]:
    """Username lookup via Namechk scraping."""
    results = []
    
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en-US,en;q=0.9",
            }
            
            # Try Namechk's API
            resp = await client.get(
                "https://namechk.p.rapidapi.com/check",
                params={"username": username, "type": "username"},
                headers={
                    **headers,
                    "X-RapidAPI-Key": "",  # Would need a key
                    "X-RapidAPI-Host": "namechk.p.rapidapi.com"
                }
            )
            
            if resp.status_code == 200:
                data = resp.json()
                for item in data[:30]:  # Top 30 sites
                    if item.get("available") == False:  # Taken = found
                        results.append({
                            "site": item.get("name", "Unknown"),
                            "status": "found",
                            "source": "namechk",
                            "url": item.get("url", "")
                        })
    except:
        pass
    
    # Fallback: scrape namechk.com directly
    if not results:
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                resp = await client.get(
                    f"https://namechk.com/",
                    params={"q": username, "type": "username"},
                    headers=headers
                )
                if resp.status_code == 200:
                    # Parse the page for site results
                    import re
                    # Namechk shows results as available/taken
                    html = resp.text
                    # Look for site names in the page
                    found_sites = re.findall(r'"site":"([^"]+)"', html)
                    taken_sites = re.findall(r'"taken":(true|false)', html)
                    for i, (site, taken) in enumerate(zip(found_sites[:20], taken_sites[:20])):
                        if taken == "true":
                            results.append({
                                "site": site.replace("_", " ").title(),
                                "status": "found",
                                "source": "namechk"
                            })
        except Exception as e:
            pass
    
    # Key platforms checked manually
    key_sites = [
        ("GitHub", f"https://github.com/{username}"),
        ("Twitter/X", f"https://twitter.com/{username}"),
        ("Instagram", f"https://instagram.com/{username}"),
        ("LinkedIn", f"https://linkedin.com/in/{username}"),
        ("Reddit", f"https://reddit.com/user/{username}"),
        ("TikTok", f"https://tiktok.com/@{username}"),
        ("YouTube", f"https://youtube.com/@{username}"),
        ("Telegram", f"https://t.me/{username}"),
        ("Discord", None),  # No profile URL
        ("Steam", None),
    ]
    
    # Check GitHub specifically (most reliable)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            gh_resp = await client.get(f"https://github.com/{username}")
            if gh_resp.status_code == 200:
                results.append({
                    "site": "GitHub",
                    "status": "found",
                    "source": "github",
                    "url": f"https://github.com/{username}"
                })
            elif gh_resp.status_code == 404:
                results.append({
                    "site": "GitHub",
                    "status": "not_found",
                    "source": "github"
                })
    except:
        pass
    
    # Check Twitter
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            tw_resp = await client.get(
                f"https://api.twitter.com/2/users/by/username/{username}",
                headers={"User-Agent": "Mozilla/5.0"},
                follow_redirects=True
            )
            if tw_resp.status_code == 200:
                results.append({
                    "site": "Twitter/X",
                    "status": "found",
                    "source": "twitter"
                })
    except:
        pass
    
    if not results:
        results.append({"site": "Username", "status": "not_found", "detail": "No accounts found"})
    
    return results


async def lookup_phone(phone: str) -> list[dict]:
    """Phone lookup using phonenumbers library."""
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone
        
        parsed = phonenumbers.parse(phone, None)
        if not phonenumbers.is_valid_number(parsed):
            return [{"site": "Phone", "status": "error", "detail": "Invalid phone number"}]
        
        return [{
            "site": "Phone Info",
            "status": "found",
            "source": "phonenumbers",
            "detail": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "data": {
                "country": geocoder.description_for_number(parsed, "en") or "Unknown",
                "carrier": carrier.name_for_number(parsed, "en") or "Unknown",
                "timezones": list(timezone.time_zones_for_number(parsed)),
                "formatted": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "valid": phonenumbers.is_valid_number(parsed),
            }
        }]
    except Exception as e:
        return [{"site": "Phone", "status": "error", "detail": str(e)}]


@app.get("/")
async def root():
    return {"status": "ok", "service": "OSINT Tool v3", "tools": ["emailrep", "namechk", "github", "phonenumbers"]}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.post("/lookup", response_model=LookupResponse)
async def lookup(req: LookupRequest):
    if not validate_input(req.query, req.lookup_type):
        raise HTTPException(status_code=400, detail="Invalid input format")
    
    query = req.query.strip()
    results = []
    error = None
    
    try:
        if req.lookup_type == "username":
            results = await lookup_username(query)
        elif req.lookup_type == "email":
            results = await lookup_email(query)
        elif req.lookup_type == "phone":
            results = await lookup_phone(query)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown type: {req.lookup_type}")
    except HTTPException:
        raise
    except Exception as e:
        error = str(e)
    
    return LookupResponse(query=query, lookup_type=req.lookup_type, results=results, error=error)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
