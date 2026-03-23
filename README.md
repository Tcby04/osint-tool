# OSINT Auto-Research Tool

Personal OSINT lookup tool — find accounts associated with an email, username, or phone number.

## Tech Stack
- **Frontend:** Static HTML/CSS/JS → GitHub Pages
- **Backend:** FastAPI (Python) → Render
- **Tools:** holehe (email), sherlock (username), phoneinfoga (phone)

## Local Development

### Backend
```bash
cd osint-tool
pip install -r requirements.txt

# Install OSINT tools
pip install holehe
pip install sherlock-project
# phoneinfoga: see https://github.com/sundowndev/phoneinfoga

# Run server
uvicorn main:app --reload --port 8000
```

### Frontend
Open `index.html` in browser, or serve it:
```bash
python -m http.server 3000
```

For local dev, the frontend points to `http://localhost:8000` by default.

## Deploy

### Backend (Render)
1. Connect GitHub repo to Render
2. Use `render.yaml` or manual setup:
   - Build: `pip install -r requirements.txt`
   - Start: `uvicorn main:app --host 0.0.0.0 --port $PORT`
3. Note the Render URL (e.g., `https://osint-tool.onrender.com`)

### Frontend (GitHub Pages)
1. Push `index.html` to a GitHub repo
2. Enable GitHub Pages in repo settings
3. Update `API_URL` in `index.html` to your Render URL

## API

### POST /lookup
```json
{
  "query": "example@email.com",
  "lookup_type": "email"
}
```

Lookup types: `email`, `username`, `phone`

### GET /health
Health check endpoint.
