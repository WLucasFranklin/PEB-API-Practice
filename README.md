# PEB-API-Practice
PEB-API-Practice is a Flask-based web application developed to explore authentication, authorization, API security, and secure web application design. The project supports both GitHub OAuth and traditional username/password authentication, allowing users to create, manage, and revoke API keys. API keys are securely stored as hashes, web routes are protected through session-based authentication, and API endpoints require valid API-key authorization. Additional security enhancements include request logging, HTTPS support through Nginx and Flask-Talisman, secure password hashing, OAuth state validation, and protection against common web application vulnerabilities.

## Features
- GitHub OAuth authentication
- Traditional username/password authentication
- Secure API key generation and revocation
- SHA-256 hashing of stored API keys
- Password hashing with Werkzeug
- Session-based authentication for web routes
- API-key authentication for API endpoints
- Request logging (method, path, client IP, duration)
- SQLite backend for user and API key storage
- Optional HTTPS support using Nginx and Flask-Talisman
- HTTP-to-HTTPS redirection

## Setup

Install dependencies:

```bash
pip install -r requirements.txt
```


### Optional HTTPS / Nginx Reverse Proxy Setup
- Nginx listens on 80 and 443
- Port 80 redirects to 443
- Port 443 proxies to Gunicorn on 127.0.0.1:8000
- Flask-Talisman adds security headers/HSTS


```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    return 301 https://localhost$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name localhost;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

## Running the Application

Start the application with Gunicorn:

```bash
gunicorn -w 4 -b 127.0.0.1:8000 app:app
```

Then browse to:

```text
https://localhost
```

or, without the optional Nginx reverse proxy:

```text
http://localhost:8000
```
