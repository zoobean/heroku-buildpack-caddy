# Rails Caddyfile Example

This directory contains example configurations for using Caddy with a Rails application.

## Files

- `rails-caddyfile` - Complete Caddyfile for Rails with WAF, caching, and Cloudflare integration
- `waf-rules.json` - Example WAF rules for common web attacks
- `ip_blacklist.txt` - IP blacklist template
- `dns_blacklist.txt` - DNS/domain blacklist template

## Setup

1. Copy `rails-caddyfile` to `config/Caddyfile` in your Rails app
2. Create directory `config/caddy/` in your Rails app
3. Copy the WAF configuration files to `config/caddy/`:
   ```bash
   mkdir -p config/caddy
   cp examples/waf-rules.json config/caddy/rules.json
   cp examples/ip_blacklist.txt config/caddy/
   cp examples/dns_blacklist.txt config/caddy/
   ```

## Environment Variables

Set these environment variables for WAF UI authentication:

```bash
# WAF admin credentials
heroku config:set WAF_ADMIN_USER=admin
heroku config:set WAF_ADMIN_PASS_HASH='$2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNqnNPnfOKjchBVmpis8.6Rna'
```

Generate password hash with:
```bash
caddy hash-password --plaintext yourpassword
```

## Features

### Asset Caching
- `/assets/*` and `/packs/*` cached for 1 year (immutable)
- Other static files cached for 1 week
- Rails handles cache busting via asset fingerprinting

### Security
- **Cloudflare Integration**: Trusted proxies with 12h refresh
- **Local Network Trust**: Private IP ranges trusted
- **WAF Protection**: SQL injection, XSS, path traversal, command injection
- **Rate Limiting**: Login endpoints protected
- **Security Headers**: XSS protection, content type sniffing prevention

### WAF Rules
- SQL injection detection
- XSS attempt blocking
- Path traversal prevention
- Command injection blocking
- Login rate limiting (5 requests/minute)
- Malicious user agent blocking

### Monitoring
- WAF metrics at `/waf_metrics` (basic auth protected)
- JSON access logs to stdout (Heroku log aggregation)
- Custom error pages (404.html, 500.html)

## Procfile

Update your `Procfile`:

```
web: bundle exec puma -p 3000 & caddy run --config config/Caddyfile --adapter caddyfile
release: bundle exec rails db:migrate
```

## Rails Configuration

Ensure your Rails app is configured for reverse proxy:

```ruby
# config/application.rb
config.force_ssl = false # Let Caddy handle SSL
config.relative_url_root = nil

# Trust Caddy proxy
config.action_dispatch.trusted_proxies = ActionDispatch::RemoteIp::TRUSTED_PROXIES + ['127.0.0.1']
```

## Testing Locally

```bash
# Start Rails on port 3000
bundle exec rails server -p 3000

# In another terminal, start Caddy
caddy run --config config/Caddyfile --adapter caddyfile
```

## Customization

### Adding WAF Rules
Edit `config/caddy/rules.json` to add custom rules:

```json
{
  "id": "007",
  "description": "Block specific endpoint",
  "pattern": "/admin/secret",
  "action": "block",
  "severity": "high"
}
```

### IP Blacklisting
Add malicious IPs to `config/caddy/ip_blacklist.txt`:

```
192.168.1.100
10.0.0.0/8
```

### Domain Blacklisting
Add malicious domains to `config/caddy/dns_blacklist.txt`:

```
malicious-site.com
phishing-domain.net
```