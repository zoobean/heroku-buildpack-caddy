# Heroku Buildpack for Caddy

A Heroku buildpack for deploying [Caddy](https://caddyserver.com/) web server applications with built-in security plugins. Works standalone or alongside Rails applications.

## Features

- **Cross-platform support**: Automatically detects ARM64 and x64 architectures
- **Rails integration**: Works as a multi-buildpack alongside Rails for reverse proxy/load balancing
- **Security plugins included**:
  - [caddy-cloudflare-ip](https://github.com/WeidiDeng/caddy-cloudflare-ip) - Real client IP detection behind Cloudflare
  - [caddy-waf](https://github.com/fabriziosalmi/caddy-waf) - Web Application Firewall middleware
- **Latest Caddy version**: Built with Go 1.24.5 and Caddy v2.10.0

## Usage

### Standalone Caddy App

1. Create a `Caddyfile` in your project root:

```caddyfile
:$PORT

root * public
file_server

# Enable Cloudflare IP detection
trusted_proxies cloudflare {
    interval 12h
}

# Enable WAF protection (optional)
waf {
    ruleset_path "/path/to/rules"
}
```

2. Add the buildpack to your Heroku app:

```bash
heroku buildpacks:add https://github.com/zoobean/heroku-buildpack-caddy
```

3. Deploy:

```bash
git push heroku main
```

### Rails App with Caddy

For Rails applications, use Caddy as a reverse proxy or load balancer:

1. Add both buildpacks to your Rails app:

```bash
# Add Ruby buildpack first
heroku buildpacks:add heroku/ruby
# Add Caddy buildpack second
heroku buildpacks:add https://github.com/zoobean/heroku-buildpack-caddy
```

2. Create a `Caddyfile` in one of these locations:
   - `config/Caddyfile` (recommended for Rails)
   - `config/caddy/Caddyfile`
   - `./Caddyfile` (project root)

See the complete example in [`examples/rails-caddyfile`](examples/rails-caddyfile) with:
- Asset caching (1 year for `/assets/*`, 1 week for others)
- Cloudflare + local network trusted proxies  
- WAF with default rules and basic auth protected UI
- Security headers and error handling

Basic Rails `config/Caddyfile`:

```caddyfile
:$PORT

# Trusted proxies: Cloudflare + private networks
trusted_proxies cloudflare { interval 12h }
trusted_proxies static private_ranges

# WAF with basic configuration
route {
    waf {
        rule_file config/caddy/rules.json
        metrics_endpoint /waf_metrics
    }
}

# Cache Rails assets
route /assets/* {
    header Cache-Control "public, max-age=31536000, immutable"
    root * public
    try_files {path} @rails
    file_server
}

# Protected WAF metrics (basic auth from env vars)
route /waf_metrics {
    basicauth {
        {$WAF_ADMIN_USER:admin} {$WAF_ADMIN_PASS_HASH}
    }
    reverse_proxy localhost:3000
}

# Main Rails app
route @rails {
    reverse_proxy localhost:3000 {
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
}

# Heroku logging to stdout
log {
    output stdout
    format json
}
```

3. Update your `Procfile` to run both Rails and Caddy:

```
web: bundle exec puma -p 3000 & caddy run --config config/Caddyfile --adapter caddyfile
release: bundle exec rails db:migrate
```

4. Deploy:

```bash
git push heroku main
```

### Detection

The buildpack will detect your app as a Caddy app if any of these files exist:

- `Caddyfile` (project root)
- `caddy.json` (project root)
- `config/Caddyfile` (Rails apps)
- `config/caddy/Caddyfile` (Rails apps)
- `Procfile` containing "caddy"
- Rails app (`Gemfile` present) with Caddy config

### Configuration

The buildpack automatically:

- Detects your platform architecture (ARM64/x64)
- Downloads the appropriate Caddy binary from GitHub releases
- Installs Caddy binary with security plugins
- Adds Caddy to your app's PATH
- For standalone apps: Sets up a default web process type
- For Rails apps: Leaves process management to Rails buildpack

#### Version Control

By default, the buildpack downloads the latest release. To specify a version:

```bash
heroku config:set CADDY_VERSION=v1.0.0
```

The buildpack will download binaries from: `https://github.com/zoobean/heroku-buildpack-caddy/releases/download/{version}/caddy-linux-{arch}`

**Standalone apps** get a default web process. Override with a `Procfile`:

```
web: caddy run --config caddy.json --adapter json
```

**Rails apps** must define processes in `Procfile` to run both Rails and Caddy:

```
web: bundle exec puma -p 3000 & caddy run --config config/Caddyfile
```

## Development

### Building and Releasing

1. Build Caddy binaries locally:

```bash
./build.sh
```

This creates binaries in `dist/` for all supported platforms.

2. Create a GitHub release with the binaries:

```bash
# Tag and push
git tag v1.0.0
git push origin v1.0.0

# Create release and upload binaries
gh release create v1.0.0 dist/* --title "Release v1.0.0" --notes "Caddy v2.10.0 with security plugins"
```

The buildpack will automatically download from the latest release.

### Testing the Buildpack

You can test the buildpack locally using the Heroku CLI:

```bash
# Create a test app with a Caddyfile
mkdir test-app && cd test-app
echo ":8080\nrespond \"Hello from Caddy!\"" > Caddyfile

# Test the buildpack
heroku buildpacks:test ../heroku-buildpack-caddy
```

## Supported Stacks

- heroku-20
- heroku-22  
- heroku-24

## License

MIT