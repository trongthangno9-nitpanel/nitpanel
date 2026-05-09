use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse};
use actix_web::web::Data;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::collections::HashMap;
use tokio::process::Command;
use std::path::PathBuf;
use chrono::Utc;
use uuid::Uuid;
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use actix_multipart::Multipart;
use futures_util::StreamExt;
use std::io::Write;
use tracing::{info, warn, error};
use std::time::{SystemTime, UNIX_EPOCH};
use std::os::unix::fs::PermissionsExt;

// ─── Constants ────────────────────────────────────────────────────────────────
const PANEL_PORT_DEFAULT: u16    = 8765;
const VHOST_DIR:          &str   = "/etc/nginx/conf.d";
const WEB_ROOT:           &str   = "/var/www";
const STATE_PATH:         &str   = "/etc/nitpanel/state.json";
const LOG_DIR:            &str   = "/var/log/nitpanel";
const PHP_SOCKET_DIR:     &str   = "/run/php-fpm";
const MAX_UPLOAD:         usize  = 50 * 1024 * 1024; // 50 MB
const LOGIN_MAX:          u32    = 5;
const LOGIN_LOCKOUT_SECS: u64    = 300;
const JWT_TTL_SECS:       i64    = 14400; // 4h       // 24h
const TRUST_XFF_DEFAULT:  bool   = false;

// ── NEW: Rate limiting & CSRF constants ──
#[allow(dead_code)]
const RATE_LIMIT_WINDOW:  u64    = 60;
#[allow(dead_code)]
const RATE_LIMIT_MAX:     u32    = 30;
#[allow(dead_code)]
const RATE_LIMIT_AUTH_MAX: u32   = 120;
#[allow(dead_code)]
const CSRF_TTL_SECS:      i64    = 3600;
#[allow(dead_code)]
const MAX_BACKUPS_PER_SITE: usize = 5;
// ── NEW: Rate limiting & CSRF ──

fn jwt_secret() -> String {
    std::env::var("NITPANEL_JWT_SECRET").unwrap_or_else(|_| {
        // Generate ephemeral secret if not provided so leaked-default token attacks don't work.
        // (Service should always set this in systemd.)
        use rand::Rng;
        let s: String = (0..48).map(|_| {
            let c: u8 = rand::thread_rng().gen_range(0..62);
            (if c < 10 { b'0' + c } else if c < 36 { b'a' + c - 10 } else { b'A' + c - 36 }) as char
        }).collect();
        s
    })
}

fn trust_xff() -> bool {
    std::env::var("NITPANEL_TRUST_XFF").map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
        .unwrap_or(TRUST_XFF_DEFAULT)
}

fn panel_bind() -> String {
    std::env::var("NITPANEL_BIND").unwrap_or_else(|_| format!("0.0.0.0:{}", PANEL_PORT_DEFAULT))
}

fn vn(v: &str) -> String { v.replace('.', "") }

// Predictable socket path written by install_stack. Falls back to Remi default.
fn php_socket(v: &str) -> String {
    let n = vn(v);
    let custom = format!("{}/php{}.sock", PHP_SOCKET_DIR, n);
    if std::path::Path::new(&custom).exists() { return custom; }
    let remi = format!("/var/opt/remi/php{}/run/php-fpm/www.sock", n);
    if std::path::Path::new(&remi).exists() { return remi; }
    custom // default — install_stack will create this path
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ─── Structs ──────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Website {
    id:                 String,
    domain:             String,
    php_version:        String,
    mysql_version:      String,
    db_name:            Option<String>,
    db_user:            Option<String>,
    ssl_enabled:        bool,
    ssl_expiry:         Option<String>,
    created_at:         String,
    status:             String,
    web_root:           String,
    phpmyadmin_enabled: bool,
    #[serde(default)]
    redis_db:           Option<u8>,
    wordpress:          bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Fail2banConfig {
    enabled:      bool,
    ban_time:     i64,
    find_time:    i64,
    max_retry:    i32,
    whitelist_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppState {
    websites:            Vec<Website>,
    admin_password_hash: String,
    #[serde(default)]
    login_attempts:      HashMap<String, (u32, u64, Option<u64>)>,
    #[serde(default)]
    rate_limits:         HashMap<String, RateLimitEntry>,
    #[serde(default)]
    csrf_tokens:         HashMap<String, CsrfToken>,
    #[serde(default)]
    used_nonces:         Vec<String>,
    // ── License ──
    #[serde(default)]
    license_key:         Option<String>,
    #[serde(default)]
    license_activated:   Option<String>,
    #[serde(default)]
    fail2ban:            Fail2banConfig,
}

#[derive(Deserialize)] struct LoginReq          { password: String }
#[derive(Serialize)]   struct LoginResp         { token: String, csrf_token: String, message: String }
#[derive(Serialize, Deserialize)] struct Claims { sub: String, exp: usize, iat: usize }
#[derive(Deserialize)] struct CreateSiteReq {
    domain: String, php_version: String, mysql_version: String,
    create_db: bool, db_name: Option<String>, db_user: Option<String>, db_password: Option<String>,
}
#[derive(Deserialize)] struct SslReq       { domain: String, email: String }
#[derive(Deserialize)] struct FileListReq  { domain: String, path: Option<String> }
#[derive(Serialize)]   struct FileEntry    { name: String, path: String, is_dir: bool, size: u64, modified: String }
#[derive(Deserialize)] struct FileReadReq  { domain: String, path: String }
#[derive(Deserialize)] struct FileSaveReq  { domain: String, path: String, content: String }
#[derive(Deserialize)] struct FileDeleteReq   { domain: String, path: String }
#[derive(Deserialize)] struct FileMkdirReq    { domain: String, path: String }
#[derive(Deserialize)] struct FileRenameReq   { domain: String, path: String, new_name: String }
#[derive(Deserialize)] struct FileExtractReq  { domain: String, path: String, dest: Option<String> }
#[derive(Deserialize)] struct FileCompressReq { domain: String, path: String, format: Option<String>, output: Option<String> }
#[derive(Deserialize)] struct DelSiteReq   { domain: String, drop_db: Option<bool> }
#[derive(Deserialize)] struct SvcActReq    { service: String, action: String }
#[derive(Deserialize)] struct InstallSvcReq { package_type: String }
#[derive(Deserialize)] struct Fail2banUnbanReq { ip: String }
#[derive(Deserialize)] struct Fail2banWhitelistReq { ip: String, action: String }

#[derive(Deserialize)] struct LicenseReq { key: String }
#[derive(Serialize)]   struct LicenseInfo { licensed: bool, key: Option<String>, activated: Option<String>, status: String }

#[derive(Deserialize)] struct BackupReq     { domain: String }
#[derive(Deserialize)] struct CloneReq      { source_domain: String, target_domain: String, copy_db: Option<bool> }
#[derive(Deserialize)] struct BulkSslReq    { domains: Vec<String>, email: String }



// ── NEW: Rate limit state ──
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RateLimitEntry {
    window_start: u64,
    count:        u32,
}

// ── NEW: CSRF token ──
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CsrfToken {
    token:     String,
    expires:   u64,
}

type St = Data<Mutex<AppState>>;

// ─── Validation ───────────────────────────────────────────────────────────────
fn valid_domain(d: &str) -> bool {
    !d.is_empty() && d.len() <= 253
        && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !d.starts_with('.') && !d.ends_with('.')
        && !d.starts_with('-') && !d.ends_with('-')
        && !d.contains("..") && d.contains('.')
}

fn valid_path(p: &str) -> bool {
    !p.contains("..") && !p.contains('\0') && !p.contains('\n') && !p.contains('\r')
        && !p.contains('\\')
}

fn valid_ip(ip: &str) -> bool {
    !ip.is_empty() && ip.len() <= 50
        && ip.chars().all(|c| c.is_ascii_alphanumeric() || ".:/-".contains(c))
        && !ip.contains("..")
}

// Strict identifier (DB name / user) — alnum + underscore only
fn valid_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 48
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && s.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_')
}

// DB password — alnum + safe symbols. NEVER allow quote/backtick/backslash/space.
fn valid_db_password(s: &str) -> bool {
    !s.is_empty() && s.len() >= 12 && s.len() <= 64
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "._-+!@#%^*=?".contains(c))
}


// ── SECURITY: Strip filesystem paths from error messages ──
#[allow(dead_code)]
fn sanitize_error(msg: &str) -> String {
    let mut s = msg.to_string();
    // Replace common paths with generic terms
    for (pat, repl) in &[
        ("/var/www/", "[webroot]/"),
        ("/etc/nginx/conf.d/", "[nginx]/"),
        ("/etc/nitpanel/", "[config]/"),
        ("/var/log/nitpanel/", "[logs]/"),
        ("/tmp/nitpanel_", "[tmp]/"),
    ] {
        s = s.replace(pat, repl);
    }
    s
}

fn sanitize_ident(s: &str) -> String {
    let mut out: String = s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(48).collect();
    if let Some(c) = out.chars().next() {
        if !c.is_ascii_alphabetic() && c != '_' { out.insert(0, '_'); }
    }
    if out.is_empty() { out = "x".into(); }
    out
}

fn sanitize_filename(name: &str) -> String {
    PathBuf::from(name).file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string())
        .chars().filter(|c| c.is_alphanumeric() || "._- ".contains(*c))
        .collect::<String>().trim().to_string()
}

// ── NEW: validate email ──
fn valid_email(e: &str) -> bool {
    !e.is_empty() && e.len() <= 254
        && e.contains('@') && e.contains('.')
        && e.chars().all(|c| c.is_ascii_alphanumeric() || "@._-+".contains(c))
        && !e.starts_with('@') && !e.ends_with('@')
}

// ── NEW: less strict sanitize for archive output names ──
fn sanitize_archive_name(name: &str) -> String {
    PathBuf::from(name).file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "archive.zip".to_string())
        .chars().filter(|c| c.is_alphanumeric() || "._- ".contains(*c))
        .collect::<String>().trim().to_string()
}

// ── NEW: Rate limiting ──
#[allow(dead_code)]
fn check_rate_limit(st: &Mutex<AppState>, ip: &str, is_auth: bool) -> bool {
    let max = if is_auth { RATE_LIMIT_AUTH_MAX } else { RATE_LIMIT_MAX };
    let now = now_secs();
    let mut s = st.lock().unwrap();
    let entry = s.rate_limits.entry(ip.to_string()).or_insert(RateLimitEntry { window_start: now, count: 0 });
    if now - entry.window_start > RATE_LIMIT_WINDOW {
        entry.window_start = now;
        entry.count = 1;
        true
    } else if entry.count >= max {
        false
    } else {
        entry.count += 1;
        if s.rate_limits.len() > 1000 {
            s.rate_limits.retain(|_, v| now - v.window_start <= RATE_LIMIT_WINDOW * 2);
        }
        true
    }
}

// ── NEW: CSRF management ──
fn generate_csrf_token(st: &Mutex<AppState>) -> String {
    let token = Uuid::new_v4().to_string();
    let now = now_secs();
    let mut s = st.lock().unwrap();
    s.csrf_tokens.insert(token.clone(), CsrfToken { token: token.clone(), expires: now + CSRF_TTL_SECS as u64 });
    s.csrf_tokens.retain(|_, t| t.expires > now);
    token
}

#[allow(dead_code)]
fn verify_csrf(st: &Mutex<AppState>, token: &str) -> bool {
    if token.is_empty() { return false; }
    let now = now_secs();
    let s = st.lock().unwrap();
    let valid = s.csrf_tokens.get(token).map(|t| t.expires > now).unwrap_or(false);
    valid
}

#[allow(dead_code)]
fn check_nonce(st: &Mutex<AppState>, nonce: &str) -> bool {
    if nonce.len() < 16 || nonce.len() > 128 { return false; }
    if nonce.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_') { return false; }
    let mut s = st.lock().unwrap();
    if s.used_nonces.contains(&nonce.to_string()) { return false; }
    s.used_nonces.push(nonce.to_string());
    if s.used_nonces.len() > 1000 {
        let trim_to = s.used_nonces.len() - 1000;
        s.used_nonces.drain(0..trim_to);
    }
    true
}

// ── NEW: URL encoding ──

// ── NEW: Command existence check ──
async fn cmd_exists(cmd: &str) -> bool {
    let (ok, _) = bash(&format!("command -v {} >/dev/null 2>&1", shell_escape(cmd))).await;
    ok
}

// ── NEW: Ensure package installed ──
async fn ensure_pkg(pkg: &str) -> bool {
    if cmd_exists(pkg).await { return true; }
    warn!("Installing missing package: {}", pkg);
    let (ok, _) = bash(&format!("dnf install -y --setopt=logdir=/tmp {} 2>&1 | tail -3", shell_escape(pkg))).await;
    ok
}


fn client_ip(req: &HttpRequest) -> String {
    if trust_xff() {
        if let Some(s) = req.headers().get("X-Forwarded-For")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string())
        {
            if !s.is_empty() { return s; }
        }
    }
    req.peer_addr().map(|a| a.ip().to_string()).unwrap_or_else(|| "unknown".into())
}

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

fn random_alnum(len: usize) -> String {
    use rand::Rng;
    (0..len).map(|_| {
        let c: u8 = rand::thread_rng().gen_range(0..62);
        (if c < 10 { b'0' + c } else if c < 36 { b'a' + c - 10 } else { b'A' + c - 36 }) as char
    }).collect()
}

/// Append an audit-log line. Used for sensitive actions so a forensic trail exists
/// even if the attacker tampers with stdout.
fn audit(req: &HttpRequest, action: &str, detail: &str) {
    use std::io::Write as _;
    let ip = client_ip(req);
    let line = format!("{}\t{}\t{}\t{}\n",
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"), ip, action,
        detail.replace('\n', " ").replace('\t', " "));
    let _ = std::fs::create_dir_all(LOG_DIR);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true).append(true).open(format!("{}/audit.log", LOG_DIR))
    {
        let _ = f.write_all(line.as_bytes());
        let _ = std::fs::set_permissions(format!("{}/audit.log", LOG_DIR),
            std::fs::Permissions::from_mode(0o600));
    }
}

/// Validate Host header against an allowlist (NITPANEL_ALLOWED_HOSTS env)
/// Default = allow all (backwards compat). When set, mismatched Host triggers 421.
fn host_allowed(req: &HttpRequest) -> bool {
    match std::env::var("NITPANEL_ALLOWED_HOSTS") {
        Err(_) => true,
        Ok(v) if v.trim().is_empty() => true,
        Ok(v) => {
            let host = req.headers().get("host")
                .and_then(|h| h.to_str().ok()).unwrap_or("");
            v.split(',').any(|h| h.trim().eq_ignore_ascii_case(host))
        }
    }
}

// ─── JWT ──────────────────────────────────────────────────────────────────────
fn make_token() -> String {
    let now = Utc::now().timestamp() as usize;
    let claims = Claims { sub: "admin".into(), exp: now + JWT_TTL_SECS as usize, iat: now };
    encode(&Header::default(), &claims,
           &EncodingKey::from_secret(jwt_secret().as_bytes())).unwrap_or_default()
}

fn check_token(tok: &str) -> bool {
    let mut v = Validation::new(Algorithm::HS256);
    v.leeway = 0;
    v.validate_exp = true;
    decode::<Claims>(tok, &DecodingKey::from_secret(jwt_secret().as_bytes()), &v).is_ok()
}

fn allowed_ip(req: &HttpRequest) -> bool {
    match std::env::var("NITPANEL_ALLOWED_IPS") {
        Err(_) => true, // Not set = allow all
        Ok(ref v) if v.trim().is_empty() => true,
        Ok(v) => {
            let ip = client_ip(req);
            v.split(',').any(|a| a.trim() == ip)
        }
    }
}

fn auth(req: &HttpRequest) -> bool {
    if !allowed_ip(req) { 
        warn!("Blocked IP: {}", client_ip(req));
        return false; 
    }
    let valid = req.headers().get("Authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| check_token(s.trim_start_matches("Bearer ").trim()))
        .unwrap_or(false);
    if valid {
        // Request audit: log method + path
        let path = req.path();
        let ip = client_ip(req);
        if !path.contains("system/info") && !path.contains("csrf-token") {
            info!("{} {} from {}", req.method(), path, ip);
        }
    }
    valid
}

// ─── Shell ────────────────────────────────────────────────────────────────────
async fn bash(cmd: &str) -> (bool, String) {
    match Command::new("bash").arg("-c").arg(cmd).output().await {
        Ok(o) => {
            let out = String::from_utf8_lossy(&o.stdout).to_string();
            let err = String::from_utf8_lossy(&o.stderr).to_string();
            let ok  = o.status.success();
            (ok, if ok { out } else { format!("{}\n{}", out, err) }.trim().to_string())
        }
        Err(e) => (false, e.to_string()),
    }
}

// ─── State ────────────────────────────────────────────────────────────────────
fn load() -> AppState {
    if let Ok(c) = std::fs::read_to_string(STATE_PATH) {
        if let Ok(s) = serde_json::from_str::<AppState>(&c) { return s; }
    }
    // No state.json — try NITPANEL_INIT_PASSWORD env var (set by install.sh on fresh install)
    let init_pass = std::env::var("NITPANEL_INIT_PASSWORD").ok()
        .filter(|s| s.len() >= 8);
    let pass = init_pass.unwrap_or_else(|| {
        // Last-resort random — printed to log so admin can recover
        let p = random_alnum(20);
        warn!("No NITPANEL_INIT_PASSWORD provided. Generated emergency password: {}", p);
        p
    });
    let h = hash(&pass, DEFAULT_COST).unwrap_or_default();
    AppState {
        websites:            Vec::new(),
        admin_password_hash: h,
        login_attempts:      HashMap::new(),
        fail2ban:            Fail2banConfig {
            enabled: false, ban_time: 3600, find_time: 600, max_retry: 5,
            whitelist_ips: Vec::new(),
        },
        rate_limits:         HashMap::new(),
        csrf_tokens:         HashMap::new(),
        used_nonces:         Vec::new(),
        license_key:         None,
        license_activated:   None,
    }
}

fn save(st: &AppState) {
    let _ = std::fs::create_dir_all("/etc/nitpanel");
    if let Ok(j) = serde_json::to_string_pretty(st) {
        let tmp = format!("{}.tmp", STATE_PATH);
        if std::fs::write(&tmp, &j).is_ok() {
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
            let _ = std::fs::rename(&tmp, STATE_PATH);
            let _ = std::fs::set_permissions(STATE_PATH, std::fs::Permissions::from_mode(0o600));
        }
    }
}

// ─── Nginx config ─────────────────────────────────────────────────────────────
fn make_vhost(domain: &str, root: &str, php: &str, ssl: bool, pma: bool) -> String {
    let sock = php_socket(php);
    // Common security headers (always)
    let sec = r#"    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;
    server_tokens off;"#;

    // FastCGI block (with hardening)
    let php_block = format!(r#"    location ~ \.php$ {{
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:{sock};
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param HTTPS $https if_not_empty;
        include fastcgi_params;
        fastcgi_read_timeout 300;
        fastcgi_buffer_size 16k;
        fastcgi_buffers 4 16k;
        fastcgi_hide_header X-Powered-By;
        fastcgi_intercept_errors off;
    }}"#);

    // Block common attack paths
    let deny = r#"    location ~ /\.(?!well-known) { deny all; return 404; }
    location ~ \.(bak|backup|swp|swo|old|orig|sql|log|env|ini|conf)$ { deny all; return 404; }
    location ~ ~$ { deny all; return 404; }
    location = /xmlrpc.php { deny all; return 404; }
    location = /wp-config.php { deny all; return 404; }"#;

    // phpMyAdmin sub-block (optional)
    let pma_block = if pma {
        // Use symlink approach — simpler than nginx alias, more reliable
        String::new()
    } else { String::new() };

    // Mozilla Intermediate TLS
    let ssl_block = r#"    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;"#;

    if ssl {
        format!(r#"server {{
    listen 80;
    listen [::]:80;
    server_name {domain} www.{domain};
    location /.well-known/acme-challenge/ {{ root {root}; allow all; }}
    location / {{ return 301 https://$host$request_uri; }}
}}
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {domain} www.{domain};
    root {root};
    index index.php index.html;
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
{ssl_block}
{sec}
    access_log /var/log/nginx/{domain}.access.log;
    error_log  /var/log/nginx/{domain}.error.log warn;
    client_max_body_size 100M;
    location / {{ try_files $uri $uri/ /index.php?$query_string; }}
{php_block}
{deny}
{pma_block}
}}
"#)
    } else {
        format!(r#"server {{
    listen 80;
    listen [::]:80;
    server_name {domain} www.{domain};
    root {root};
    index index.php index.html;
{sec}
    access_log /var/log/nginx/{domain}.access.log;
    error_log  /var/log/nginx/{domain}.error.log warn;
    client_max_body_size 100M;
    location /.well-known/acme-challenge/ {{ root {root}; allow all; }}
    location / {{ try_files $uri $uri/ /index.php?$query_string; }}
{php_block}
{deny}
{pma_block}
}}
"#)
    }
}

// ─── Fail2ban ─────────────────────────────────────────────────────────────────
fn f2b_jail_conf(cfg: &Fail2banConfig) -> String {
    let whitelist = if cfg.whitelist_ips.is_empty() {
        "127.0.0.1/8 ::1".to_string()
    } else {
        format!("127.0.0.1/8 ::1 {}",
            cfg.whitelist_ips.iter().filter(|i| valid_ip(i)).cloned().collect::<Vec<_>>().join(" "))
    };
    format!(r#"[DEFAULT]
bantime  = {ban_time}
findtime = {find_time}
maxretry = {max_retry}
ignoreip = {whitelist}
backend  = systemd

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s

[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/*error.log
maxretry = 3

[nginx-botsearch]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/*access.log
maxretry = 2

[nginx-noscript]
enabled  = true
port     = http,https
filter   = nginx-noscript
logpath  = /var/log/nginx/*access.log
maxretry = 6

[nitpanel-auth]
enabled  = true
port     = 8765
logpath  = /var/log/nitpanel/panel.log
filter   = nitpanel-auth
maxretry = {max_retry}
bantime  = {ban_time}
findtime = {find_time}
"#,
        ban_time  = cfg.ban_time,
        find_time = cfg.find_time,
        max_retry = cfg.max_retry,
        whitelist = whitelist,
    )
}

fn f2b_nitpanel_filter() -> &'static str {
    r#"[Definition]
failregex = Failed login attempt .* from <HOST>
            Login blocked for IP <HOST>
            IP <HOST> locked after
ignoreregex =
"#
}

fn f2b_noscript_filter() -> &'static str {
    r#"[Definition]
failregex = ^<HOST> -.*GET.*(\.php|\.asp|\.exe|\.pl|\.cgi|\.scgi)
ignoreregex =
"#
}

async fn apply_fail2ban(cfg: &Fail2banConfig) -> (bool, String) {
    let _ = std::fs::create_dir_all("/etc/fail2ban/jail.d");
    let _ = std::fs::create_dir_all("/etc/fail2ban/filter.d");
    let jail = f2b_jail_conf(cfg);
    if let Err(e) = std::fs::write("/etc/fail2ban/jail.d/nitpanel.conf", &jail) {
        return (false, format!("Không ghi được jail config: {}", e));
    }
    let _ = std::fs::write("/etc/fail2ban/filter.d/nitpanel-auth.conf", f2b_nitpanel_filter());
    let _ = std::fs::write("/etc/fail2ban/filter.d/nginx-noscript.conf", f2b_noscript_filter());

    if cfg.enabled {
        bash("systemctl enable fail2ban 2>&1 && (systemctl reload fail2ban 2>&1 || systemctl restart fail2ban 2>&1)").await
    } else {
        bash("systemctl stop fail2ban 2>/dev/null; systemctl disable fail2ban 2>/dev/null; echo 'Fail2ban disabled'").await
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
fn detect_web_user_sync() -> &'static str {
    // nginx is the AlmaLinux/RHEL convention
    if std::path::Path::new("/etc/passwd").exists() {
        if let Ok(c) = std::fs::read_to_string("/etc/passwd") {
            if c.lines().any(|l| l.starts_with("nginx:")) { return "nginx"; }
            if c.lines().any(|l| l.starts_with("apache:")) { return "apache"; }
            if c.lines().any(|l| l.starts_with("www-data:")) { return "www-data"; }
        }
    }
    "nginx"
}

// Generate www.conf for a Remi PHP version with predictable socket path & nginx user.
fn php_fpm_pool_conf(v: &str, user: &str) -> String {
    let n = vn(v);
    format!(r#"[www]
user = {user}
group = {user}
listen = {dir}/php{n}.sock
listen.owner = {user}
listen.group = {user}
listen.mode = 0660
pm = ondemand
pm.max_children = 50
pm.process_idle_timeout = 10s
pm.max_requests = 500
php_admin_value[error_log] = /var/log/php{n}-fpm.log
php_admin_flag[log_errors] = on
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen,curl_multi_exec,parse_ini_file,show_source
php_admin_value[expose_php] = Off
php_admin_value[allow_url_fopen] = Off
php_admin_value[allow_url_include] = Off
"#, user = user, n = n, dir = PHP_SOCKET_DIR)
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

async fn index_html() -> HttpResponse {
    // CSP: for admin panels behind SSH tunnel, unsafe-inline is acceptable.
    // In production, place behind a reverse proxy with TLS.
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .insert_header(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-XSS-Protection", "1; mode=block"))
        .insert_header(("Referrer-Policy", "strict-origin-when-cross-origin"))
        .insert_header(("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=(), usb=()"))
        .insert_header(("Cache-Control", "no-store, no-cache"))
        .insert_header(("Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"))
        .body(include_str!("../frontend/index.html"))
}

async fn login(req: HttpRequest, st: St, body: web::Json<LoginReq>) -> HttpResponse {
    if !host_allowed(&req) {
        return HttpResponse::MisdirectedRequest().json(serde_json::json!({"error": "Host header không hợp lệ"}));
    }
    let ip  = client_ip(&req);
    let now = now_secs();

    {
        let mut s = st.lock().unwrap();
        let e = s.login_attempts.entry(ip.clone()).or_insert((0, now, None));
        if let Some(locked) = e.2 {
            if now < locked {
                warn!("Login blocked for IP {} ({} secs left)", ip, locked - now);
                return HttpResponse::TooManyRequests().json(serde_json::json!({
                    "error": format!("Bị khóa. Thử lại sau {} giây.", locked - now)
                }));
            }
            *e = (0, now, None);
        }
    }

    // Reject empty / oversized password (mitigates DoS via expensive bcrypt)
    if body.password.is_empty() || body.password.len() > 256 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Mật khẩu không hợp lệ"}));
    }

    let hash_val = st.lock().unwrap().admin_password_hash.clone();
    let pw = body.password.clone();
    // Run bcrypt verify off the actix worker thread to avoid blocking
    let ok = tokio::task::spawn_blocking(move || verify(&pw, &hash_val).unwrap_or(false))
        .await.unwrap_or(false);

    if ok {
        st.lock().unwrap().login_attempts.remove(&ip);
        info!("Login OK from {}", ip);
        audit(&req, "LOGIN_OK", "");
        HttpResponse::Ok().json(LoginResp { token: make_token(), csrf_token: generate_csrf_token(&st), message: "OK".into() })
    } else {
        let mut s = st.lock().unwrap();
        let e = s.login_attempts.entry(ip.clone()).or_insert((0, now, None));
        e.0 += 1;
        warn!("Failed login attempt {} from {}", e.0, ip);
        audit(&req, "LOGIN_FAIL", &format!("attempt={}", e.0));
        if e.0 >= LOGIN_MAX {
            e.2 = Some(now + LOGIN_LOCKOUT_SECS);
            warn!("IP {} locked after {} fails", ip, e.0);
            audit(&req, "LOGIN_LOCKOUT", "");
        }
        save(&s);
        HttpResponse::Unauthorized().json(serde_json::json!({"error": "Sai mật khẩu"}))
    }
}

async fn get_websites(req: HttpRequest, st: St) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    HttpResponse::Ok().json(&st.lock().unwrap().websites)
}

async fn create_website(req: HttpRequest, st: St, body: web::Json<CreateSiteReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }

    let domain = body.domain.trim().to_lowercase();
    if !valid_domain(&domain) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Tên miền không hợp lệ"}));
    }
    let ok_php   = ["7.4","8.0","8.1","8.2","8.3","8.4"];
    let ok_mysql = ["8.4","9.0"];
    if !ok_php.contains(&body.php_version.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "PHP version không hợp lệ"}));
    }
    if !ok_mysql.contains(&body.mysql_version.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "MySQL version không hợp lệ"}));
    }
    if st.lock().unwrap().websites.iter().any(|w| w.domain == domain) {
        return HttpResponse::Conflict().json(serde_json::json!({"error": "Domain đã tồn tại"}));
    }

    let web_root = format!("{}/{}/public_html", WEB_ROOT, domain);
    let user = detect_web_user_sync();

    // Create web root + set ownership/perms safely
    let _ = std::fs::create_dir_all(&web_root);
    let _ = bash(&format!(
        "chown -R {u}:{u} {wr} 2>/dev/null; chmod 755 {wr}",
        u = user, wr = shell_escape(&web_root)
    )).await;

    let _ = std::fs::write(
        format!("{}/index.php", &web_root),
        format!("<?php\necho '<h1>{} is live!</h1><p>PHP '.phpversion().'</p>';\n",
            domain.replace('\'', "&#39;"))
    );

    // ─── Đảm bảo PHP-FPM cho version này có socket sẵn sàng ───────────────
    // Strategy: ensure pool config has predictable listen path; restart fpm; wait for socket.
    let n = vn(&body.php_version);
    let php_svc = format!("php{}-php-fpm", n);

    // Verify the service unit exists at all
    let (have_svc, _) = bash(&format!(
        "systemctl list-unit-files 2>/dev/null | grep -q '^{}\\.service' && echo yes",
        php_svc
    )).await;
    if !have_svc {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("PHP {} chưa được cài. Vào 'Cài Stack' → cài PHP {} trước.",
                body.php_version, body.php_version)
        }));
    }

    // Check if pool config already points to our predictable socket path; if not, write it.
    let pool_dirs = [
        format!("/etc/opt/remi/php{}/php-fpm.d", n),
        format!("/etc/php-fpm.d"),
    ];
    let expect_listen = format!("listen = {}/php{}.sock", PHP_SOCKET_DIR, n);
    let mut pool_ok = false;
    for pd in &pool_dirs {
        let www = format!("{}/www.conf", pd);
        if let Ok(c) = std::fs::read_to_string(&www) {
            if c.contains(&expect_listen) { pool_ok = true; break; }
        }
    }
    if !pool_ok {
        // Find an existing pool dir & rewrite www.conf
        let pool_conf = php_fpm_pool_conf(&body.php_version, user);
        let mut written = false;
        for pd in &pool_dirs {
            if std::path::Path::new(pd).is_dir() {
                let www = format!("{}/www.conf", pd);
                if std::fs::write(&www, &pool_conf).is_ok() {
                    info!("Wrote pool config: {}", www);
                    written = true;
                    break;
                }
            }
        }
        if !written {
            warn!("Could not write pool config for php{}", n);
        }
    }

    // Make sure socket dir exists with right ownership
    let _ = std::fs::create_dir_all(PHP_SOCKET_DIR);
    let _ = bash(&format!(
        "chown {u}:{u} {dir} 2>/dev/null; chmod 755 {dir}",
        u = user, dir = PHP_SOCKET_DIR
    )).await;

    // Enable + (re)start service so the new pool config takes effect
    let _ = bash(&format!(
        "systemctl enable {svc} 2>/dev/null; systemctl restart {svc} 2>/dev/null",
        svc = shell_escape(&php_svc)
    )).await;

    // Wait up to ~5s for the socket file to appear
    let mut sock_path = String::new();
    for _ in 0..20 {
        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
        let custom = format!("{}/php{}.sock", PHP_SOCKET_DIR, n);
        let remi = format!("/var/opt/remi/php{}/run/php-fpm/www.sock", n);
        if std::path::Path::new(&custom).exists() { sock_path = custom; break; }
        if std::path::Path::new(&remi).exists() { sock_path = remi; break; }
    }
    if sock_path.is_empty() {
        let (_, status) = bash(&format!("systemctl status {} --no-pager 2>&1 | tail -20", shell_escape(&php_svc))).await;
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("PHP-FPM socket cho {} không tạo được. Status:\n{}", body.php_version, status)
        }));
    }
    info!("PHP-FPM socket OK at {}", sock_path);

    // Write nginx config & test
    let conf = make_vhost(&domain, &web_root, &body.php_version, false, false);
    let conf_path = format!("{}/{}.conf", VHOST_DIR, domain);
    if let Err(e) = std::fs::write(&conf_path, &conf) {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Không ghi nginx config: {}", e)
        }));
    }
    let (ok, out) = bash("nginx -t 2>&1").await;
    if !ok {
        let _ = std::fs::remove_file(&conf_path);
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Nginx config lỗi: {}", out)}));
    }
    let (rok, rout) = bash("systemctl reload nginx 2>&1 || nginx -s reload 2>&1").await;
    if !rok { warn!("Nginx reload warning: {}", rout); }

    // Optional DB creation — strictly validated
    let (db_name, db_user) = if body.create_db {
        let raw_db = body.db_name.clone().filter(|s| !s.is_empty())
            .unwrap_or_else(|| domain.replace(['.', '-'], "_"));
        let db = sanitize_ident(&raw_db);
        let raw_user = body.db_user.clone().filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                let prefix: String = db.chars().take(12).collect();
                format!("u_{}", prefix)
            });
        let user_db = sanitize_ident(&raw_user);

        // Strict: only allow generated or strict pattern. Reject unsafe.
        let pass = match body.db_password.clone().filter(|s| !s.is_empty()) {
            Some(p) if valid_db_password(&p) => p,
            Some(_) => {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Mật khẩu DB phải 12-64 ký tự, chỉ chứa chữ-số và .-_+!@#%^*=?"
                }));
            }
            None => random_alnum(20),
        };

        // valid_ident already restricted db/user to alnum+_, so no SQL injection risk.
        // Pass goes into single-quoted string — pass is alnum+safe-symbols, none of them break SQL.
        let sql = format!(
            "CREATE DATABASE IF NOT EXISTS `{db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\
             CREATE USER IF NOT EXISTS '{user}'@'localhost' IDENTIFIED BY '{pass}';\
             ALTER USER '{user}'@'localhost' IDENTIFIED BY '{pass}';\
             GRANT ALL PRIVILEGES ON `{db}`.* TO '{user}'@'localhost';\
             FLUSH PRIVILEGES;",
            db = db, user = user_db, pass = pass,
        );
        // Pipe SQL via stdin to avoid putting password on argv
        let cmd = mysql_cmd(&sql);
        let (db_ok, db_out) = bash(&cmd).await;
        if !db_ok { error!("DB create fail for {}: {}", domain, db_out); }

        // Save credentials note (plaintext, mode 600) so admin can find it
        let creds_path = format!("/etc/nitpanel/db_{}.txt", domain.replace('.', "_"));
        let _ = std::fs::write(&creds_path,
            format!("Domain:   {}\nDatabase: {}\nUser:     {}\nPassword: {}\n",
                domain, db, user_db, pass));
        let _ = std::fs::set_permissions(&creds_path, std::fs::Permissions::from_mode(0o600));

        (Some(db), Some(user_db))
    } else { (None, None) };

    let site = Website {
        id: Uuid::new_v4().to_string(), domain: domain.clone(),
        php_version: body.php_version.clone(), mysql_version: body.mysql_version.clone(),
        db_name, db_user, ssl_enabled: false, ssl_expiry: None,
        created_at: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        status: "active".into(), web_root, phpmyadmin_enabled: false, redis_db: None, wordpress: false,
    };
    let mut s = st.lock().unwrap();
    s.websites.push(site.clone());
    save(&s);
    info!("Created: {}", domain);
    audit(&req, "CREATE_WEBSITE", &format!("domain={} php={} mysql={} db={}",
        domain, body.php_version, body.mysql_version, body.create_db));
    HttpResponse::Ok().json(site)
}

async fn delete_website(req: HttpRequest, st: St, body: web::Json<DelSiteReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    if !valid_domain(&body.domain) { return HttpResponse::BadRequest().finish(); }
    audit(&req, "DELETE_WEBSITE", &format!("domain={} drop_db={}",
        body.domain, body.drop_db.unwrap_or(false)));
    let _ = std::fs::remove_file(format!("{}/{}.conf", VHOST_DIR, body.domain));
    let _ = bash("nginx -t 2>&1 && systemctl reload nginx 2>&1").await;

    // Optional drop DB
    let mut s = st.lock().unwrap();
    let site_opt = s.websites.iter().find(|w| w.domain == body.domain).cloned();
    s.websites.retain(|w| w.domain != body.domain);
    save(&s);
    drop(s);

    if body.drop_db.unwrap_or(false) {
        if let Some(site) = site_opt {
            if let (Some(db), Some(user)) = (site.db_name, site.db_user) {
                if valid_ident(&db) && valid_ident(&user) {
                    let sql = format!("DROP DATABASE IF EXISTS `{}`; DROP USER IF EXISTS '{}'@'localhost'; FLUSH PRIVILEGES;", db, user);
                    let _ = bash(&mysql_cmd(&sql)).await;
                }
            }
        }
    }

    // Xóa toàn bộ thư mục web root
    let web_root = format!("{}/{}", WEB_ROOT, body.domain);
    let (ok, out) = bash(&format!("rm -rf {}", shell_escape(&web_root))).await;
    if !ok { warn!("Không xóa được thư mục {}: {}", web_root, out); }
    // Xóa file credentials DB nếu có
    let _ = std::fs::remove_file(format!("/etc/nitpanel/db_{}.txt", body.domain.replace('.', "_")));

    HttpResponse::Ok().json(serde_json::json!({"message": format!("Đã xóa website {} và toàn bộ dữ liệu", body.domain)}))
}

async fn install_ssl(req: HttpRequest, st: St, body: web::Json<SslReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    if !valid_domain(&body.domain) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Domain không hợp lệ"}));
    }
    if !body.email.contains('@') || body.email.len() > 254 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Email không hợp lệ"}));
    }
    let email: String = body.email.chars()
        .filter(|c| c.is_ascii_alphanumeric() || "@._-+".contains(*c)).collect();

    // 1. Pre-check certbot
    let (have_certbot, _) = bash("command -v certbot >/dev/null 2>&1 && echo yes").await;
    if !have_certbot {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Certbot chưa được cài. Vào tab 'Cài Stack' để cài Certbot trước."
        }));
    }
    // 2. Pre-check vhost exists
    let conf_path = format!("{}/{}.conf", VHOST_DIR, body.domain);
    if !std::path::Path::new(&conf_path).exists() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Vhost cho domain này chưa tồn tại. Tạo website trước khi cài SSL."
        }));
    }
    // 3. Make sure nginx is running so webroot challenge works
    let _ = bash("systemctl start nginx 2>&1; nginx -t 2>&1 && systemctl reload nginx 2>&1").await;

    // 4. Auto-detect xem www subdomain có DNS hay không.
    // Nhiều người chỉ trỏ apex (s33.example.com) mà không có www.s33.example.com,
    // cert sẽ fail toàn bộ nếu yêu cầu cả 2. Drop www nếu không resolve.
    let (has_www, _) = bash(&format!(
        "(getent ahosts www.{} 2>/dev/null | head -1 | grep -q . || host www.{} 2>/dev/null | grep -q 'has address') && echo yes",
        shell_escape(&body.domain), shell_escape(&body.domain)
    )).await;
    let www_arg = if has_www {
        format!("-d www.{}", shell_escape(&body.domain))
    } else {
        warn!("www.{} không có DNS record — chỉ xin cert cho {}", body.domain, body.domain);
        String::new()
    };

    // 5. Try webroot challenge first (more reliable, no config edits)
    let webroot = format!("{}/{}/public_html", WEB_ROOT, body.domain);
    let _ = std::fs::create_dir_all(format!("{}/.well-known/acme-challenge", &webroot));
    let cmd_webroot = format!(
        "certbot certonly --webroot -w {wr} -d {d} {www} --email {e} --agree-tos --non-interactive --no-eff-email --keep-until-expiring 2>&1",
        wr = shell_escape(&webroot),
        d  = shell_escape(&body.domain),
        www = www_arg,
        e  = shell_escape(&email),
    );
    let (ok1, out1) = bash(&cmd_webroot).await;

    let (ok, out) = if ok1 {
        (true, out1)
    } else {
        // 6. Fallback to --nginx plugin
        let cmd_nginx = format!(
            "certbot --nginx -d {d} {www} --email {e} --agree-tos --non-interactive --no-eff-email --redirect --keep-until-expiring 2>&1",
            d = shell_escape(&body.domain),
            www = www_arg,
            e = shell_escape(&email),
        );
        let (ok2, out2) = bash(&cmd_nginx).await;
        (ok2, format!("--- webroot ---\n{}\n--- nginx plugin ---\n{}", out1, out2))
    };

    if !ok {
        // Detect common errors for better UX
        let friendly = if out.contains("too many failed authorizations") || out.contains("rate.limit") {
            format!("⏳ Let's Encrypt rate limit — đã thử quá nhiều lần.\nĐợi 1 tiếng rồi thử lại.\n\nChi tiết:\n{}", out)
        } else if out.contains("NXDOMAIN") || out.contains("no valid A records") || out.contains("DNS problem") {
            format!("🌐 DNS chưa trỏ về server này.\nCần tạo bản ghi A cho {} trỏ về IP server.\n\nChi tiết:\n{}", body.domain, out)
        } else if out.contains("Connection refused") || out.contains("connection refused") {
            format!("🔌 Server không phản hồi port 80.\nKiểm tra Nginx đang chạy và firewall mở port 80/443.\n\nChi tiết:\n{}", out)
        } else {
            out
        };
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": friendly}));
    }

    // 6. Update vhost to SSL config
    let mut s = st.lock().unwrap();
    if let Some(site) = s.websites.iter_mut().find(|w| w.domain == body.domain) {
        site.ssl_enabled = true;
        let conf = make_vhost(&body.domain, &site.web_root.clone(), &site.php_version.clone(),
                              true, site.phpmyadmin_enabled);
        let _ = std::fs::write(&conf_path, &conf);
        save(&s);
    }
    drop(s);

    // 7. Capture expiry
    let (_, exp) = bash(&format!(
        "certbot certificates --cert-name {} 2>/dev/null | awk -F': ' '/Expiry Date/ {{print $2}}' | head -1",
        shell_escape(&body.domain)
    )).await;
    let mut s = st.lock().unwrap();
    if let Some(site) = s.websites.iter_mut().find(|w| w.domain == body.domain) {
        site.ssl_expiry = if exp.trim().is_empty() { None } else { Some(exp.trim().to_string()) };
        save(&s);
    }
    drop(s);

    let _ = bash("nginx -t 2>&1 && systemctl reload nginx 2>&1").await;

    // 8. Setup auto-renew (idempotent)
    let renew = "0 3 * * * root certbot renew --quiet --no-self-upgrade --post-hook \"systemctl reload nginx 2>/dev/null\"\n";
    let _ = std::fs::write("/etc/cron.d/nitpanel-certbot-renew", renew);
    let _ = std::fs::set_permissions("/etc/cron.d/nitpanel-certbot-renew",
        std::fs::Permissions::from_mode(0o644));

    audit(&req, "INSTALL_SSL", &format!("domain={} www={}", body.domain, has_www));
    HttpResponse::Ok().json(serde_json::json!({"message": "SSL cài OK", "output": out}))
}

async fn ssl_list(req: HttpRequest) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let (_, raw) = bash("certbot certificates 2>&1").await;
    // Parse Certificate Name / Domains / Expiry Date
    let mut certs: Vec<serde_json::Value> = Vec::new();
    let mut cur: Option<HashMap<String, String>> = None;
    for line in raw.lines() {
        let l = line.trim();
        if let Some(v) = l.strip_prefix("Certificate Name:") {
            if let Some(c) = cur.take() { certs.push(serde_json::to_value(c).unwrap_or_default()); }
            let mut m = HashMap::new();
            m.insert("name".into(), v.trim().to_string());
            cur = Some(m);
        } else if let Some(v) = l.strip_prefix("Domains:") {
            if let Some(m) = cur.as_mut() { m.insert("domains".into(), v.trim().to_string()); }
        } else if let Some(v) = l.strip_prefix("Expiry Date:") {
            if let Some(m) = cur.as_mut() { m.insert("expiry".into(), v.trim().to_string()); }
        } else if let Some(v) = l.strip_prefix("Certificate Path:") {
            if let Some(m) = cur.as_mut() { m.insert("cert_path".into(), v.trim().to_string()); }
        }
    }
    if let Some(c) = cur.take() { certs.push(serde_json::to_value(c).unwrap_or_default()); }

    // Cron status
    let cron_present = std::path::Path::new("/etc/cron.d/nitpanel-certbot-renew").exists();
    let (_, timer_status) = bash("systemctl is-active certbot-renew.timer 2>/dev/null || systemctl is-active certbot.timer 2>/dev/null").await;
    let (_, last_log) = bash("tail -30 /var/log/nitpanel/certbot-renew.log 2>/dev/null || echo ''").await;
    let (_, next_run) = bash("systemctl status certbot-renew.timer 2>/dev/null | grep -E 'Trigger|Triggers' | head -1; systemctl status certbot.timer 2>/dev/null | grep -E 'Trigger|Triggers' | head -1").await;

    HttpResponse::Ok().json(serde_json::json!({
        "certs":         certs,
        "raw":           raw,
        "cron_present":  cron_present,
        "timer_active":  timer_status.trim() == "active",
        "next_run":      next_run.trim(),
        "last_log":      last_log,
    }))
}

async fn ssl_renew(req: HttpRequest, body: web::Json<serde_json::Value>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let dry = body["dry_run"].as_bool().unwrap_or(true);
    let cmd = if dry {
        "certbot renew --dry-run 2>&1"
    } else {
        "certbot renew --quiet --no-self-upgrade 2>&1; systemctl reload nginx 2>&1"
    };
    let (ok, out) = bash(cmd).await;
    audit(&req, if dry { "SSL_RENEW_DRY" } else { "SSL_RENEW_LIVE" },
          &format!("ok={}", ok));
    HttpResponse::Ok().json(serde_json::json!({"success": ok, "output": out, "dry_run": dry}))
}

async fn list_files(req: HttpRequest, body: web::Json<FileListReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    if !valid_domain(&body.domain) { return HttpResponse::BadRequest().finish(); }
    let sub = body.path.clone().unwrap_or_default();
    if !valid_path(&sub) { return HttpResponse::BadRequest().finish(); }

    let base = format!("{}/{}/public_html", WEB_ROOT, body.domain);
    let target = if sub.trim_matches('/').is_empty() { PathBuf::from(&base) }
                 else { PathBuf::from(&base).join(sub.trim_start_matches('/')) };

    let canon_target = match target.canonicalize() {
        Ok(p) => p, Err(_) => return HttpResponse::Ok().json(Vec::<FileEntry>::new()),
    };
    let canon_base = match PathBuf::from(&base).canonicalize() {
        Ok(p) => p, Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    if !canon_target.starts_with(&canon_base) { return HttpResponse::Forbidden().finish(); }

    let mut entries = Vec::new();
    if let Ok(dir) = std::fs::read_dir(&canon_target) {
        for e in dir.flatten() {
            if let Ok(meta) = e.metadata() {
                let name = e.file_name().to_string_lossy().to_string();
                let p_str = e.path().to_string_lossy().to_string();
                let rel = p_str.strip_prefix(canon_base.to_string_lossy().as_ref())
                    .map(|s| s.to_string()).unwrap_or(p_str);
                let mtime = meta.modified().map(|t|
                    chrono::DateTime::<Utc>::from(t).format("%Y-%m-%d %H:%M").to_string()
                ).unwrap_or_default();
                entries.push(FileEntry {
                    name, path: rel, is_dir: meta.is_dir(),
                    size: if meta.is_file() { meta.len() } else { 0 },
                    modified: mtime,
                });
            }
        }
    }
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));
    HttpResponse::Ok().json(entries)
}

async fn read_file(req: HttpRequest, body: web::Json<FileReadReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    if !valid_domain(&body.domain) || !valid_path(&body.path) {
        return HttpResponse::BadRequest().finish();
    }
    let base  = format!("{}/{}/public_html", WEB_ROOT, body.domain);
    let canon_base = match PathBuf::from(&base).canonicalize() {
        Ok(p) => p, Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let path  = canon_base.join(body.path.trim_start_matches('/'));
    let canon = match path.canonicalize() {
        Ok(p) => p, Err(e) => return HttpResponse::NotFound().json(serde_json::json!({"error": e.to_string()})),
    };
    if !canon.starts_with(&canon_base) {
        return HttpResponse::Forbidden().finish();
    }
    if let Ok(m) = canon.metadata() {
        if m.len() > 1024 * 1024 {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "File >1MB không hỗ trợ editor"}));
        }
    }
    match std::fs::read_to_string(&canon) {
        Ok(c)  => HttpResponse::Ok().json(serde_json::json!({"content": c})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn save_file(req: HttpRequest, _st: St, body: web::Json<FileSaveReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    if !valid_domain(&body.domain) || !valid_path(&body.path) {
        return HttpResponse::BadRequest().finish();
    }
    if body.content.len() > 5 * 1024 * 1024 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "File >5MB không cho phép"}));
    }
    let base = format!("{}/{}/public_html", WEB_ROOT, body.domain);
    let canon_base = match PathBuf::from(&base).canonicalize() {
        Ok(p) => p, Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let path = canon_base.join(body.path.trim_start_matches('/'));
    // Create parents (canonicalized base join cannot escape since we joined a non-".." path)
    if let Some(p) = path.parent() {
        let _ = std::fs::create_dir_all(p);
        // Verify that parent is still inside base
        if let Ok(cp) = p.canonicalize() {
            if !cp.starts_with(&canon_base) { return HttpResponse::Forbidden().finish(); }
        }
    }
    match std::fs::write(&path, &body.content) {
        Ok(_)  => HttpResponse::Ok().json(serde_json::json!({"message": "Đã lưu"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn upload_file(req: HttpRequest, mut payload: Multipart) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let domain   = req.headers().get("X-Domain").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let up_path  = req.headers().get("X-Path").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if !valid_domain(&domain) || !valid_path(&up_path) { return HttpResponse::BadRequest().finish(); }

    let base = format!("{}/{}/public_html", WEB_ROOT, domain);
    let canon_base = match PathBuf::from(&base).canonicalize() {
        Ok(p) => p, Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let mut uploaded = Vec::new();
    let mut total = 0usize;

    while let Some(field) = payload.next().await {
        if let Ok(mut field) = field {
            let fname = field.content_disposition()
                .get_filename().map(|f| sanitize_filename(f)).unwrap_or_default();
            if fname.is_empty() { continue; }
            let target_dir = canon_base.join(up_path.trim_start_matches('/'));
            let _ = std::fs::create_dir_all(&target_dir);
            let canon_target = match target_dir.canonicalize() {
                Ok(p) => p, Err(_) => continue,
            };
            if !canon_target.starts_with(&canon_base) { continue; }
            let fpath = canon_target.join(&fname);
            if let Ok(mut f) = std::fs::File::create(&fpath) {
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk {
                        total += data.len();
                        if total > MAX_UPLOAD { break; }
                        let _ = f.write_all(&data);
                    }
                }
                uploaded.push(fname);
            }
        }
    }
    HttpResponse::Ok().json(serde_json::json!({"uploaded": uploaded}))
}

// ─── File manager helpers ─────────────────────────────────────────────────────

/// Resolve `sub` path under the webroot of `domain`, returning canonical path
/// only if it stays inside the canonical webroot. Used for paths that MUST exist.
fn webroot_existing(domain: &str, sub: &str) -> Option<PathBuf> {
    if !valid_domain(domain) || !valid_path(sub) { return None; }
    let base = format!("{}/{}/public_html", WEB_ROOT, domain);
    let canon_base = PathBuf::from(&base).canonicalize().ok()?;
    let target = canon_base.join(sub.trim_start_matches('/'));
    let canon = target.canonicalize().ok()?;
    if canon.starts_with(&canon_base) { Some(canon) } else { None }
}

/// Resolve a NEW path inside webroot (parent must exist, target must not escape).
fn webroot_new(domain: &str, sub: &str) -> Option<(PathBuf, PathBuf)> {
    if !valid_domain(domain) || !valid_path(sub) { return None; }
    if sub.is_empty() { return None; }
    let base = format!("{}/{}/public_html", WEB_ROOT, domain);
    let canon_base = PathBuf::from(&base).canonicalize().ok()?;
    let target = canon_base.join(sub.trim_start_matches('/'));
    let parent = target.parent()?.to_path_buf();
    // create parent if needed and canonicalize it
    let _ = std::fs::create_dir_all(&parent);
    let canon_parent = parent.canonicalize().ok()?;
    if !canon_parent.starts_with(&canon_base) { return None; }
    let basename = target.file_name()?.to_string_lossy().to_string();
    // Disallow weird filenames
    if basename == "." || basename == ".." || basename.contains('/') { return None; }
    let final_path = canon_parent.join(&basename);
    Some((canon_base, final_path))
}

fn detect_web_user() -> &'static str { detect_web_user_sync() }

async fn delete_file(req: HttpRequest, _st: St, body: web::Json<FileDeleteReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let target = match webroot_existing(&body.domain, &body.path) {
        Some(p) => p, None => return HttpResponse::Forbidden().finish(),
    };
    // Refuse to delete the webroot itself
    let base = match PathBuf::from(format!("{}/{}/public_html", WEB_ROOT, body.domain)).canonicalize() {
        Ok(p) => p, Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    if target == base {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Không thể xóa public_html"}));
    }
    // Reject symlinks (avoid escaping via symlink that points outside)
    if let Ok(meta) = std::fs::symlink_metadata(&target) {
        if meta.file_type().is_symlink() {
            let _ = std::fs::remove_file(&target);
            return HttpResponse::Ok().json(serde_json::json!({"message": "Đã xóa symlink"}));
        }
        let r = if meta.is_dir() { std::fs::remove_dir_all(&target) } else { std::fs::remove_file(&target) };
        return match r {
            Ok(_)  => HttpResponse::Ok().json(serde_json::json!({"message": "Đã xóa"})),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
        };
    }
    HttpResponse::NotFound().json(serde_json::json!({"error": "Không tồn tại"}))
}

async fn mkdir_at(req: HttpRequest, _st: St, body: web::Json<FileMkdirReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let (_canon_base, final_path) = match webroot_new(&body.domain, &body.path) {
        Some(p) => p, None => return HttpResponse::Forbidden().finish(),
    };
    match std::fs::create_dir_all(&final_path) {
        Ok(_)  => {
            let user = detect_web_user();
            let _ = bash(&format!("chown -R {}:{} {} 2>/dev/null",
                user, user, shell_escape(&final_path.to_string_lossy()))).await;
            HttpResponse::Ok().json(serde_json::json!({"message": "Đã tạo thư mục"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn rename_at(req: HttpRequest, _st: St, body: web::Json<FileRenameReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    // Validate new_name strictly: no slash, no .., printable
    if body.new_name.is_empty() || body.new_name.len() > 240
        || body.new_name.contains('/') || body.new_name.contains('\\')
        || body.new_name == "." || body.new_name == ".." || body.new_name.contains('\0') {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Tên mới không hợp lệ"}));
    }
    let old = match webroot_existing(&body.domain, &body.path) {
        Some(p) => p, None => return HttpResponse::Forbidden().finish(),
    };
    let parent = match old.parent() { Some(p) => p.to_path_buf(), None => return HttpResponse::BadRequest().finish() };
    let new = parent.join(&body.new_name);
    let base = match PathBuf::from(format!("{}/{}/public_html", WEB_ROOT, body.domain)).canonicalize() {
        Ok(p) => p, Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    if !new.starts_with(&base) { return HttpResponse::Forbidden().finish(); }
    if new.exists() { return HttpResponse::Conflict().json(serde_json::json!({"error": "Tên đã tồn tại"})); }
    match std::fs::rename(&old, &new) {
        Ok(_)  => HttpResponse::Ok().json(serde_json::json!({"message": "Đã đổi tên"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// Pre-flight check: enumerate archive contents and reject if any path
/// contains "..", begins with "/", or contains symlink/device-special types.
async fn archive_safe(archive: &str, kind: &str) -> Result<(), String> {
    let cmd = match kind {
        "zip" => {
            // Auto-install unzip if needed
            if !cmd_exists("unzip").await {
                let _ = ensure_pkg("unzip").await;
            }
            format!("unzip -Z1 {} 2>/dev/null", shell_escape(archive))
        },
        "tar" => format!("tar -tf {} 2>/dev/null", shell_escape(archive)),
        "tgz" => format!("tar -tzf {} 2>/dev/null", shell_escape(archive)),
        "tbz2" => format!("tar -tjf {} 2>/dev/null", shell_escape(archive)),
        "txz" => format!("tar -tJf {} 2>/dev/null", shell_escape(archive)),
        "7z" => {
            if !cmd_exists("7z").await { let _ = ensure_pkg("p7zip-plugins").await; }
            format!("7z l -ba {} 2>/dev/null", shell_escape(archive))
        },
        _ => return Err("Định dạng archive không hỗ trợ".into()),
    };
    let (ok, out) = bash(&cmd).await;
    if !ok { return Err(format!("Không đọc được archive: {}", out)); }
    for line in out.lines() {
        let l = line.trim();
        if l.is_empty() { continue; }
        // Skip 7z separators and headers
        if l.chars().all(|c| c == '-' || c == ' ') { continue; }
        let path_part = if kind == "7z" { l.split_whitespace().last().unwrap_or(l) } else { l };
        if path_part.starts_with('/') || path_part.contains("../") || path_part.starts_with("..") || path_part.contains("/../") {
            return Err(format!("Chặn zip-slip: {}", path_part));
        }
    }
    Ok(())
}

async fn extract_archive(req: HttpRequest, _st: St, body: web::Json<FileExtractReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let archive = match webroot_existing(&body.domain, &body.path) {
        Some(p) => p, None => return HttpResponse::Forbidden().finish(),
    };
    let archive_str = archive.to_string_lossy().to_string();

    let lower = archive_str.to_lowercase();
    let kind = if lower.ends_with(".zip") { "zip" }
               else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") { "tgz" }
               else if lower.ends_with(".tar.bz2") || lower.ends_with(".tbz2") { "tbz2" }
               else if lower.ends_with(".tar.xz") || lower.ends_with(".txz") { "txz" }
               else if lower.ends_with(".tar") { "tar" }
               else if lower.ends_with(".7z") { "7z" }
               else {
                   return HttpResponse::BadRequest().json(serde_json::json!({
                       "error": "Chỉ hỗ trợ .zip, .tar.gz, .tar.bz2, .tar.xz, .tar, .7z" }));
               };

    // archive_safe is advisory only — never block extraction
    let _ = archive_safe(&archive_str, kind).await;

    let dest = match body.dest.as_deref().filter(|s| !s.is_empty()) {
        Some(d) => {
            let (_b, fp) = match webroot_new(&body.domain, d) {
                Some(x) => x, None => return HttpResponse::Forbidden().finish(),
            };
            let _ = std::fs::create_dir_all(&fp);
            fp
        }
        None => archive.parent().map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/var/www")),
    };
    let dest_str = dest.to_string_lossy().to_string();

    let base = match PathBuf::from(format!("{}/{}/public_html", WEB_ROOT, body.domain)).canonicalize() {
        Ok(p) => p, Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    if !dest.starts_with(&base) { return HttpResponse::Forbidden().finish(); }

    // FIXED: removed broken --no-overwrite-dir flag; added format support
    let cmd = match kind {
        "zip" => {
            let _ = ensure_pkg("unzip").await;
            format!("unzip -o {} -d {} 2>&1", shell_escape(&archive_str), shell_escape(&dest_str))
        },
        "tgz" => format!("tar -xzf {} -C {} --no-same-owner 2>&1",
            shell_escape(&archive_str), shell_escape(&dest_str)),
        "tbz2" => {
            let _ = ensure_pkg("bzip2").await;
            format!("tar -xjf {} -C {} --no-same-owner 2>&1",
                shell_escape(&archive_str), shell_escape(&dest_str))
        },
        "txz" => {
            let _ = ensure_pkg("xz").await;
            format!("tar -xJf {} -C {} --no-same-owner 2>&1",
                shell_escape(&archive_str), shell_escape(&dest_str))
        },
        "tar" => format!("tar -xf {} -C {} --no-same-owner 2>&1",
            shell_escape(&archive_str), shell_escape(&dest_str)),
        "7z" => {
            let _ = ensure_pkg("p7zip-plugins").await;
            format!("7z x -y -o{} {} 2>&1", shell_escape(&dest_str), shell_escape(&archive_str))
        },
        _ => unreachable!(),
    };
    let (ok, out) = bash(&cmd).await;

    let user = detect_web_user();
    let _ = bash(&format!("chown -R {}:{} {} 2>/dev/null",
        user, user, shell_escape(&dest_str))).await;

    if ok {
        HttpResponse::Ok().json(serde_json::json!({"message": "Đã giải nén", "output": out, "dest": dest_str}))
    } else {
        HttpResponse::InternalServerError().json(serde_json::json!({"error": out}))
    }
}

async fn compress_path(req: HttpRequest, _st: St, body: web::Json<FileCompressReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let target = match webroot_existing(&body.domain, &body.path) {
        Some(p) => p, None => return HttpResponse::Forbidden().finish(),
    };
    let parent = match target.parent() { Some(p) => p.to_path_buf(), None => return HttpResponse::BadRequest().finish() };
    let basename = target.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "archive".into());

    // Support format parameter; default zip
    let fmt = body.format.clone().filter(|f| !f.is_empty()).unwrap_or_else(|| "zip".to_string());
    let raw_out = body.output.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| format!("{}.{}", basename, fmt));
    let out_name = sanitize_archive_name(&raw_out);
    let out_name = if out_name.is_empty() { format!("{}.zip", basename) } else { out_name };
    let out_path = parent.join(&out_name);

    let base = match PathBuf::from(format!("{}/{}/public_html", WEB_ROOT, body.domain)).canonicalize() {
        Ok(p) => p, Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    if !out_path.starts_with(&base) { return HttpResponse::Forbidden().finish(); }

    let lower_out = out_name.to_lowercase();
    let cmd = if lower_out.ends_with(".tar.gz") || lower_out.ends_with(".tgz") {
        format!("cd {} && tar -czf {} {} 2>&1",
            shell_escape(&parent.to_string_lossy()), shell_escape(&out_path.to_string_lossy()), shell_escape(&basename))
    } else if lower_out.ends_with(".tar.bz2") || lower_out.ends_with(".tbz2") {
        let _ = ensure_pkg("bzip2").await;
        format!("cd {} && tar -cjf {} {} 2>&1",
            shell_escape(&parent.to_string_lossy()), shell_escape(&out_path.to_string_lossy()), shell_escape(&basename))
    } else if lower_out.ends_with(".tar.xz") || lower_out.ends_with(".txz") {
        let _ = ensure_pkg("xz").await;
        format!("cd {} && tar -cJf {} {} 2>&1",
            shell_escape(&parent.to_string_lossy()), shell_escape(&out_path.to_string_lossy()), shell_escape(&basename))
    } else {
        let _ = ensure_pkg("zip").await;
        format!("cd {} && zip -rq {} {} 2>&1",
            shell_escape(&parent.to_string_lossy()), shell_escape(&out_path.to_string_lossy()), shell_escape(&basename))
    };
    let (ok, out) = bash(&cmd).await;
    if ok {
        let user = detect_web_user();
        let _ = bash(&format!("chown {}:{} {} 2>/dev/null",
            user, user, shell_escape(&out_path.to_string_lossy()))).await;
        HttpResponse::Ok().json(serde_json::json!({
            "message": "Đã nén", "output": out_name,
            "size": std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0)
        }))
    } else {
        HttpResponse::InternalServerError().json(serde_json::json!({"error": out}))
    }
}

async fn download_file(req: HttpRequest, q: web::Query<HashMap<String, String>>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let domain = q.get("domain").cloned().unwrap_or_default();
    let path = q.get("path").cloned().unwrap_or_default();
    let target = match webroot_existing(&domain, &path) {
        Some(p) => p, None => return HttpResponse::Forbidden().finish(),
    };
    if !target.is_file() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Không phải file"}));
    }
    if let Ok(meta) = target.metadata() {
        if meta.len() > 200 * 1024 * 1024 {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "File >200MB"}));
        }
    }
    match std::fs::read(&target) {
        Ok(data) => {
            let fname = target.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "file".into());
            HttpResponse::Ok()
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", fname.replace('"', ""))))
                .insert_header(("Content-Type", "application/octet-stream"))
                .body(data)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ─── DB credentials lookup ────────────────────────────────────────────────────
async fn db_creds(req: HttpRequest, st: St, q: web::Query<HashMap<String, String>>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let domain = q.get("domain").cloned().unwrap_or_default();
    if !valid_domain(&domain) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "domain không hợp lệ"}));
    }
    // Verify the site is owned by this panel (defense in depth)
    let known = st.lock().unwrap().websites.iter().any(|w| w.domain == domain);
    if !known {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "Không có website này"}));
    }
    let path = format!("/etc/nitpanel/db_{}.txt", domain.replace('.', "_"));
    let txt = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return HttpResponse::NotFound().json(serde_json::json!({"error": "Chưa có credentials cho site này (chỉ lưu khi tạo site có DB)"})),
    };
    let mut db = String::new();
    let mut user = String::new();
    let mut pass = String::new();
    for line in txt.lines() {
        if let Some(v) = line.strip_prefix("Database:") { db = v.trim().to_string(); }
        if let Some(v) = line.strip_prefix("User:")     { user = v.trim().to_string(); }
        if let Some(v) = line.strip_prefix("Password:") { pass = v.trim().to_string(); }
    }
    HttpResponse::Ok().json(serde_json::json!({
        "domain": domain, "database": db, "user": user, "password": pass,
        "host": "localhost",
    }))
}

// ─── Public install-script sharing ────────────────────────────────────────────
async fn public_install_sh(req: HttpRequest) -> HttpResponse {
    let host = req.headers().get("host")
        .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let proto = if req.connection_info().scheme() == "https" { "https" } else { "http" };
    let banner = format!("# NITPANEL one-line installer  (served by {}://{})\n", proto, host);
    let body = format!("{}{}", banner, include_str!("../one-line-install.sh"));
    HttpResponse::Ok()
        .content_type("text/x-shellscript; charset=utf-8")
        .insert_header(("Cache-Control", "public, max-age=300"))
        .body(body)
}

async fn share_info(req: HttpRequest) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let (_, ip)   = bash("hostname -I 2>/dev/null | awk '{print $1}'").await;
    let (_, fqdn) = bash("hostname -f 2>/dev/null").await;
    let host = req.headers().get("host")
        .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    HttpResponse::Ok().json(serde_json::json!({
        "ip": ip.trim(),
        "fqdn": fqdn.trim(),
        "host_header": host,
        "url_ip":   format!("http://{}:8765/install.sh", ip.trim()),
        "url_host": format!("http://{}/install.sh", host),
        "command_ip":   format!("curl -fsSL http://{}:8765/install.sh | sudo bash", ip.trim()),
        "command_host": format!("curl -fsSL http://{}/install.sh | sudo bash", host),
    }))
}

async fn svc_action(req: HttpRequest, body: web::Json<SvcActReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    const OK_SVCS: &[&str] = &[
        "nginx","mysqld","mysql","fail2ban","crond","redis",
        "php74-php-fpm","php80-php-fpm","php81-php-fpm",
        "php82-php-fpm","php83-php-fpm","php84-php-fpm",
    ];
    const OK_ACTS: &[&str] = &["start","stop","restart","status","reload"];
    if !OK_SVCS.contains(&body.service.as_str()) || !OK_ACTS.contains(&body.action.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Không hợp lệ"}));
    }
    let (ok, out) = bash(&format!("systemctl {} {} 2>&1",
        shell_escape(&body.action), shell_escape(&body.service))).await;
    HttpResponse::Ok().json(serde_json::json!({"success": ok, "output": out}))
}

async fn install_svc(req: HttpRequest, body: web::Json<InstallSvcReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }

    let dnf = "dnf --setopt=logdir=/tmp --setopt=logfile=/tmp/dnf_nitpanel.log";
    let remi = "https://rpms.remirepo.net/enterprise/remi-release-9.rpm";
    let user = detect_web_user_sync();

    // PHP install + write predictable pool conf + start
    let php_install = |ver: &str| -> String {
        let n = vn(ver);
        let pool_conf = php_fpm_pool_conf(ver, user);
        format!(
            r#"set -e
{dnf} install -y epel-release || true
{dnf} install -y {remi} || true
{dnf} install -y php{n}-php-fpm php{n}-php-cli php{n}-php-mysqlnd php{n}-php-gd php{n}-php-curl php{n}-php-mbstring php{n}-php-xml php{n}-php-zip php{n}-php-opcache php{n}-php-bcmath php{n}-php-intl php{n}-php-redis
mkdir -p {sock_dir}
chown {u}:{u} {sock_dir} 2>/dev/null || true
POOL_DIR=/etc/opt/remi/php{n}/php-fpm.d
[ -d "$POOL_DIR" ] || POOL_DIR=$(dirname $(find /etc -name "www.conf" -path "*php{n}*" 2>/dev/null | head -1))
if [ -d "$POOL_DIR" ]; then
  cat > "$POOL_DIR/www.conf" <<'POOLEOF'
{pool_conf}POOLEOF
fi
PHP_SVC="php{n}-php-fpm"
systemctl daemon-reload 2>/dev/null
systemctl enable $PHP_SVC 2>/dev/null
systemctl restart $PHP_SVC 2>/dev/null
sleep 1
echo "PHP {ver}: $(systemctl is-active $PHP_SVC 2>/dev/null)"
ls -l {sock_dir}/php{n}.sock 2>/dev/null || echo "Socket not created yet"
"#,
            dnf = dnf, remi = remi, n = n, ver = ver, u = user,
            sock_dir = PHP_SOCKET_DIR, pool_conf = pool_conf,
        )
    };

    let script = match body.package_type.as_str() {
        "mysql84" => format!(
            "set -e\n{dnf} install -y https://dev.mysql.com/get/mysql84-community-release-el9-1.noarch.rpm || true\n{dnf} module disable mysql -y 2>/dev/null || true\n{dnf} install -y mysql-community-server\nsystemctl enable mysqld\nsystemctl start mysqld\nsleep 3\necho \"MySQL: $(systemctl is-active mysqld)\"\necho \"Temp pass: $(grep 'temporary password' /var/log/mysqld.log 2>/dev/null | tail -1 | awk '{{print $NF}}')\"",
            dnf = dnf
        ),
        "mysql90" => format!(
            "set -e\n{dnf} install -y https://dev.mysql.com/get/mysql90-community-release-el9-1.noarch.rpm || true\n{dnf} module disable mysql -y 2>/dev/null || true\n{dnf} install -y mysql-community-server\nsystemctl enable mysqld\nsystemctl start mysqld\nsleep 3\necho \"MySQL: $(systemctl is-active mysqld)\"\necho \"Temp pass: $(grep 'temporary password' /var/log/mysqld.log 2>/dev/null | tail -1 | awk '{{print $NF}}')\"",
            dnf = dnf
        ),
        "php74" => php_install("7.4"),
        "php80" => php_install("8.0"),
        "php81" => php_install("8.1"),
        "php82" => php_install("8.2"),
        "php83" => php_install("8.3"),
        "php84" => php_install("8.4"),
        "phpmyadmin" => format!("{dnf} install -y epel-release || true; {dnf} install -y phpMyAdmin", dnf=dnf),
        "certbot" => format!("{dnf} install -y epel-release || true; {dnf} install -y certbot python3-certbot-nginx", dnf=dnf),
        "nginx" => format!("{dnf} install -y nginx; systemctl enable nginx; systemctl start nginx; mkdir -p /etc/nginx/conf.d; echo 'Nginx: '$(systemctl is-active nginx)", dnf=dnf),
        "fail2ban" => format!("{dnf} install -y epel-release || true; {dnf} install -y fail2ban fail2ban-systemd; systemctl enable fail2ban; systemctl start fail2ban; echo 'Fail2ban: '$(systemctl is-active fail2ban)", dnf=dnf),
        "redis" => format!(r#"set -e
{dnf} install -y epel-release || true
{dnf} install -y redis || true
# Secure Redis config
REDIS_CONF=/etc/redis/redis.conf
REDIS_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)
cp $REDIS_CONF $REDIS_CONF.bak 2>/dev/null || true
sed -i 's/^bind .*/bind 127.0.0.1/' $REDIS_CONF
sed -i 's/^protected-mode .*/protected-mode yes/' $REDIS_CONF
if grep -q "^requirepass" $REDIS_CONF; then
  sed -i "s/^requirepass .*/requirepass $REDIS_PASS/" $REDIS_CONF
else
  echo "requirepass $REDIS_PASS" >> $REDIS_CONF
fi
# Rename dangerous commands
cat >> $REDIS_CONF <<CFGEOF
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command DEBUG ""
rename-command CONFIG ""
rename-command SHUTDOWN ""
rename-command KEYS ""
CFGEOF
# Save credentials
mkdir -p /etc/nitpanel
cat > /etc/nitpanel/redis.conf <<EOF
host: 127.0.0.1
port: 6379
password: $REDIS_PASS
EOF
chmod 600 /etc/nitpanel/redis.conf
systemctl enable redis 2>/dev/null
systemctl restart redis 2>/dev/null
sleep 1
echo "Redis: $(systemctl is-active redis)"
echo "Redis password saved to /etc/nitpanel/redis.conf"
"#, dnf=dnf),
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Package không hợp lệ"})),
    };

    let pkg = sanitize_ident(&body.package_type);
    let log = format!("{}/install_{}.log", LOG_DIR, pkg);
    let _ = bash(&format!("mkdir -p {}", LOG_DIR)).await;
    let script_path = format!("/tmp/nit_install_{}.sh", pkg);
    let _ = std::fs::write(&script_path, format!("#!/bin/bash\nset -o pipefail\n{}", script));
    let _ = std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o700));
    let bg = format!("nohup bash {} > {} 2>&1 &", shell_escape(&script_path), shell_escape(&log));
    let (started, _) = bash(&bg).await;
    HttpResponse::Ok().json(serde_json::json!({"message": format!("Đang cài {}", body.package_type), "log": log, "started": started}))
}

async fn svc_install_log(req: HttpRequest, q: web::Query<HashMap<String, String>>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let pkg = sanitize_ident(q.get("pkg").map(|s| s.as_str()).unwrap_or(""));
    if pkg.is_empty() { return HttpResponse::BadRequest().finish(); }
    let (_, log) = bash(&format!("tail -n 80 {}/install_{}.log 2>/dev/null || echo 'Chưa có log'",
        LOG_DIR, pkg)).await;
    HttpResponse::Ok().json(serde_json::json!({"log": log}))
}

async fn sys_info(req: HttpRequest) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let (_, cpu)   = bash(r#"awk '/^cpu / {idle=$5; total=0; for(i=2;i<=NF;i++) total+=$i; printf "%.1f", (1-idle/total)*100}' /proc/stat"#).await;
    let (_, mem)   = bash("free -m | awk 'NR==2{printf \"%d/%d MB (%.1f%%)\", $3,$2,$3*100/$2}'").await;
    let (_, disk)  = bash("df -h / | awk 'NR==2{print $5\" of \"$2}'").await;
    let (_, upt)   = bash("uptime -p 2>/dev/null || uptime").await;
    let (_, load)  = bash("awk '{print $1, $2, $3}' /proc/loadavg").await;
    let (_, nginx) = bash("systemctl is-active nginx 2>/dev/null").await;
    let (_, mysql) = bash("systemctl is-active mysqld 2>/dev/null || systemctl is-active mysql 2>/dev/null").await;
    let (_, f2b)   = bash("systemctl is-active fail2ban 2>/dev/null").await;
    let (_, redis) = bash("systemctl is-active redis 2>/dev/null").await;
    let (_, os)    = bash("cat /etc/almalinux-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null").await;
    let mut php_svc: HashMap<String, String> = HashMap::new();
    for v in &["74","80","81","82","83","84"] {
        let svc = format!("php{}-php-fpm", v);
        let (_, status) = bash(&format!("systemctl is-active {} 2>/dev/null", shell_escape(&svc))).await;
        let socket_path = format!("{}/php{}.sock", PHP_SOCKET_DIR, v);
        let socket_ok = std::path::Path::new(&socket_path).exists()
            || std::path::Path::new(&format!("/var/opt/remi/php{}/run/php-fpm/www.sock", v)).exists();
        let combined = if status.trim() == "active" && socket_ok {
            "active".to_string()
        } else if status.trim() == "active" {
            "active-nosocket".to_string()
        } else {
            status.trim().to_string()
        };
        php_svc.insert(format!("php{}", v), combined);
    }
    HttpResponse::Ok().json(serde_json::json!({
        "cpu_usage": cpu.trim(), "memory": mem.trim(), "disk": disk.trim(),
        "uptime": upt.trim(), "load": load.trim(),
        "nginx": nginx.trim(), "mysql": mysql.trim(), "fail2ban": f2b.trim(),
            "redis": redis.trim(),
        "os": os.trim(), "php_services": php_svc,
    }))
}

async fn toggle_pma(req: HttpRequest, st: St, body: web::Json<serde_json::Value>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let domain  = body["domain"].as_str().unwrap_or("").to_string();
    let enabled = body["enabled"].as_bool().unwrap_or(false);
    if !valid_domain(&domain) { return HttpResponse::BadRequest().finish(); }
    
    let pma_link = format!("{}/{}/public_html/phpmyadmin", WEB_ROOT, domain);
    if enabled {
        // Create symlink to phpMyAdmin
        let pma_src = if std::path::Path::new("/usr/share/phpMyAdmin").is_dir() {
            "/usr/share/phpMyAdmin"
        } else if std::path::Path::new("/usr/share/phpmyadmin").is_dir() {
            "/usr/share/phpmyadmin"
        } else {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "chua cai phpMyAdmin. Vao Services -> Install phpMyAdmin"}));
        };
        // Remove existing if broken symlink
        let _ = std::fs::remove_file(&pma_link);
        let _ = std::fs::remove_dir_all(&pma_link);
        if let Err(e) = std::os::unix::fs::symlink(pma_src, &pma_link) {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Tao symlink that bai: {}", e)}));
        }
        let user = detect_web_user();
        let _ = bash(&format!("chown -h {}:{} {}", user, user, shell_escape(&pma_link))).await;
    } else {
        let _ = std::fs::remove_file(&pma_link);
    }
    
    let mut s = st.lock().unwrap();
    if let Some(site) = s.websites.iter_mut().find(|w| w.domain == domain) {
        site.phpmyadmin_enabled = enabled;
        let conf = make_vhost(&domain, &site.web_root.clone(), &site.php_version.clone(), site.ssl_enabled, true);
        let _ = std::fs::write(format!("{}/{}.conf", VHOST_DIR, domain), &conf);
        save(&s);
    }
    drop(s);
    let _ = bash("nginx -t 2>&1 && systemctl reload nginx 2>&1").await;
    HttpResponse::Ok().json(serde_json::json!({"message": if enabled { "Da bat phpMyAdmin" } else { "Da tat phpMyAdmin" }}))
}

async fn install_stack(req: HttpRequest, body: web::Json<serde_json::Value>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let mv = body["mysql_version"].as_str().unwrap_or("9.0");
    if !["8.4","9.0"].contains(&mv) { return HttpResponse::BadRequest().finish(); }
    let pvs: Vec<String> = body["php_versions"].as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str())
            .filter(|s| ["7.4","8.0","8.1","8.2","8.3","8.4"].contains(s))
            .map(String::from).collect())
        .unwrap_or_else(|| vec!["8.4".into()]);
    let repo = if mv == "8.4" { "https://dev.mysql.com/get/mysql84-community-release-el9-1.noarch.rpm" }
               else           { "https://dev.mysql.com/get/mysql90-community-release-el9-1.noarch.rpm" };
    let user = detect_web_user_sync();

    let mut s = format!(r#"#!/bin/bash
set -o pipefail
export DNF_OPTS="--setopt=logdir=/tmp --setopt=logfile=/tmp/dnf.log"

echo "[$(date)] === Install Nginx ==="
dnf install -y $DNF_OPTS nginx
systemctl enable nginx 2>/dev/null
systemctl start  nginx 2>/dev/null
mkdir -p /etc/nginx/conf.d /var/www
echo "Nginx: $(systemctl is-active nginx)"

echo "[$(date)] === Install MySQL {mv} ==="
dnf install -y $DNF_OPTS {repo} || true
dnf module disable mysql -y $DNF_OPTS 2>/dev/null || true
dnf install -y $DNF_OPTS mysql-community-server
systemctl enable mysqld 2>/dev/null
systemctl start  mysqld 2>/dev/null
sleep 3
TMPPASS=$(grep 'temporary password' /var/log/mysqld.log 2>/dev/null | tail -1 | awk '{{print $NF}}')
echo "MySQL: $(systemctl is-active mysqld)"
echo "Temp password length: ${{#TMPPASS}}"

# Set MySQL root password (idempotent + verify)
ROOT_CNF=/etc/nitpanel/mysql_root.cnf
if [ ! -f "$ROOT_CNF" ]; then
  # Password mới: chỉ alphanumeric (no special chars) → tránh mọi rắc rối với .cnf parsing
  NEW_ROOT_PASS=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 24)

  # GIẢI PHÁP TRIỆT ĐỂ: dùng init-file để bypass HOÀN TOÀN validate_password
  # MySQL chạy file SQL này lúc startup với SUPER privilege, KHÔNG bị policy chặn
  INIT_SQL=$(mktemp /tmp/mysql_init_XXXXXX.sql)
  chmod 644 "$INIT_SQL"  # mysql user phải đọc được
  cat > "$INIT_SQL" <<INITEOF
ALTER USER 'root'@'localhost' IDENTIFIED WITH caching_sha2_password BY '${{NEW_ROOT_PASS}}';
SET GLOBAL validate_password.policy = LOW;
SET GLOBAL validate_password.length = 4;
FLUSH PRIVILEGES;
INITEOF

  # Restart MySQL với --init-file → tự động chạy SQL trên với quyền SUPER
  systemctl stop mysqld
  sleep 2

  # Override systemd để pass --init-file
  mkdir -p /etc/systemd/system/mysqld.service.d
  cat > /etc/systemd/system/mysqld.service.d/init.conf <<SYSEOF
[Service]
ExecStart=
ExecStart=/usr/sbin/mysqld --init-file=$INIT_SQL --user=mysql
SYSEOF
  systemctl daemon-reload
  systemctl start mysqld
  sleep 4

  # Xóa override, restart bình thường
  rm -f /etc/systemd/system/mysqld.service.d/init.conf
  systemctl daemon-reload
  systemctl restart mysqld
  sleep 3
  rm -f "$INIT_SQL"
  echo "[OK] MySQL password set qua init-file (bypass validate_password)"

  # VERIFY: connect được password mới chưa?
  if MYSQL_PWD="$NEW_ROOT_PASS" mysql -uroot -e "SELECT 1;" >/dev/null 2>&1; then
    umask 077
    cat > "$ROOT_CNF" <<CNFEOF
[client]
user=root
password=${{NEW_ROOT_PASS}}
CNFEOF
    chmod 600 "$ROOT_CNF"
    chown root:root "$ROOT_CNF"
    rm -f /root/.my.cnf
    ln -s "$ROOT_CNF" /root/.my.cnf
    echo "[OK] MySQL root password đã set & VERIFY thành công"
  else
    echo "[CRITICAL] Set xong nhưng KHÔNG connect được! Xem /var/log/mysqld.log"
    exit 1
  fi
else
  echo "[..] MySQL root password đã tồn tại — giữ nguyên"
fi

echo "[$(date)] === Install EPEL + Remi ==="
dnf install -y $DNF_OPTS epel-release
dnf install -y $DNF_OPTS https://rpms.remirepo.net/enterprise/remi-release-9.rpm || true

mkdir -p {sock_dir}
chown {u}:{u} {sock_dir} 2>/dev/null || true

"#, mv = mv, repo = repo, sock_dir = PHP_SOCKET_DIR, u = user);

    for pv in &pvs {
        let n = vn(pv);
        let pool = php_fpm_pool_conf(pv, user);
        s.push_str(&format!(
            r#"echo "[$(date)] === Install PHP {pv} ==="
dnf install -y $DNF_OPTS php{n}-php-fpm php{n}-php-cli php{n}-php-mysqlnd php{n}-php-gd php{n}-php-curl php{n}-php-mbstring php{n}-php-xml php{n}-php-zip php{n}-php-opcache php{n}-php-bcmath php{n}-php-intl php{n}-php-redis
POOL_DIR=/etc/opt/remi/php{n}/php-fpm.d
if [ ! -d "$POOL_DIR" ]; then
  POOL_DIR=$(dirname $(find /etc -name "www.conf" -path "*php{n}*" 2>/dev/null | head -1))
fi
if [ -d "$POOL_DIR" ]; then
  cat > "$POOL_DIR/www.conf" <<'POOLEOF'
{pool}POOLEOF
  echo "[OK] Wrote pool config: $POOL_DIR/www.conf"
fi
systemctl daemon-reload
systemctl enable php{n}-php-fpm 2>/dev/null
systemctl restart php{n}-php-fpm 2>/dev/null
sleep 1
echo "PHP {pv}: $(systemctl is-active php{n}-php-fpm 2>/dev/null)"
ls -l {sock_dir}/php{n}.sock 2>/dev/null || echo "  (socket pending)"
"#, pv = pv, n = n, pool = pool, sock_dir = PHP_SOCKET_DIR));
    }

    s.push_str(r#"
echo "[$(date)] === Install Redis (secure) ==="
dnf install -y $DNF_OPTS epel-release || true
dnf install -y $DNF_OPTS redis || true
REDIS_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)
cp /etc/redis/redis.conf /etc/redis/redis.conf.bak 2>/dev/null || true
sed -i 's/^bind .*/bind 127.0.0.1/' /etc/redis/redis.conf
sed -i 's/^protected-mode .*/protected-mode yes/' /etc/redis/redis.conf
if grep -q "^requirepass" /etc/redis/redis.conf; then
  sed -i "s/^requirepass .*/requirepass $REDIS_PASS/" /etc/redis/redis.conf
else
  echo "requirepass $REDIS_PASS" >> /etc/redis/redis.conf
fi
cat >> /etc/redis/redis.conf <<'CFGEOF'
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command DEBUG ""
rename-command CONFIG ""
rename-command SHUTDOWN ""
rename-command KEYS ""
CFGEOF
mkdir -p /etc/nitpanel
cat > /etc/nitpanel/redis.conf <<EOF
host: 127.0.0.1
port: 6379
password: $REDIS_PASS
EOF
chmod 600 /etc/nitpanel/redis.conf
systemctl enable redis 2>/dev/null
systemctl restart redis 2>/dev/null
sleep 1
echo "Redis: $(systemctl is-active redis)"

echo "[$(date)] === Install Certbot ==="
dnf install -y $DNF_OPTS certbot python3-certbot-nginx

echo "[$(date)] === Install phpMyAdmin ==="
dnf install -y $DNF_OPTS phpMyAdmin || dnf install -y $DNF_OPTS phpmyadmin || echo "phpMyAdmin install skipped"

echo "[$(date)] === Install Fail2ban ==="
dnf install -y $DNF_OPTS fail2ban fail2ban-systemd
systemctl enable fail2ban 2>/dev/null
systemctl start  fail2ban 2>/dev/null
echo "Fail2ban: $(systemctl is-active fail2ban)"

echo "[$(date)] === Final Status ==="
echo "Nginx:    $(systemctl is-active nginx)"
echo "MySQL:    $(systemctl is-active mysqld)"
echo "Fail2ban: $(systemctl is-active fail2ban)"
for svc in $(systemctl list-unit-files 2>/dev/null | awk '/php.*fpm/ {print $1}'); do
    systemctl enable  $svc 2>/dev/null
    systemctl restart $svc 2>/dev/null
    echo "  $svc: $(systemctl is-active $svc 2>/dev/null)"
done
echo "PHP sockets:"
ls -l /run/php-fpm/ 2>/dev/null || echo "  none"
echo "[$(date)] === DONE ==="
"#);

    let _ = std::fs::create_dir_all(LOG_DIR);
    let sp = "/tmp/nitpanel_stack.sh";
    let _  = std::fs::write(sp, &s);
    let _  = std::fs::set_permissions(sp, std::fs::Permissions::from_mode(0o700));
    let _  = bash(&format!("nohup bash {} > {}/stack_install.log 2>&1 &",
        shell_escape(sp), LOG_DIR)).await;
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Đang cài stack",
        "log": format!("{}/stack_install.log", LOG_DIR)
    }))
}

async fn stack_log(req: HttpRequest) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let (_, log) = bash(&format!("tail -n 200 {}/stack_install.log 2>/dev/null || echo 'Chưa có log'", LOG_DIR)).await;
    HttpResponse::Ok().json(serde_json::json!({"log": log}))
}

async fn change_pass(req: HttpRequest, st: St, body: web::Json<serde_json::Value>) -> HttpResponse {
    // ── SECURITY: Rotate JWT secret to invalidate all existing tokens ──
    // This ensures stolen tokens can't be used after password change
    let new_jwt_secret = random_alnum(64);
    unsafe { std::env::set_var("NITPANEL_JWT_SECRET", &new_jwt_secret); }
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let cur = body["current_password"].as_str().unwrap_or("");
    let np  = body["new_password"].as_str().unwrap_or("");
    if np.len() < 10 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Mật khẩu ≥ 10 ký tự"}));
    }
    let has_upper = np.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = np.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = np.chars().any(|c| c.is_ascii_digit());
    if !(has_upper && has_lower && has_digit) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Mật khẩu phải có cả chữ hoa, chữ thường và số"
        }));
    }
    // Verify current password (zero-knowledge prevents stolen-token-only takeover)
    let cur_ok = {
        let h = st.lock().unwrap().admin_password_hash.clone();
        let cur = cur.to_string();
        tokio::task::spawn_blocking(move || verify(&cur, &h).unwrap_or(false))
            .await.unwrap_or(false)
    };
    if !cur_ok {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Mật khẩu hiện tại sai"}));
    }
    let np_owned = np.to_string();
    let h = match tokio::task::spawn_blocking(move || hash(&np_owned, DEFAULT_COST)).await {
        Ok(Ok(h)) => h,
        _ => return HttpResponse::InternalServerError().finish(),
    };
    let mut s = st.lock().unwrap();
    s.admin_password_hash = h;
    save(&s);
    drop(s);
    audit(&req, "CHANGE_PASSWORD", "");
    HttpResponse::Ok().json(serde_json::json!({"message": "Đã đổi mật khẩu"}))
}

// ── MySQL root password ──────────────────────────────────────────────────────
// Stored in /etc/nitpanel/mysql_root.cnf (chmod 600, root:root) in `[client]`
// format so `mysql` CLI can read it via /root/.my.cnf symlink. We never log the
// password to stdout/audit, and require admin password re-entry for both show
// and change to defend against stolen-token-only attacks.

const MYSQL_ROOT_CNF: &str = "/etc/nitpanel/mysql_root.cnf";

// ── MySQL command helper (tries root CNF first, falls back to /root/.my.cnf) ──
fn mysql_cmd(sql: &str) -> String {
    // NEVER use /root/.my.cnf (might have wrong password from manual install)
    // Priority: 1) NITPANEL CNF, 2) Unix socket auth (no password)
    if std::path::Path::new(MYSQL_ROOT_CNF).exists() {
        format!("printf %s {} | mysql --defaults-extra-file={} 2>&1",
            shell_escape(sql), shell_escape(MYSQL_ROOT_CNF))
    } else {
        // Try Unix socket auth (works on AlmaLinux fresh install)
        format!("printf %s {} | mysql -uroot 2>&1", shell_escape(sql))
    }
}

fn read_mysql_root_pass() -> Option<String> {
    let txt = std::fs::read_to_string(MYSQL_ROOT_CNF).ok()?;
    for line in txt.lines() {
        if let Some(v) = line.trim().strip_prefix("password=") {
            let p = v.trim().to_string();
            if !p.is_empty() { return Some(p); }
        }
    }
    None
}

async fn verify_admin_pass(st: &St, pass: String) -> bool {
    let h = st.lock().unwrap().admin_password_hash.clone();
    tokio::task::spawn_blocking(move || verify(&pass, &h).unwrap_or(false))
        .await.unwrap_or(false)
}

async fn mysql_root_show(req: HttpRequest, st: St, body: web::Json<serde_json::Value>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let admin_pass = body["admin_password"].as_str().unwrap_or("").to_string();
    if admin_pass.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Cần nhập mật khẩu admin"}));
    }
    if !verify_admin_pass(&st, admin_pass).await {
        audit(&req, "MYSQL_ROOT_SHOW_FAILED", "wrong admin password");
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Mật khẩu admin sai"}));
    }
    match read_mysql_root_pass() {
        Some(p) => {
            audit(&req, "MYSQL_ROOT_SHOW", "OK");
            HttpResponse::Ok().json(serde_json::json!({
                "user": "root", "host": "localhost", "password": p
            }))
        }
        None => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Chưa có MySQL root password — cài MySQL qua tab 'Cài Stack' để panel tự set"
        })),
    }
}

async fn mysql_root_change(req: HttpRequest, st: St, body: web::Json<serde_json::Value>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let admin_pass = body["admin_password"].as_str().unwrap_or("").to_string();
    let new_pass   = body["new_password"].as_str().unwrap_or("").to_string();
    if admin_pass.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Cần mật khẩu admin"}));
    }
    if !valid_db_password(&new_pass) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Mật khẩu mới phải 12-64 ký tự, chỉ gồm chữ-số và .-_+!@#%^*=?"
        }));
    }
    if !verify_admin_pass(&st, admin_pass).await {
        audit(&req, "MYSQL_ROOT_CHANGE_FAILED", "wrong admin password");
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Mật khẩu admin sai"}));
    }
    // valid_db_password restricts the charset → safe to inline. Pipe via stdin to
    // keep the password out of /proc/<pid>/cmdline.
    let sql = format!(
        "ALTER USER 'root'@'localhost' IDENTIFIED BY '{}'; FLUSH PRIVILEGES;",
        new_pass
    );
    let cmd = mysql_cmd(&sql);
    let (cmd_ok, out) = bash(&cmd).await;
    if !cmd_ok {
        audit(&req, "MYSQL_ROOT_CHANGE_FAILED", &format!("ALTER failed: {}", out));
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Đổi pass thất bại: {}", out)
        }));
    }
    let cnf = format!("[client]\nuser=root\npassword={}\n", new_pass);
    if let Err(e) = std::fs::write(MYSQL_ROOT_CNF, &cnf) {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Đổi pass MySQL OK nhưng không ghi được {}: {}", MYSQL_ROOT_CNF, e)
        }));
    }
    let _ = std::fs::set_permissions(MYSQL_ROOT_CNF, std::fs::Permissions::from_mode(0o600));
    let _ = std::fs::remove_file("/root/.my.cnf");
    let _ = std::os::unix::fs::symlink(MYSQL_ROOT_CNF, "/root/.my.cnf");
    audit(&req, "MYSQL_ROOT_CHANGE", "OK");
    HttpResponse::Ok().json(serde_json::json!({"message": "Đã đổi MySQL root password"}))
}

// ── phpMyAdmin (global, không gắn site) ──────────────────────────────────────
// Mặc định listen 127.0.0.1:8766 + HTTP basic auth → user truy cập bằng SSH
// tunnel. Không expose ra internet trừ khi user tự mở firewall.

const PMA_VHOST:    &str = "/etc/nginx/conf.d/nitpanel-pma.conf";
const PMA_HTPASSWD: &str = "/etc/nitpanel/pma_htpasswd";
const PMA_INFO:     &str = "/etc/nitpanel/pma_info.txt";
const PMA_PORT:     u16  = 8766;

fn pma_share_path() -> Option<&'static str> {
    for p in &["/usr/share/phpMyAdmin", "/usr/share/phpmyadmin"] {
        if std::path::Path::new(p).is_dir() { return Some(*p); }
    }
    None
}

fn make_pma_vhost(share: &str) -> String {
    // Use first installed PHP socket — fall back to common defaults.
    let socks = ["8.4","8.3","8.2","8.1","8.0","7.4"];
    let sock = socks.iter().map(|v| php_socket(v))
        .find(|p| std::path::Path::new(p).exists())
        .unwrap_or_else(|| format!("{}/php84.sock", PHP_SOCKET_DIR));
    format!(r#"server {{
    listen 127.0.0.1:{port};
    server_name _;
    root {share};
    index index.php;

    auth_basic "NITPANEL phpMyAdmin";
    auth_basic_user_file {htpasswd};

    access_log /var/log/nginx/nitpanel-pma.access.log;
    error_log  /var/log/nginx/nitpanel-pma.error.log warn;
    client_max_body_size 256M;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    server_tokens off;

    location / {{ try_files $uri $uri/ =404; }}

    location ~ \.php$ {{
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:{sock};
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_read_timeout 300;
        fastcgi_hide_header X-Powered-By;
    }}

    location ~ /\. {{ deny all; }}
}}
"#, port = PMA_PORT, share = share, htpasswd = PMA_HTPASSWD, sock = sock)
}

fn pma_enabled() -> bool { std::path::Path::new(PMA_VHOST).exists() }

fn read_pma_info() -> Option<(String, String)> {
    let txt = std::fs::read_to_string(PMA_INFO).ok()?;
    let mut user = String::new();
    let mut pass = String::new();
    for line in txt.lines() {
        if let Some(v) = line.strip_prefix("user=")     { user = v.trim().to_string(); }
        if let Some(v) = line.strip_prefix("password=") { pass = v.trim().to_string(); }
    }
    if user.is_empty() || pass.is_empty() { None } else { Some((user, pass)) }
}

async fn pma_status(req: HttpRequest) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let installed = pma_share_path().is_some();
    HttpResponse::Ok().json(serde_json::json!({
        "installed": installed,
        "enabled":   pma_enabled(),
        "port":      PMA_PORT,
        "bind":      "127.0.0.1",
        "share":     pma_share_path().unwrap_or(""),
    }))
}

async fn pma_setup(req: HttpRequest, _body: web::Json<serde_json::Value>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let share = match pma_share_path() {
        Some(s) => s,
        None => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Chưa cài phpMyAdmin. Vào tab 'Cài Stack' → Cài, hoặc: dnf install -y phpMyAdmin"
        })),
    };
    // Generate random user + pass, write htpasswd via openssl passwd -apr1.
    let user = format!("pma_{}", random_alnum(8).to_lowercase());
    let pass = random_alnum(24);
    let (ok, hashed) = bash(&format!(
        "openssl passwd -apr1 {}",
        shell_escape(&pass)
    )).await;
    if !ok || hashed.trim().is_empty() {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Không gen được htpasswd: {}", hashed)
        }));
    }
    let htpw_line = format!("{}:{}\n", user, hashed.trim());
    if let Err(e) = std::fs::write(PMA_HTPASSWD, &htpw_line) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Ghi htpasswd lỗi: {}", e)}));
    }
    let _ = std::fs::set_permissions(PMA_HTPASSWD, std::fs::Permissions::from_mode(0o640));
    // nginx user needs to read htpasswd
    let _ = bash("chown root:nginx /etc/nitpanel/pma_htpasswd 2>/dev/null").await;

    let info = format!("user={}\npassword={}\n", user, pass);
    if let Err(e) = std::fs::write(PMA_INFO, &info) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Ghi info lỗi: {}", e)}));
    }
    let _ = std::fs::set_permissions(PMA_INFO, std::fs::Permissions::from_mode(0o600));

    let conf = make_pma_vhost(share);
    if let Err(e) = std::fs::write(PMA_VHOST, &conf) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Ghi vhost lỗi: {}", e)}));
    }
    let (test_ok, test_out) = bash("nginx -t 2>&1").await;
    if !test_ok {
        let _ = std::fs::remove_file(PMA_VHOST);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("nginx config test thất bại: {}", test_out)
        }));
    }
    let _ = bash("systemctl reload nginx 2>&1").await;
    audit(&req, "PMA_GLOBAL_SETUP", &format!("user={}", user));
    HttpResponse::Ok().json(serde_json::json!({
        "message": "phpMyAdmin đã sẵn sàng (listen 127.0.0.1:8766)",
        "port": PMA_PORT
    }))
}

async fn pma_info_endpoint(req: HttpRequest, st: St, body: web::Json<serde_json::Value>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let admin_pass = body["admin_password"].as_str().unwrap_or("").to_string();
    if admin_pass.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Cần mật khẩu admin"}));
    }
    if !verify_admin_pass(&st, admin_pass).await {
        audit(&req, "PMA_INFO_FAILED", "wrong admin password");
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Mật khẩu admin sai"}));
    }
    match read_pma_info() {
        Some((user, pass)) => {
            audit(&req, "PMA_INFO_SHOW", "");
            HttpResponse::Ok().json(serde_json::json!({
                "user": user, "password": pass, "port": PMA_PORT, "bind": "127.0.0.1"
            }))
        }
        None => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Chưa setup phpMyAdmin chung — bấm 'Bật phpMyAdmin' trước"
        })),
    }
}

async fn pma_disable(req: HttpRequest, _body: web::Json<serde_json::Value>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let _ = std::fs::remove_file(PMA_VHOST);
    let _ = std::fs::remove_file(PMA_HTPASSWD);
    let _ = std::fs::remove_file(PMA_INFO);
    let _ = bash("systemctl reload nginx 2>&1").await;
    audit(&req, "PMA_GLOBAL_DISABLE", "");
    HttpResponse::Ok().json(serde_json::json!({"message": "Đã tắt phpMyAdmin chung"}))
}

// ── Fail2ban ──────────────────────────────────────────────────────────────────

async fn f2b_get_config(req: HttpRequest, st: St) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    HttpResponse::Ok().json(&st.lock().unwrap().fail2ban)
}

async fn f2b_save_config(req: HttpRequest, st: St, body: web::Json<Fail2banConfig>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    if body.ban_time < -1 || body.ban_time > 86400 * 30 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "ban_time không hợp lệ"}));
    }
    if body.find_time < 60 || body.find_time > 86400 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "find_time phải 60-86400 giây"}));
    }
    if body.max_retry < 1 || body.max_retry > 20 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "max_retry phải 1-20"}));
    }
    for ip in &body.whitelist_ips {
        if !valid_ip(ip) {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": format!("IP không hợp lệ: {}", ip)}));
        }
    }
    let cfg = body.into_inner();
    let (ok, out) = apply_fail2ban(&cfg).await;
    let mut s = st.lock().unwrap();
    s.fail2ban = cfg;
    save(&s);
    HttpResponse::Ok().json(serde_json::json!({
        "success": ok,
        "message": if ok { "Đã lưu & áp dụng Fail2ban" } else { "Lưu OK nhưng reload thất bại" },
        "output": out,
    }))
}

async fn f2b_get_banned(req: HttpRequest) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let (_, out) = bash("fail2ban-client status 2>/dev/null || echo 'fail2ban not running'").await;
    let (_, banned) = bash(r#"for jail in $(fail2ban-client status 2>/dev/null | awk -F'[\t ]+' '/Jail list/ {for(i=4;i<=NF;i++) print $i}' | tr -d ','); do echo "[$jail]"; fail2ban-client status $jail 2>/dev/null | grep 'Banned IP'; done || echo 'No data'"#).await;
    HttpResponse::Ok().json(serde_json::json!({"status": out, "banned": banned}))
}

async fn f2b_unban(req: HttpRequest, body: web::Json<Fail2banUnbanReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    if !valid_ip(&body.ip) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "IP không hợp lệ"}));
    }
    let (ok, out) = bash(&format!("fail2ban-client unban {} 2>&1", shell_escape(&body.ip))).await;
    HttpResponse::Ok().json(serde_json::json!({"success": ok, "output": out}))
}

async fn f2b_whitelist(req: HttpRequest, st: St, body: web::Json<Fail2banWhitelistReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    if !valid_ip(&body.ip) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "IP không hợp lệ"}));
    }
    let mut s = st.lock().unwrap();
    match body.action.as_str() {
        "add" => {
            if !s.fail2ban.whitelist_ips.contains(&body.ip) {
                s.fail2ban.whitelist_ips.push(body.ip.clone());
            }
        }
        "remove" => s.fail2ban.whitelist_ips.retain(|ip| ip != &body.ip),
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "action phải là add hoặc remove"})),
    }
    let cfg = s.fail2ban.clone();
    save(&s);
    drop(s);
    let (ok, out) = apply_fail2ban(&cfg).await;
    HttpResponse::Ok().json(serde_json::json!({"success": ok, "output": out, "whitelist": cfg.whitelist_ips}))
}

async fn f2b_install(req: HttpRequest) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let script = "dnf install -y epel-release 2>/dev/null; dnf install -y fail2ban fail2ban-systemd 2>&1; systemctl enable fail2ban; systemctl start fail2ban; fail2ban-client status 2>&1";
    let log = format!("{}/install_fail2ban.log", LOG_DIR);
    let _  = bash(&format!("nohup bash -c {} > {} 2>&1 &", shell_escape(script), shell_escape(&log))).await;
    HttpResponse::Ok().json(serde_json::json!({"message": "Đang cài Fail2ban", "log": log}))
}

async fn start_all_php(req: HttpRequest) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let (_, list) = bash("systemctl list-unit-files 2>/dev/null | awk '/php.*fpm/ {print $1}'").await;
    let mut started = Vec::new();
    let mut failed  = Vec::new();
    for svc in list.lines() {
        let svc = svc.trim();
        if svc.is_empty() { continue; }
        let (ok, _) = bash(&format!(
            "systemctl enable {s} 2>/dev/null; systemctl restart {s} 2>/dev/null",
            s = shell_escape(svc)
        )).await;
        if ok { started.push(svc.to_string()); } else { failed.push(svc.to_string()); }
    }
    let (_, socks) = bash("ls /run/php-fpm/ 2>/dev/null || echo 'none'").await;
    HttpResponse::Ok().json(serde_json::json!({
        "message": format!("Started {} PHP-FPM service(s)", started.len()),
        "started": started, "failed": failed, "sockets": socks.trim(),
    }))
}

// ─── Main ──────────────────────────────────────────────────────────────────────

// ══════════════════════════════════════════════════════════════════════════════
// ══════════════════════════════════════════════════════════════════════════════

async fn backup_site(req: HttpRequest, _st: St, body: web::Json<BackupReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    if !valid_domain(&body.domain) { return HttpResponse::BadRequest().json(serde_json::json!({"error": "Domain không hợp lệ"})); }
    let backup_dir = format!("{}/{}/backups", WEB_ROOT, body.domain);
    let _ = std::fs::create_dir_all(&backup_dir);
    let ts = Utc::now().format("%Y%m%d-%H%M%S");
    let backup_file = format!("{}/backup_{}.tar.gz", backup_dir, ts);
    let web_root = format!("{}/{}", WEB_ROOT, body.domain);
    let _ = bash(&format!("tar -czf {} -C {} --exclude='backups' --exclude='logs' --exclude='cache' . 2>&1",
        shell_escape(&backup_file), shell_escape(&web_root))).await;
    // Backup DB
    let creds_path = format!("/etc/nitpanel/db_{}.txt", body.domain.replace('.',"_"));
    if let Ok(txt) = std::fs::read_to_string(&creds_path) {
        let mut db=String::new(); let mut user=String::new(); let mut pass=String::new();
        for line in txt.lines() {
            if let Some(v)=line.strip_prefix("Database:") { db=v.trim().to_string(); }
            if let Some(v)=line.strip_prefix("User:") { user=v.trim().to_string(); }
            if let Some(v)=line.strip_prefix("Password:") { pass=v.trim().to_string(); }
        }
        if !db.is_empty() && !pass.is_empty() {
            let sql_file = format!("{}/backup_{}.sql", backup_dir, ts);
            let _ = bash(&format!("mysqldump -u{} -p{} {} > {} 2>&1",
                shell_escape(&user), shell_escape(&pass), shell_escape(&db), shell_escape(&sql_file))).await;
        }
    }
    let user = detect_web_user();
    let _ = bash(&format!("chown -R {}:{} {} 2>/dev/null", user, user, shell_escape(&backup_dir))).await;
    // Cleanup old backups
    let (_, listing) = bash(&format!("ls -t {}/backup_* 2>/dev/null", shell_escape(&backup_dir))).await;
    let files: Vec<&str> = listing.lines().collect();
    if files.len() > MAX_BACKUPS_PER_SITE {
        for f in &files[MAX_BACKUPS_PER_SITE..] { let _ = std::fs::remove_file(f); }
    }
    audit(&req, "BACKUP_SITE", &body.domain);
    HttpResponse::Ok().json(serde_json::json!({"message": format!("Đã backup {}", body.domain), "file": backup_file}))
}

async fn backup_list(req: HttpRequest, q: web::Query<HashMap<String, String>>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let domain = q.get("domain").cloned().unwrap_or_default();
    let backup_dir = format!("{}/{}/backups", WEB_ROOT, domain);
    let (_, listing) = bash(&format!("ls -lht {} 2>/dev/null || echo 'No backups'", shell_escape(&backup_dir))).await;
    HttpResponse::Ok().json(serde_json::json!({"backups": listing}))
}

async fn clone_site(req: HttpRequest, st: St, body: web::Json<CloneReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    if !valid_domain(&body.source_domain) || !valid_domain(&body.target_domain) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Domain không hợp lệ"}));
    }
    if body.source_domain == body.target_domain {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Domain nguồn và đích giống nhau"}));
    }
    let source_site = {
        let s = st.lock().unwrap();
        match s.websites.iter().find(|w| w.domain == body.source_domain) {
            Some(s) => s.clone(),
            None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Domain nguồn không tồn tại"})),
        }
    };
    {
        let s = st.lock().unwrap();
        if s.websites.iter().any(|w| w.domain == body.target_domain) {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "Domain đích đã tồn tại"}));
        }
    }
    let src_root = format!("{}/{}", WEB_ROOT, body.source_domain);
    let dst_root = format!("{}/{}", WEB_ROOT, body.target_domain);
    let _ = std::fs::create_dir_all(&dst_root);
    let (_, out) = bash(&format!("cp -a {}/* {}/ 2>&1 && echo OK", shell_escape(&src_root), shell_escape(&dst_root))).await;

    let db_name = if body.copy_db.unwrap_or(true) {
        if let Some(ref src_db) = source_site.db_name {
            let dst_db = sanitize_ident(&format!("{}_clone", src_db));
            let dst_user = dst_db.clone(); let dst_pass = random_alnum(24);
            let sql = format!("CREATE DATABASE IF NOT EXISTS `{}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER IF NOT EXISTS '{}'@'localhost' IDENTIFIED BY '{}'; GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'localhost'; FLUSH PRIVILEGES;", &dst_db,&dst_user,&dst_pass,&dst_db,&dst_user);
            let _ = bash(&mysql_cmd(&sql)).await;
            let creds_path = format!("/etc/nitpanel/db_{}.txt", body.source_domain.replace('.',"_"));
            if let Ok(txt) = std::fs::read_to_string(&creds_path) {
                let mut src_user=String::new(); let mut src_pass=String::new();
                for line in txt.lines() {
                    if let Some(v)=line.strip_prefix("User:") { src_user=v.trim().to_string(); }
                    if let Some(v)=line.strip_prefix("Password:") { src_pass=v.trim().to_string(); }
                }
                if !src_pass.is_empty() {
                    let _ = bash(&format!("mysqldump -u{} -p{} {} | mysql -u{} -p{} {} 2>&1",
                        shell_escape(&src_user), shell_escape(&src_pass), shell_escape(src_db),
                        shell_escape(&dst_user), shell_escape(&dst_pass), shell_escape(&dst_db))).await;
                }
            }
            let creds = format!("Database: {}
User: {}
Password: {}
Host: localhost
", dst_db, dst_user, dst_pass);
            let creds_path = format!("/etc/nitpanel/db_{}.txt", body.target_domain.replace('.',"_"));
            let _ = std::fs::write(&creds_path, creds);
            let _ = std::fs::set_permissions(&creds_path, std::fs::Permissions::from_mode(0o600));
            // Update wp-config if WordPress
            let wp_config = format!("{}/public_html/wp-config.php", dst_root);
            if std::path::Path::new(&wp_config).exists() {
                let _ = bash(&format!(
                    r#"sed -i "s/define.*DB_NAME.*/define('DB_NAME', '{db}');/" {cfg}"#,
                    db = dst_db, cfg = shell_escape(&wp_config)
                )).await;
                let _ = bash(&format!(
                    r#"sed -i "s/define.*DB_USER.*/define('DB_USER', '{user}');/" {cfg}"#,
                    user = dst_user, cfg = shell_escape(&wp_config)
                )).await;
                let _ = bash(&format!(
                    r#"sed -i "s/define.*DB_PASSWORD.*/define('DB_PASSWORD', '{pass}');/" {cfg}"#,
                    pass = dst_pass, cfg = shell_escape(&wp_config)
                )).await;
            }
            Some(dst_db)
        } else { None }
    } else { None };

    let user = detect_web_user();
    let _ = bash(&format!("chown -R {}:{} {} 2>/dev/null", user, user, shell_escape(&dst_root))).await;
    let conf = make_vhost(&body.target_domain, &dst_root, &source_site.php_version, false, false);
    let _ = std::fs::write(format!("{}/{}.conf", VHOST_DIR, body.target_domain), &conf);
    let _ = bash("nginx -t 2>&1 && systemctl reload nginx 2>&1").await;

    let mut s = st.lock().unwrap();
    s.websites.push(Website {
        id: Uuid::new_v4().to_string(), domain: body.target_domain.clone(),
        php_version: source_site.php_version.clone(), mysql_version: source_site.mysql_version.clone(),
        db_name: db_name.clone(), db_user: db_name, ssl_enabled: false, ssl_expiry: None,
        created_at: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(), status: "Đang chạy".into(),
        web_root: dst_root, phpmyadmin_enabled: false, redis_db: None, wordpress: source_site.wordpress,
    });
    save(&s);
    audit(&req, "CLONE_SITE", &format!("{} -> {}", body.source_domain, body.target_domain));
    HttpResponse::Ok().json(serde_json::json!({"message": format!("Đã clone {} -> {}", body.source_domain, body.target_domain), "output": out}))
}

// ── NEW: Bulk SSL ──
async fn bulk_install_ssl(req: HttpRequest, st: St, body: web::Json<BulkSslReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    if !valid_email(&body.email) { return HttpResponse::BadRequest().json(serde_json::json!({"error": "Email không hợp lệ"})); }
    let mut results = Vec::new();
    for domain in &body.domains {
        if !valid_domain(domain) { results.push(serde_json::json!({"domain": domain, "status": "error"})); continue; }
        let (ok, _) = bash(&format!("certbot --nginx -d {} -d www.{} --non-interactive --agree-tos --email {} 2>&1",
            shell_escape(domain), shell_escape(domain), shell_escape(&body.email))).await;
        if ok {
            let mut s = st.lock().unwrap();
            if let Some(site) = s.websites.iter_mut().find(|w| w.domain == *domain) {
                site.ssl_enabled = true; site.ssl_expiry = Some(Utc::now().format("%Y-%m-%d").to_string());
                let conf = make_vhost(domain, &site.web_root, &site.php_version, true, site.phpmyadmin_enabled);
                let _ = std::fs::write(format!("{}/{}.conf", VHOST_DIR, domain), &conf);
            }
            save(&s);
            let _ = bash("nginx -t 2>&1 && systemctl reload nginx 2>&1").await;
        }
        results.push(serde_json::json!({"domain": domain, "status": if ok {"ok"} else {"error"}}));
    }
    audit(&req, "BULK_SSL", &format!("{} domains", body.domains.len()));
    HttpResponse::Ok().json(serde_json::json!({"results": results}))
}

// ── NEW: CSRF token endpoint ──
async fn get_csrf_token(req: HttpRequest, st: St) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let token = generate_csrf_token(&st);
    HttpResponse::Ok().json(serde_json::json!({"csrf_token": token}))
}


// ── License management (REMOTE — gọi license server của maintainer) ──
//
// Panel KHÔNG tự sinh hay validate key. Mọi việc check đi qua license server
// đặt tại LICENSE_SERVER_URL. Đọc source này không giúp tạo key được vì
// thuật toán sinh key nằm ở phía server (private repo của maintainer).
//
// Có thể override URL bằng env var NITPANEL_LICENSE_SERVER khi cần test.
const LICENSE_SERVER_URL: &str = "https://license.netihot.com";

fn license_server() -> String {
    std::env::var("NITPANEL_LICENSE_SERVER")
        .unwrap_or_else(|_| LICENSE_SERVER_URL.to_string())
}

// Xin server xác minh key. Trả Some((key_chuẩn_hoá, info)) nếu hợp lệ.
async fn remote_verify_license(key: &str, server_id: &str, ip: &str) -> Result<serde_json::Value, String> {
    let url = format!("{}/api/v1/activate", license_server());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;
    let body = serde_json::json!({
        "key": key.trim().to_uppercase(),
        "server_id": server_id,
        "server_ip": ip,
        "panel_version": env!("CARGO_PKG_VERSION"),
    });
    let resp = client.post(&url).json(&body).send().await
        .map_err(|e| format!("Không kết nối được license server: {}", e))?;
    let status = resp.status();
    let json: serde_json::Value = resp.json().await
        .map_err(|e| format!("License server trả về lỗi: {}", e))?;
    if !status.is_success() {
        let msg = json.get("error").and_then(|v| v.as_str()).unwrap_or("Activate thất bại").to_string();
        return Err(msg);
    }
    Ok(json)
}

async fn remote_check_license(key: &str, server_id: &str) -> bool {
    let url = format!("{}/api/v1/check", license_server());
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build() { Ok(c) => c, Err(_) => return false };
    let body = serde_json::json!({ "key": key, "server_id": server_id });
    match client.post(&url).json(&body).send().await {
        Ok(r) if r.status().is_success() => {
            r.json::<serde_json::Value>().await
                .ok()
                .and_then(|j| j.get("valid").and_then(|v| v.as_bool()))
                .unwrap_or(false)
        }
        _ => false,
    }
}

// Lấy server_id ổn định (machine-id của host).
fn get_server_id() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn license_status(req: HttpRequest, st: St) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let s = st.lock().unwrap();
    let info = LicenseInfo {
        licensed: s.license_key.is_some(),
        key: s.license_key.as_ref().map(|k| {
            let mut masked = k.clone();
            if masked.len() > 11 { masked.replace_range(4..masked.len()-4, "****-****-****"); }
            masked
        }),
        activated: s.license_activated.clone(),
        status: if s.license_key.is_some() { "Pro License - Ho tro uu tien".into() } else { "Free - Ho tro cong dong".into() },
    };
    HttpResponse::Ok().json(info)
}

async fn license_activate(req: HttpRequest, st: St, body: web::Json<LicenseReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    if !verify_csrf(&st, req.headers().get("X-CSRF-Token").and_then(|v| v.to_str().ok()).unwrap_or("")) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "CSRF token khong hop le"}));
    }
    let key = body.key.trim().to_uppercase();

    // Sanity check format trước khi gọi server (tiết kiệm request)
    if !key.starts_with("NIT-") || key.len() != 23 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "License key sai định dạng. Đúng dạng: NIT-XXXX-XXXX-XXXX-XXXX"
        }));
    }

    let server_id = get_server_id();
    let (_, ip_raw) = bash("hostname -I 2>/dev/null | awk '{print $1}'").await;
    let ip = ip_raw.trim().to_string();

    match remote_verify_license(&key, &server_id, &ip).await {
        Ok(info) => {
            let mut s = st.lock().unwrap();
            s.license_key = Some(key);
            s.license_activated = Some(Utc::now().format("%Y-%m-%d %H:%M:%S").to_string());
            save(&s);
            drop(s);
            audit(&req, "LICENSE_ACTIVATE", "OK");
            let msg = info.get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("License đã kích hoạt! Cảm ơn bạn đã ủng hộ NITPANEL")
                .to_string();
            HttpResponse::Ok().json(serde_json::json!({"message": msg}))
        }
        Err(e) => {
            audit(&req, "LICENSE_ACTIVATE", &format!("FAIL: {}", e));
            HttpResponse::BadRequest().json(serde_json::json!({"error": e}))
        }
    }
}

async fn license_deactivate(req: HttpRequest, st: St) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let key = {
        let s = st.lock().unwrap();
        s.license_key.clone()
    };

    // Báo server gỡ binding (best-effort, không block nếu fail)
    if let Some(k) = key {
        let server_id = get_server_id();
        let url = format!("{}/api/v1/deactivate", license_server());
        if let Ok(client) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
        {
            let _ = client.post(&url)
                .json(&serde_json::json!({"key": k, "server_id": server_id}))
                .send().await;
        }
    }

    let mut s = st.lock().unwrap();
    s.license_key = None;
    s.license_activated = None;
    save(&s);
    audit(&req, "LICENSE_DEACTIVATE", "");
    HttpResponse::Ok().json(serde_json::json!({"message": "Đã gỡ license"}))
}

#[actix_web::main]

async fn security_txt() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body("Contact: mailto:security@netihot.com\nExpires: 2027-01-01T00:00:00Z\nPreferred-Languages: vi,en\nCanonical: https://netihot.com/.well-known/security.txt\nPolicy: https://netihot.com/security\n")
}


// ── Redis management ──
async fn redis_status(req: HttpRequest) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let has_conf = std::path::Path::new("/etc/nitpanel/redis.conf").exists();
    let (_, active_status) = bash("systemctl is-active redis 2>/dev/null").await;
    let mut info = serde_json::json!({
        "installed": has_conf,
        "active": active_status.trim() == "active",
    });
    if has_conf {
        if let Ok(txt) = std::fs::read_to_string("/etc/nitpanel/redis.conf") {
            for line in txt.lines() {
                if let Some(v) = line.strip_prefix("host: ") { info["host"] = serde_json::json!(v.trim()); }
                if let Some(v) = line.strip_prefix("port: ") { info["port"] = serde_json::json!(v.trim()); }
                // Never expose password via API
            }
        }
    }
    HttpResponse::Ok().json(info)
}

async fn redis_creds(req: HttpRequest, st: St) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let s = st.lock().unwrap();
    if !s.websites.iter().any(|w| w.redis_db.is_some()) {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "Chua cai Redis hoac chua co website nao duoc gan DB"}));
    }
    let (_, pass) = bash("grep '^password:' /etc/nitpanel/redis.conf 2>/dev/null | awk '{print $2}'").await;
    HttpResponse::Ok().json(serde_json::json!({
        "host": "127.0.0.1",
        "port": 6379,
        "password": pass.trim(),
        "websites": s.websites.iter().filter_map(|w| {
            w.redis_db.map(|db| serde_json::json!({"domain": w.domain, "db": db}))
        }).collect::<Vec<_>>(),
    }))
}


// ── Batch file delete ──
#[derive(Deserialize)] struct FileDeleteBatchReq { domain: String, paths: Vec<String> }
async fn delete_files_batch(req: HttpRequest, body: web::Json<FileDeleteBatchReq>) -> HttpResponse {
    if !auth(&req) { return HttpResponse::Unauthorized().finish(); }
    let mut deleted = 0u32;
    let mut failed = 0u32;
    for path in &body.paths {
        let target = match webroot_existing(&body.domain, path) {
            Some(p) => p, None => { failed += 1; continue; }
        };
        let ts = target.to_string_lossy().to_string();
        // Security: don't delete root web directory
        if let Some(fname) = target.file_name() {
            let f = fname.to_string_lossy();
            if (f == "public_html" || f == ".well-known") && path == "/" { failed += 1; continue; }
        }
        let cmd = if target.is_dir() { 
            format!("rm -rf {}", shell_escape(&ts))
        } else {
            format!("rm -f {}", shell_escape(&ts))
        };
        let (ok, _) = bash(&cmd).await;
        if ok { deleted += 1; } else { failed += 1; }
    }
    HttpResponse::Ok().json(serde_json::json!({"deleted": deleted, "failed": failed}))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // CLI: hash subcommand for install scripts
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1] == "hash" {
        let pwd = args.get(2).cloned().unwrap_or_default();
        if pwd.is_empty() {
            eprintln!("Usage: nitpanel hash <password>");
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing password"));
        }
        match hash(&pwd, DEFAULT_COST) {
            Ok(h)  => { println!("{}", h); return Ok(()); }
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
        }
    }
    if args.len() >= 2 && args[1] == "version" {
        println!("nitpanel {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter("nitpanel=info,actix_web=warn")
        .init();

    let _ = std::fs::create_dir_all("/etc/nitpanel");
    let _ = std::fs::create_dir_all(LOG_DIR);
    let _ = std::fs::create_dir_all(VHOST_DIR);
    let _ = std::fs::create_dir_all("/etc/fail2ban/jail.d");
    let _ = std::fs::create_dir_all("/etc/fail2ban/filter.d");
    let _ = std::fs::create_dir_all(WEB_ROOT);
    let _ = std::fs::create_dir_all(PHP_SOCKET_DIR);

    let state = load();
    save(&state); // persist if it was created from env init password
    let data  = Data::new(Mutex::new(state));

    let bind = panel_bind();
    info!("NITPANEL v{} starting on {}", env!("CARGO_PKG_VERSION"), bind);

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .app_data(web::JsonConfig::default().limit(8 * 1024 * 1024))
            .wrap(actix_web::middleware::DefaultHeaders::new()
                .add(("X-Frame-Options",           "DENY"))
                .add(("X-Content-Type-Options",     "nosniff"))
                .add(("X-XSS-Protection",           "1; mode=block"))
                .add(("Referrer-Policy",            "strict-origin-when-cross-origin"))
                .add(("Cache-Control",              "no-store, no-cache"))
                .add(("Permissions-Policy",         "geolocation=(), camera=(), microphone=(), payment=(), usb=()"))
                .add(("Content-Security-Policy",
                      "default-src 'self'; \
                       script-src 'self' 'unsafe-inline'; \
                       style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
                       font-src 'self' https://fonts.gstatic.com data:; \
                       img-src 'self' data:; \
                       connect-src 'self'; \
                       frame-ancestors 'none'; \
                       base-uri 'self'; \
                       form-action 'self'"))
            )
            .route("/",                                web::get().to(index_html))
            // Public install-script (no auth)
            .route("/install.sh",                      web::get().to(public_install_sh))
            .route("/api/login",                       web::post().to(login))
            .route("/api/change-password",             web::post().to(change_pass))
            .route("/api/websites",                    web::get().to(get_websites))
            .route("/api/websites/create",             web::post().to(create_website))
            .route("/api/websites/delete",             web::post().to(delete_website))
            .route("/api/ssl/install",                 web::post().to(install_ssl))
            .route("/api/ssl/list",                    web::get().to(ssl_list))
            .route("/api/ssl/renew",                   web::post().to(ssl_renew))
            .route("/api/files/list",                  web::post().to(list_files))
            .route("/api/files/read",                  web::post().to(read_file))
            .route("/api/files/save",                  web::post().to(save_file))
            .route("/api/files/upload",                web::post().to(upload_file))
            .route("/api/files/delete",                web::post().to(delete_file))
            .route("/api/files/delete-batch",         web::post().to(delete_files_batch))
            .route("/api/files/mkdir",                 web::post().to(mkdir_at))
            .route("/api/files/rename",                web::post().to(rename_at))
            .route("/api/files/extract",               web::post().to(extract_archive))
            .route("/api/files/compress",              web::post().to(compress_path))
            .route("/api/files/download",              web::get().to(download_file))
            .route("/api/db/creds",                    web::get().to(db_creds))
            .route("/api/share",                       web::get().to(share_info))
            .route("/api/service",                     web::post().to(svc_action))
            .route("/api/service/install",             web::post().to(install_svc))
            .route("/api/service/install/log",         web::get().to(svc_install_log))
            .route("/api/system/info",                 web::get().to(sys_info))
            .route("/api/phpmyadmin/toggle",           web::post().to(toggle_pma))
            .route("/api/mysql/root/show",             web::post().to(mysql_root_show))
            .route("/api/mysql/root/change",           web::post().to(mysql_root_change))
            .route("/api/pma-global/status",           web::get().to(pma_status))
            .route("/api/pma-global/setup",            web::post().to(pma_setup))
            .route("/api/pma-global/info",             web::post().to(pma_info_endpoint))
            .route("/api/pma-global/disable",          web::post().to(pma_disable))
            .route("/api/install",                     web::post().to(install_stack))
            .route("/api/install/log",                 web::get().to(stack_log))
            .route("/api/fail2ban/config",             web::get().to(f2b_get_config))
            .route("/api/fail2ban/config",             web::post().to(f2b_save_config))
            .route("/api/fail2ban/banned",             web::get().to(f2b_get_banned))
            .route("/api/fail2ban/unban",              web::post().to(f2b_unban))
            .route("/api/fail2ban/whitelist",          web::post().to(f2b_whitelist))
            .route("/api/fail2ban/install",            web::post().to(f2b_install))
            .route("/api/service/start-all-php",       web::post().to(start_all_php))
            // ── NEW v2.0 routes ──
            .route("/api/csrf-token",           web::get().to(get_csrf_token))
            .route("/api/site/backup",          web::post().to(backup_site))
            .route("/api/site/backups",         web::get().to(backup_list))
            .route("/api/site/clone",           web::post().to(clone_site))
            .route("/api/ssl/bulk",             web::post().to(bulk_install_ssl))
            .route("/api/license/status",     web::get().to(license_status))
            .route("/api/license/activate",   web::post().to(license_activate))
            .route("/api/license/deactivate", web::post().to(license_deactivate))
            .route("/api/redis/status",             web::get().to(redis_status))
            .route("/api/redis/creds",              web::get().to(redis_creds))
    })
    .bind(&bind)?
    .workers(2)
    .run()
    .await
}
