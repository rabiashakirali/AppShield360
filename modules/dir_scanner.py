#!/usr/bin/env python3
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

class DirScanner:
    def __init__(self, target, threads=50, timeout=8):
        self.target = target.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.found = []
        
        self.paths = [
            "/.env","/.git/HEAD","/.git/config","/.svn/entries","/.htaccess","/.htpasswd",
            "/robots.txt","/sitemap.xml","/sitemap.xml.gz","/crossdomain.xml","/clientaccesspolicy.xml",
            "/admin","/administrator","/admin.php","/admin/login","/admin/login.php",
            "/wp-admin","/wp-login.php","/wp-content/","/wp-includes/",
            "/phpmyadmin","/pma","/mysql","/dbadmin","/sqladmin",
            "/api","/api/v1","/api/v2","/swagger-ui.html","/api-docs","/swagger.json",
            "/graphql","/graphiql","/playground",
            "/login","/signin","/register","/signup","/auth","/oauth","/sso",
            "/backup","/backups","/bak","/old","/archive","/archives",
            "/test","/testing","/dev","/devel","/development","/staging","/demo",
            "/config","/configuration","/settings","/setup","/install",
            "/debug","/console","/shell","/cmd","/terminal",
            "/.DS_Store","/Thumbs.db","/.idea","/.vscode","/nbproject",
            "/composer.json","/package.json","/requirements.txt","/Gemfile",
            "/Dockerfile","/docker-compose.yml","/.dockerignore",
            "/.github","/.gitlab-ci.yml","/Jenkinsfile",
            "/phpinfo.php","/info.php","/xdebug","/server-status","/server-info",
            "/trace","/actuator","/actuator/health","/actuator/env","/actuator/configprops",
            "/metrics","/prometheus","/health","/healthz","/ready","/live",
            "/.well-known/security.txt","/security.txt","/humans.txt",
            "/cdn-cgi/trace","/cdn-cgi/status",
        ]
        
        self.backup_exts = [".bak",".backup",".old",".orig",".save",".swp",".tmp",".copy",
                           ".zip",".tar.gz",".tgz",".rar",".sql",".dump",".db",".sqlite",
                           ".txt",".log",".config",".conf",".cfg",".ini",".json",".xml"]
        
        # Generate backup variations for common files
        backup_paths = []
        for p in ["/.env","/config.php","/database.php","/wp-config.php","/settings.py",
                  "/app.py","/index.php","/home.php","/config.json","/web.config"]:
            for ext in self.backup_exts:
                backup_paths.append(p + ext)
                backup_paths.append(p + ext + ".txt")
        self.paths.extend(backup_paths)

    def _check(self, path):
        try:
            url = f"{self.target}{path}"
            r = requests.get(url, timeout=self.timeout, allow_redirects=False,
                headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code in [200, 201, 401, 403, 407, 500]:
                size = len(r.content)
                # Skip generic 404 pages
                if r.status_code == 200 and size < 100:
                    return None
                return (path, r.status_code, size)
        except:
            pass
        return None

    def scan(self):
        print(f"[+] Scanning directories...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check, p): p for p in self.paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.found.append(result)
        
        self.found.sort(key=lambda x: x[0])
        for path, code, size in self.found:
            print(f"    [+] {path} [{code}] ({size} bytes)")
        
        return self.found