import requests
import socket
import ssl
import re

class Color:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class SiteGuard:
    def __init__(self, url):
        self.url = url
        self.report = {"url": url}
    
    def check_accessibility(self):
        try:
            response = requests.get(self.url, timeout=5)
            self.report["status_code"] = response.status_code
            self.report["accessible"] = response.status_code == 200
        except requests.RequestException as e:
            self.report["accessible"] = False
            self.report["error"] = str(e)
            return False
        return True
    
    def check_https(self):
        https_url = self.url.replace("http://", "https://")
        try:
            https_response = requests.get(https_url, timeout=5)
            self.report["https_supported"] = https_response.status_code == 200
        except requests.RequestException:
            self.report["https_supported"] = False
        self.report["redirects_to_https"] = https_url.startswith("https://")
    
    def check_security_headers(self, response):
        security_headers = ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"]
        self.report["missing_headers"] = [header for header in security_headers if header not in response.headers]
    
    def check_open_ports(self):
        domain = self.url.replace("http://", "").replace("https://", "").split("/")[0]
        common_ports = [80, 443, 21, 22, 25, 3306, 8080]
        open_ports = []
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((domain, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        self.report["open_ports"] = open_ports
    
    def check_brute_force_risk(self):
        login_pages = ["/admin", "/login", "/wp-login.php", "/user/login"]
        brute_force_risk = []
        existing_login_pages = []
        for page in login_pages:
            try:
                login_response = requests.get(self.url + page, timeout=5)
                if login_response.status_code == 200:
                    brute_force_risk.append(page)
                    existing_login_pages.append(self.url + page)
            except requests.RequestException:
                pass
        self.report["brute_force_risk"] = brute_force_risk
        self.report["existing_login_pages"] = existing_login_pages
    
    def check_exposed_files(self):
        sensitive_files = ["/robots.txt", "/.git/config", "/.env", "/config.php", "/database.sql", "/.htaccess"]
        accessible_files = []
        for file in sensitive_files:
            try:
                response = requests.get(self.url + file, timeout=5)
                if response.status_code == 200:
                    accessible_files.append(self.url + file)
            except requests.RequestException:
                pass
        self.report["exposed_files"] = accessible_files
    
    def generate_report(self):
        if not self.check_accessibility():
            return self.report
        response = requests.get(self.url, timeout=5)
        self.check_https()
        self.check_security_headers(response)
        self.check_open_ports()
        self.check_brute_force_risk()
        self.check_exposed_files()
        
        if self.report["exposed_files"]:
            self.report["accessible_sensitive_files"] = ", ".join(self.report["exposed_files"])
        else:
            self.report["accessible_sensitive_files"] = "Nenhum arquivo sensível acessível encontrado."

        if self.report["existing_login_pages"]:
            self.report["existing_login_routes"] = ", ".join(self.report["existing_login_pages"])
        else:
            self.report["existing_login_routes"] = "Nenhuma rota de login encontrada."
        
        return self.report

if __name__ == "__main__":
    site = input("Digite o site para analisar (ex: http://example.com): ")
    scanner = SiteGuard(site)
    report = scanner.generate_report()
    
    print("\n" + Color.GREEN + "--- RELATÓRIO DE SEGURANÇA ---" + Color.RESET)
    for key, value in report.items():
        if key == "accessible" and value:
            print(f"{Color.GREEN}{key}: {value}{Color.RESET}")
        elif key == "accessible" and not value:
            print(f"{Color.RED}{key}: {value}{Color.RESET}")
        elif key == "missing_headers" and value:
            print(f"{Color.RED}{key}: {', '.join(value)}{Color.RESET}")
        elif key == "exposed_files" and value:
            print(f"{Color.RED}{key}: {', '.join(value)}{Color.RESET}")
        elif key == "existing_login_pages" and value:
            print(f"{Color.RED}{key}: {', '.join(value)}{Color.RESET}")
        else:
            print(f"{Color.BLUE}{key}: {value}{Color.RESET}")
