import joblib
import pandas as pd
import tldextract
from urllib.parse import urlparse, parse_qs
import re
import json
import math
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class PhishingDetector:
    def __init__(self):
        try:
            self.model = joblib.load("model/phishing_model.pkl")
            with open("model/feature_names.json") as f:
                self.feature_names = json.load(f)
            self.default_features = {name: 0 for name in self.feature_names}
        except Exception as e:
            print(f"{Fore.RED}Failed to load model: {str(e)}{Style.RESET_ALL}")
            exit(1)
        
        self.sensitive_words = [
            'login', 'signin', 'verify', 'account', 'secure',
            'bank', 'payment', 'update', 'confirm', 'password'
        ]
        
        # Expanded list of official domains
        self.official_domains = [
            'paypal.com', 'www.paypal.com', 'paypalobjects.com',
            'amazon.com', 'www.amazon.com', 'amazonaws.com',
            'apple.com', 'www.apple.com', 'icloud.com',
            'google.com', 'www.google.com', 'googleapis.com',
            'microsoft.com', 'www.microsoft.com', 'live.com',
            'ebay.com', 'www.ebay.com',
            'netflix.com', 'www.netflix.com',
            'bankofamerica.com', 'www.bankofamerica.com',
            'wellsfargo.com', 'www.wellsfargo.com',
            'chase.com', 'www.chase.com'
        ]
        
        self.known_brands = ['paypal', 'amazon', 'apple', 'google', 'microsoft',
                           'ebay', 'netflix', 'bankofamerica', 'wellsfargo', 'chase']

    def is_official(self, hostname):
        """Check if domain is official, including subdomains of official domains"""
        ext = tldextract.extract(hostname.lower())
        base_domain = f"{ext.domain}.{ext.suffix}"
        return base_domain in self.official_domains or hostname.lower() in self.official_domains

    def check_brand_usage(self, hostname):
        if self.is_official(hostname):
            return 0
            
        ext = tldextract.extract(hostname.lower())
        main_domain = f"{ext.domain}.{ext.suffix}"
        
        for brand in self.known_brands:
            if brand in hostname.lower() and brand not in main_domain:
                return 1
        return 0

    def extract_features(self, url):
        features = self.default_features.copy()
        
        try:
            parsed = urlparse(url)
            ext = tldextract.extract(url)
            hostname = parsed.netloc.lower()
            path = parsed.path.lower()
            is_official = self.is_official(hostname)
            
            features.update({
                'NumDots': url.count('.'),
                'SubdomainLevel': ext.subdomain.count('.') + 1,
                'PathLevel': path.count('/') - 1 if path else 0,
                'UrlLength': len(url),
                'NumDash': url.count('-'),
                'NumDashInHostname': hostname.count('-'),
                'AtSymbol': int('@' in url),
                'TildeSymbol': int('~' in url),
                'NumUnderscore': url.count('_'),
                'NumPercent': url.count('%'),
                'NumQueryComponents': len(parse_qs(parsed.query)),
                'NumAmpersand': url.count('&'),
                'NumHash': url.count('#'),
                'NumNumericChars': sum(c.isdigit() for c in url),
                'NoHttps': int(parsed.scheme != 'https'),
                'RandomString': int(bool(re.search(r'[0-9a-f]{8}', url))),
                'IpAddress': int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', hostname))),
                'HttpsInHostname': int('https' in hostname),
                'HostnameLength': len(hostname),
                'PathLength': len(path),
                'QueryLength': len(parsed.query),
                'DoubleSlashInPath': int('//' in path),
                'SubdomainLevelRT': math.log(max(1, ext.subdomain.count('.') + 1)),
                'UrlLengthRT': math.log(max(1, len(url))),
                'IsOfficialDomain': int(is_official),
                'BrandSpoofing': self.check_brand_usage(hostname) if 'BrandSpoofing' in self.feature_names else 0,
                'NumSensitiveWords': 0 if is_official else sum(
                    word in url.lower() for word in self.sensitive_words
                )
            })
            
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Feature extraction error - {str(e)}{Style.RESET_ALL}")
        
        return features

    def analyze(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            features = self.extract_features(url)
            
            if features.get('IsOfficialDomain', 0):
                return {
                    "result": "✅ Legitimate",
                    "confidence": "100%",
                    "threats": [],
                    "features": features
                }
            
            features_df = pd.DataFrame([features])[self.feature_names]
            proba = self.model.predict_proba(features_df)[0][1]
            is_phishing = proba > 0.7
            
            threats = []
            if features['NoHttps']: 
                threats.append("No HTTPS")
            if features.get('NumSensitiveWords', 0) > 2:
                threats.append(f"{features['NumSensitiveWords']} sensitive words")
            if features.get('BrandSpoofing', 0):
                threats.append("Brand spoofing detected")
            
            return {
                "result": "⚠ PHISHING" if is_phishing else "✅ Legitimate",
                "confidence": f"{min(99, int(proba*100))}%",
                "threats": threats,
                "features": features
            }
            
        except Exception as e:
            return {"error": str(e)}

def print_results(result):
    if 'error' in result:
        print(f"{Fore.RED}Error: {result['error']}{Style.RESET_ALL}")
        return
    
    color = Fore.RED if "PHISHING" in result["result"] else Fore.GREEN
    print(f"\n{color}{result['result']} (Confidence: {result['confidence']}){Style.RESET_ALL}")
    
    if result.get('threats'):
        print(f"\n{Fore.YELLOW}🚨 Threats:{Style.RESET_ALL}")
        for threat in result['threats']:
            print(f"- {Fore.RED}{threat}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}🔍 Features:{Style.RESET_ALL}")
    features = result['features']
    for name in ['UrlLength', 'NoHttps', 'SubdomainLevel', 
                'NumSensitiveWords', 'BrandSpoofing', 'IsOfficialDomain']:
        if name not in features:
            continue
            
        value = features[name]
        if name == 'NoHttps':
            text = 'No' if value else 'Yes'
            color = Fore.RED if value else Fore.GREEN
        elif name == 'BrandSpoofing':
            text = 'Yes' if value else 'No'
            color = Fore.RED if value else Fore.GREEN
        elif name == 'IsOfficialDomain':
            text = 'Yes' if value else 'No'
            color = Fore.GREEN if value else Fore.WHITE
        elif name == 'NumSensitiveWords':
            text = value
            color = Fore.RED if value > 2 else Fore.WHITE
        else:
            text = value
            color = Fore.WHITE
            
        print(f"- {name}: {color}{text}{Style.RESET_ALL}")

def main():
    print(f"{Fore.BLUE}=== Phishing Detector ==={Style.RESET_ALL}")
    print(f"Enter URLs to check (or 'quit' to exit)\n")
    
    detector = PhishingDetector()
    
    while True:
        try:
            url = input(f"{Fore.YELLOW}URL:{Style.RESET_ALL} ").strip()
            if url.lower() in ('quit', 'exit'):
                break
                
            result = detector.analyze(url)
            print_results(result)
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Exiting...{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}Scanning complete. Stay safe online!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()