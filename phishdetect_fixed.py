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

class URLFeatureExtractor:
    def __init__(self):
        with open("model/feature_names.json") as f:
            self.expected_features = json.load(f)
        
        # Enhanced detection lists
        self.sensitive_words = [
            'login', 'signin', 'verify', 'account', 'secure',
            'bank', 'payment', 'update', 'confirm', 'password'
        ]
        
        # Official domains for major brands (must be lowercase)
        self.official_domains = [
            'paypal.com', 'www.paypal.com',
            'amazon.com', 'www.amazon.com',
            'apple.com', 'www.apple.com',
            'google.com', 'www.google.com',
            'microsoft.com', 'www.microsoft.com'
        ]
    
    def is_official_domain(self, hostname):
        """Check if the domain is an official brand domain"""
        return hostname.lower() in self.official_domains
    
    def check_brand_spoofing(self, hostname):
        """Detect brand names used in suspicious ways"""
        if self.is_official_domain(hostname):
            return 0
            
        ext = tldextract.extract(hostname.lower())
        main_domain = f"{ext.domain}.{ext.suffix}"
        
        # List of brand names to check
        brand_names = ['paypal', 'amazon', 'apple', 'google', 'microsoft']
        
        # Check if brand appears in subdomains but not main domain
        for brand in brand_names:
            if brand in hostname.lower() and brand not in main_domain:
                return 1
        return 0
    
    def extract_all_features(self, url):
        """Extract all features with proper official domain handling"""
        try:
            parsed = urlparse(url)
            ext = tldextract.extract(url)
            hostname = parsed.netloc.lower()
            path = parsed.path
            query = parsed.query
            
            # Check if official domain
            is_official = self.is_official_domain(hostname)
            
            # Initialize with default values
            features = {name: 0 for name in self.expected_features}
            
            # Basic URL features
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
                'NumQueryComponents': len(parse_qs(query)),
                'NumAmpersand': url.count('&'),
                'NumHash': url.count('#'),
                'NumNumericChars': sum(c.isdigit() for c in url),
                'NoHttps': int(parsed.scheme != 'https'),
                'RandomString': int(bool(re.search(r'[0-9a-f]{8}', url))),
                'IpAddress': int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', hostname))),
                'HttpsInHostname': int('https' in hostname),
                'HostnameLength': len(hostname),
                'PathLength': len(path),
                'QueryLength': len(query),
                'DoubleSlashInPath': int('//' in path),
                'SubdomainLevelRT': math.log(max(1, ext.subdomain.count('.') + 1)),
                'UrlLengthRT': math.log(max(1, len(url))),
                'IsOfficialDomain': int(is_official),
                'BrandSpoofing': 0 if is_official else self.check_brand_spoofing(hostname),
                'NumSensitiveWords': 0 if is_official else sum(
                    word in url.lower() for word in self.sensitive_words
                )
            })
            
            return features
        except Exception as e:
            print(f"Feature extraction error: {str(e)}")
            return {name: 0 for name in self.expected_features}

def print_result(result):
    """Print results with color coding"""
    if 'error' in result:
        print(f"{Fore.RED}Error: {result['error']}{Style.RESET_ALL}")
        return
    
    # Result line
    if "PHISHING" in result["result"]:
        print(f"\n{Fore.RED}{result['result']} (Confidence: {result['confidence']}){Style.RESET_ALL}")
    else:
        print(f"\n{Fore.GREEN}{result['result']} (Confidence: {result['confidence']}){Style.RESET_ALL}")
    
    # Threat indicators
    if result.get('threat_indicators'):
        print(f"\n{Fore.YELLOW}🚨 Threat Indicators:{Style.RESET_ALL}")
        for indicator in result['threat_indicators']:
            print(f"- {Fore.RED}{indicator}{Style.RESET_ALL}")
    
    # Key features
    print(f"\n{Fore.CYAN}🔍 Key Features:{Style.RESET_ALL}")
    features = result['features']
    feature_map = {
        'UrlLength': 'URL Length',
        'NoHttps': 'Uses HTTPS',
        'SubdomainLevel': 'Subdomains',
        'NumSensitiveWords': 'Sensitive Words',
        'BrandSpoofing': 'Brand Spoofing',
        'IsOfficialDomain': 'Official Domain'
    }
    
    for feat, label in feature_map.items():
        value = features.get(feat, 0)
        if feat == 'NoHttps':
            display = 'No' if value else 'Yes'
            color = Fore.RED if value else Fore.GREEN
        elif feat in ('BrandSpoofing', 'IsOfficialDomain'):
            display = 'Yes' if value else 'No'
            color = Fore.RED if (feat == 'BrandSpoofing' and value) else (
                Fore.GREEN if (feat == 'IsOfficialDomain' and value) else Fore.WHITE
            )
        elif feat == 'NumSensitiveWords':
            color = Fore.RED if value > 2 else Fore.WHITE
            display = value
        else:
            display = value
            color = Fore.WHITE
        
        print(f"- {label}: {color}{display}{Style.RESET_ALL}")

def predict_phishing(url):
    """Main prediction function"""
    try:
        model = joblib.load("model/phishing_model.pkl")
        extractor = URLFeatureExtractor()
        features = extractor.extract_all_features(url)
        
        # Official domains are always legitimate
        if features.get('IsOfficialDomain', 0):
            return {
                "result": "✅ Legitimate",
                "confidence": "100%",
                "threat_indicators": [],
                "features": features
            }
        
        features_df = pd.DataFrame([features])[extractor.expected_features]
        
        probability = model.predict_proba(features_df)[0][1]
        prediction = 1 if probability > 0.7 else 0
        
        # Threat analysis
        threat_indicators = []
        if features.get('NoHttps', 0): 
            threat_indicators.append("No HTTPS")
        if features.get('NumSensitiveWords', 0) > 2:
            threat_indicators.append(f"{features['NumSensitiveWords']} sensitive words")
        if features.get('BrandSpoofing', 0):
            threat_indicators.append("Brand spoofing detected")
        
        return {
            "result": "⚠ PHISHING" if prediction == 1 else "✅ Legitimate",
            "confidence": f"{min(99, int(probability*100))}%",
            "threat_indicators": threat_indicators,
            "features": features
        }
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    print(f"{Fore.BLUE}=== Phishing URL Detector ==={Style.RESET_ALL}")
    print(f"{Fore.WHITE}Enter a URL to analyze (or 'quit' to exit){Style.RESET_ALL}")
    
    while True:
        try:
            url = input(f"\n{Fore.YELLOW}URL:{Style.RESET_ALL} ").strip()
            if url.lower() in ('quit', 'exit'):
                break
            
            # Auto-add http:// if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            result = predict_phishing(url)
            print_result(result)
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}Thank you for using the Phishing Detector!{Style.RESET_ALL}")