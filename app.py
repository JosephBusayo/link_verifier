from flask import Flask, request, render_template
import validators
import requests
import socket

app = Flask(__name__)

# AbuseIPDB API key
ABUSEIPDB_API_KEY = '1f479be99eee3eec9ea045e73e29dfe4d2c5cdabdb9f80c499dfa6f84af614d09b93c16fe19226d0'

# Extended list of known phishing URLs with detailed reports
KNOWN_PHISHING_URLS = {
    "http://paypal.com.verify-login-account.info": {
        "is_phishing": True,
        "report": "This is a known PayPal phishing site. It attempts to trick users into entering their PayPal login credentials. The domain uses a subdomain structure to appear legitimate, but it's not an official PayPal domain. Never enter your credentials on this site.",
        "risk_score": 100
    },
    "https://secure-facebook-login.com": {
        "is_phishing": True,
        "report": "This is a Facebook phishing site. It mimics the Facebook login page to steal user credentials. The domain name tries to appear secure, but it's not an official Facebook domain. Do not enter any information on this site.",
        "risk_score": 95
    },
    "http://yourbank.support-login.com": {
        "is_phishing": True,
        "report": "This is a generic bank phishing site. It may attempt to imitate various banking institutions. The use of 'support-login' in the domain is suspicious and not typical for legitimate bank websites. Avoid entering any banking information here.",
        "risk_score": 90
    },
    "http://apple.id.login.verification-secure.com": {
        "is_phishing": True,
        "report": "This site is impersonating Apple's login page. It uses multiple subdomains to appear legitimate, but it's not an official Apple domain. The site likely aims to steal Apple ID credentials. Do not enter your Apple ID or password on this site.",
        "risk_score": 98
    },
    "http://amaz0n.billing-confirmation.net": {
        "is_phishing": True,
        "report": "This is an Amazon phishing site. Note the use of '0' instead of 'o' in 'amaz0n', a common tactic in phishing URLs. The site may attempt to steal login credentials or financial information under the guise of a billing confirmation. Do not provide any information on this site.",
        "risk_score": 97
    }
}

def get_ip_from_domain(domain):
    """Converts domain name to IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def check_abuse_ip(ip_address):
    """Checks the IP address using the AbuseIPDB API."""
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90'
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

@app.route('/', methods=['GET', 'POST'])
def index():
    """Main route for phishing detection."""
    if request.method == 'POST':
        url = request.form['url']
        
        # Step 1: Check if URL is a known phishing site
        if url in KNOWN_PHISHING_URLS:
            phishing_data = KNOWN_PHISHING_URLS[url]
            return render_template(
                'result.html',
                url=url,
                phishing=phishing_data['is_phishing'],
                phishing_message=phishing_data['report'],
                risk_score=phishing_data['risk_score'],
                ip_address="N/A",  # No IP needed for known phishing URLs
                abuse_data=None  # No abuse data check for known phishing URLs
            )
        
        # Step 2: Validate URL format
        if not validators.url(url):
            return render_template('index.html', error="Invalid URL format.")
        
        # Step 3: Get IP address from domain
        domain = url.split('//')[-1].split('/')[0]  # Extract domain
        ip_address = get_ip_from_domain(domain)
        if not ip_address:
            return render_template('index.html', error="Could not resolve the domain to an IP address.")
        
        # Step 4: Check for abusive activity (using AbuseIPDB)
        abuse_data = check_abuse_ip(ip_address)
        
        # Step 5: Check for phishing traits (generic check for keywords)
        phishing, phishing_message = is_phishing(url)
        
        # Step 6: Display result to the user
        return render_template(
            'result.html',
            url=url,
            phishing=phishing,
            phishing_message=phishing_message,
            ip_address=ip_address,
            abuse_data=abuse_data
        )
    return render_template('index.html')

def is_phishing(url):
    """Simple phishing check based on keywords."""
    phishing_keywords = ['login', 'secure', 'bank', 'password', 'verify', 'account']
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return True, "Potential phishing website based on suspicious keywords."
    return False, "URL does not appear to be a phishing site."

if __name__ == '__main__':
    app.run(debug=True)
