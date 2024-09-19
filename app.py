from flask import Flask, request, render_template
import validators
import requests
import socket

app = Flask(__name__)

# AbuseIPDB API Key
ABUSEIPDB_API_KEY = '1f479be99eee3eec9ea045e73e29dfe4d2c5cdabdb9f80c499dfa6f84af614d09b93c16fe19226d0'

# List of known phishing URLs
KNOWN_PHISHING_URLS = [
    'http://paypal.com.verify-login-account.info',
    'https://secure-facebook-login.com',
    'http://yourbank.support-login.com',
    'http://apple.id.login.verification-secure.com',
    'http://amaz0n.billing-confirmation.net'
]

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

        # Step 1: Validate URL format
        if not validators.url(url):
            return render_template('index.html', error="Invalid URL format.")

        # Step 2: Get IP address from domain
        domain = url.split('//')[-1].split('/')[0]  # Extract domain
        ip_address = get_ip_from_domain(domain)
        if not ip_address:
            return render_template('index.html', error="Could not resolve the domain to an IP address.")

        # Step 3: Check for abusive activity (using AbuseIPDB)
        abuse_data = check_abuse_ip(ip_address)

        # Step 4: Check for phishing traits (using both the keyword check and known phishing URLs)
        phishing, phishing_message = is_phishing(url)

        # Step 5: Display result to the user
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
    """Check if a URL is a known phishing site or contains suspicious keywords."""
    # Check if the URL is in the predefined list of known phishing URLs
    if url in KNOWN_PHISHING_URLS:
        return True, "This URL is a known phishing site."

    # Check for phishing keywords
    phishing_keywords = ['login', 'secure', 'bank', 'password', 'verify', 'account']
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return True, "Potential phishing website based on suspicious keywords."

    return False, "URL does not appear to be a phishing site."

if __name__ == '__main__':
    app.run(debug=True)
