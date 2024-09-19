from flask import Flask, request, render_template
import validators
import requests
import socket

app = Flask(__name__)

# AbuseIPDB API Key
ABUSEIPDB_API_KEY = '1f479be99eee3eec9ea045e73e29dfe4d2c5cdabdb9f80c499dfa6f84af614d09b93c16fe19226d0'

# Known phishing URLs with detailed information
KNOWN_PHISHING_URLS = {
    "http://paypal.com.verify-login-account.info": {
        "phishing_message": "This is a known phishing site targeting PayPal users.",
        "detailed_info": {
            "Detected": "2023-06-15",
            "Reason": "Phishing page mimicking PayPal login.",
            "Threat Level": "High"
        }
    },
    "https://secure-facebook-login.com": {
        "phishing_message": "This is a known phishing site targeting Facebook users.",
        "detailed_info": {
            "Detected": "2023-07-20",
            "Reason": "Fake Facebook login page to steal credentials.",
            "Threat Level": "Critical"
        }
    },
    "http://yourbank.support-login.com": {
        "phishing_message": "This is a known phishing site targeting online banking users.",
        "detailed_info": {
            "Detected": "2023-05-10",
            "Reason": "Phishing page imitating a bank's login page.",
            "Threat Level": "High"
        }
    },
    "http://apple.id.login.verification-secure.com": {
        "phishing_message": "This is a known phishing site targeting Apple ID users.",
        "detailed_info": {
            "Detected": "2023-08-01",
            "Reason": "Fake Apple ID verification page to steal credentials.",
            "Threat Level": "Critical"
        }
    },
    "http://amaz0n.billing-confirmation.net": {
        "phishing_message": "This is a known phishing site targeting Amazon users.",
        "detailed_info": {
            "Detected": "2023-09-05",
            "Reason": "Imitating Amazon billing confirmation to steal payment info.",
            "Threat Level": "High"
        }
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

        # Step 1: Validate URL format
        if not validators.url(url):
            return render_template('index.html', error="Invalid URL format.")

        # Step 2: Check if the URL is in the known phishing list
        if url in KNOWN_PHISHING_URLS:
            phishing_info = KNOWN_PHISHING_URLS[url]
            return render_template(
                'result.html',
                url=url,
                phishing=True,
                phishing_message=phishing_info['phishing_message'],
                detailed_info=phishing_info['detailed_info'],
                ip_address=None,
                abuse_data=None
            )

        # Step 3: Get IP address from domain
        domain = url.split('//')[-1].split('/')[0]  # Extract domain
        ip_address = get_ip_from_domain(domain)
        if not ip_address:
            return render_template('index.html', error="Could not resolve the domain to an IP address.")

        # Step 4: Check for abusive activity (using AbuseIPDB)
        abuse_data = check_abuse_ip(ip_address)

        # Step 5: Display result to the user
        phishing, phishing_message = is_phishing(url)

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
