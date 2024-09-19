from flask import Flask, request, render_template
import validators
import requests

app = Flask(__name__)

# Mock API function (replace with actual API calls)
def get_url_details(url):
    # This is a placeholder function.
    # You should replace this with actual API calls to services like VirusTotal or similar.
    return {
        "creation_date": "2023-01-01",
        "malicious_activity": "No recent reports",
        "owner": "Example Corp",
        "country": "US",
        "ip_address": "192.168.1.1"
    }

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        url = request.form['url']
        is_valid, message = verify_url(url)
        if is_valid:
            url_details = get_url_details(url)
            return render_template('index.html', is_valid=is_valid, message=message, url=url, url_details=url_details)
        else:
            return render_template('home.html', is_valid=is_valid, message=message)
    return render_template('home.html')

def verify_url(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return True, "Valid URL format! Now performing phishing check..."
        else:
            return False, f"The link returned a status code {response.status_code}."
    except requests.exceptions.RequestException as e:
        return False, f"An error occurred: {e}"

@app.route('/check', methods=['POST'])
def check_url():
    url = request.form['url']
    phishing, message = is_phishing(url)
    url_details = get_url_details(url)
    return render_template('result.html', url=url, phishing=phishing, message=message, url_details=url_details)

def is_phishing(url):
    if not validators.url(url):
        return False, "Invalid URL format."
    
    phishing_keywords = ['login', 'verify', 'secure', 'bank', 'account', 'password', 'paypal']
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return True, "Suspicious keywords found."

    try:
        response = requests.get(url)
        if response.status_code != 200:
            return True, "Website returned an unusual status."
    except:
        return True, "Unable to reach the website."

    return False, "URL seems fine."

if __name__ == '__main__':
    app.run(debug=True)
