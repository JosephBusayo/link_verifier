from flask import Flask, request, render_template
import validators
import requests
from datetime import datetime
import time

app = Flask(__name__)

def is_phishing(url):
    if not validators.url(url):
        return False, "Invalid URL format."
    
    phishing_keywords = ['login', 'verify', 'secure', 'bank', 'account', 'password', 'paypal']
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return True, "Suspicious keywords found."

    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return True, "Website returned an unusual status."
    except requests.exceptions.RequestException:
        return True, "Unable to reach the website."

    return False, "URL seems fine."

def get_url_details(url):
    # Dummy implementation for URL details
    return {
        'creation_date': 'Unknown',
        'malicious_activity': 'None',
        'owner': 'Unknown',
        'country': 'Unknown',
        'ip_address': 'Unknown'
    }

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        url = request.form['url']
        is_valid, message = verify_url(url)
        if is_valid:
            return render_template('index.html', is_valid=is_valid, message=message, url=url, url_details=get_url_details(url))
        else:
            return render_template('index.html', is_valid=is_valid, message=message)
    return render_template('home.html')

def verify_url(url):
    # Add your URL verification logic here
    return True, "Valid URL format! Now performing phishing check..."

@app.route('/check', methods=['POST'])
def check_url():
    url = request.form['url']
    start_time = time.time()
    phishing, message = is_phishing(url)
    end_time = time.time()

    duration = end_time - start_time
    if duration > 120:  # Check if the process took longer than 2 minutes
        message = "The phishing check took too long. Please try again later."
        phishing = None

    return render_template('result.html', url=url, phishing=phishing, message=message, url_details=get_url_details(url))

if __name__ == '__main__':
    app.run(debug=True)
