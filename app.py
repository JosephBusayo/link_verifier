from flask import Flask, request, render_template
import validators
import requests
from concurrent.futures import ThreadPoolExecutor, TimeoutError

app = Flask(__name__)
executor = ThreadPoolExecutor(1)  # Limit to 1 worker for the phishing check

# Home route for URL input
@app.route('/', methods=['GET'])
def home():
    return render_template('home.html')

# Route to validate the URL format and redirect to index.html
@app.route('/check', methods=['POST'])
def check_url():
    url = request.form['url']
    
    # Validate URL format
    if not validators.url(url):
        return render_template('index.html', is_valid=False, url=url, message="Invalid URL format.")
    
    # Redirect to index.html to show URL validation result
    return render_template('index.html', is_valid=True, url=url, message="Valid URL format! Now performing phishing check.")

# Route to perform phishing check and display the result
@app.route('/result', methods=['POST'])
def result():
    url = request.form['url']
    
    try:
        # Run phishing check with a timeout of 2 minutes
        future = executor.submit(is_phishing, url)
        phishing, message = future.result(timeout=120)
    except TimeoutError:
        phishing, message = True, "Phishing check timed out."

    return render_template('result.html', url=url, phishing=phishing, message=message)

# Phishing detection function
def is_phishing(url):
    phishing_keywords = ['login', 'verify', 'secure', 'bank', 'account', 'password', 'paypal']
    
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return True, "Suspicious keywords found in the URL."
    
    try:
        response = requests.get(url, timeout=10)  # Increase timeout for requests to handle longer responses
        if response.status_code != 200:
            return True, f"Website returned status code: {response.status_code}."
    except requests.RequestException as e:
        return True, f"Error reaching website: {e}"

    return False, "Website seems safe."

if __name__ == '__main__':
    app.run(debug=True)
