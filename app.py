from flask import Flask, request, render_template
import validators
import requests

app = Flask(__name__)

# Home route for input page
@app.route('/', methods=['GET'])
def home():
    return render_template('home.html')

# Route to check URL format and display validation result on index.html
@app.route('/check', methods=['POST'])
def check_url():
    url = request.form['url']
    
    # Step 1: Validate URL format using `validators.url()`
    if not validators.url(url):
        # If invalid, show index.html with an error message
        return render_template('index.html', is_valid=False, url=url, message="Invalid URL format.")
    
    # If valid, optionally show index.html with a success message
    return render_template('index.html', is_valid=True, url=url, message="Valid URL format! Now performing phishing check...")
    
    # Optionally, proceed directly to phishing check and result.html
    phishing, message = is_phishing(url)
    return render_template('result.html', url=url, phishing=phishing, message=message)

# Phishing detection function (same as before)
def is_phishing(url):
    phishing_keywords = ['login', 'verify', 'secure', 'bank', 'account', 'password', 'paypal']
    
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return True, "Suspicious keywords found in the URL."
    
    try:
        response = requests.get(url, timeout=3)
        if response.status_code != 200:
            return True, f"Website returned status code: {response.status_code}."
    except requests.RequestException as e:
        return True, f"Error reaching website: {e}"

    return False, "Website seems safe."

if __name__ == '__main__':
    app.run(debug=True)
