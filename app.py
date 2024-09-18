from flask import Flask, request, render_template
import requests

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        is_valid, message = verify_url(url)
        return render_template('index.html', is_valid=is_valid, message=message, url=url)
    return render_template('index.html')

def verify_url(url):
    try:
        response = requests.get(url, timeout=5)  # Timeout for quick response
        if response.status_code == 200:
            return True, "The link is valid!"
        else:
            return False, f"The link returned a status code {response.status_code}."
    except requests.exceptions.RequestException as e:
        return False, f"An error occurred: {e}"

if __name__ == '__main__':
    app.run(debug=True)
