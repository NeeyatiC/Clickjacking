from flask import Flask, render_template, request
import requests

app = Flask(__name__)

attribute=['Strict','Lax']

def check_clickjacking_protection(url):
    try:
        response = requests.get(url)
        headers = response.headers

        results = {}
        x_frame_options = headers.get('X-Frame-Options', None)
        csp = headers.get('Content-Security-Policy', None)
        set_cookie = headers.get('Set-Cookie', None)

        if x_frame_options:
            results['X-Frame-Options'] = x_frame_options
            if x_frame_options.upper() in ['DENY', 'SAMEORIGIN']:
                results['X-Frame-Options-Status'] = "properly set to prevent clickjacking."
            else:
                results['X-Frame-Options-Status'] = "set but might not be effective for clickjacking protection."
        else:
            results['X-Frame-Options'] = "missing"

        if csp:
            results['Content-Security-Policy'] = csp
            if 'frame-ancestors' in csp:
                results['CSP-Status'] = "header with frame-ancestors directive is set to prevent clickjacking."
            else:
                results['CSP-Status'] = "header is set but does not contain frame-ancestors directive for clickjacking protection."
        else:
            results['Content-Security-Policy'] = "missing"

        if set_cookie:
            results['Set-Cookie'] = set_cookie
            # Check if SameSite attribute is properly set
            same_site_value = next((value for value in attribute if value in set_cookie), None)
            if same_site_value:
                results['SameSite-Status'] = f"Correct SameSite attribute ({same_site_value}) is set in cookies."
            else:
                results['SameSite-Status'] = "SameSite attribute is not properly set in cookies."
        else:
            results['Set-Cookie'] = "missing"

        return results

    except requests.RequestException as e:
        return {"error": f"An error occurred: {e}"}

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        results = check_clickjacking_protection(url)
        return render_template('result.html', url=url, results=results)
    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True)
