import os
import json
import requests 
from flask import Flask, request, render_template
from dotenv import load_dotenv

#Load API key from .env file
load_dotenv()
API_KEY= os.getenv("GOOGLE_API_KEY")

SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

app = Flask(__name__)

def check_url(url):
    body = {
        "client": {"clientId": "safe-link-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(SAFE_BROWSING_URL, data=json.dumps(body))
    result = response.json()
    if "matches" in result:
        return "Link is unsafe"
    else:
        return "Link is safe"

@app.route("/", methods=["GET", "POST"])
def index():
    verdict = None
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            verdict = check_url(url)
    return render_template("index.html", verdict=verdict)

if __name__ == "__main__":
    app.run(debug=True)