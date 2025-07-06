import json
from os import environ as env
from urllib.parse import quote_plus, urlencode
import logging
from datetime import datetime

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request
from functools import wraps

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

app.logger.setLevel(logging.INFO)

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            app.logger.warning(f"UNAUTHORIZED_ACCESS: ip={request.remote_addr} path={request.path} timestamp={datetime.utcnow().isoformat()}")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token

    user_info = token.get("userinfo", {})
    user_id = user_info.get("sub", "unknown")
    email = user_info.get("email", "unknown")

    app.logger.info(f"LOGIN: user_id={user_id} email={email} timestamp={datetime.utcnow().isoformat()}")

    return redirect("/")

# Logout route
@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

# Protected route
@app.route("/protected")
@requires_auth
def protected():
    user_info = session["user"].get("userinfo", {})
    user_id = user_info.get("sub", "unknown")

    app.logger.info(f"ACCESS_PROTECTED: user_id={user_id} timestamp={datetime.utcnow().isoformat()} path={request.path}")

    return render_template("protected.html", user=session["user"])

# Public home route
@app.route("/")
def home():
    return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4))

# Run the app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 3000))