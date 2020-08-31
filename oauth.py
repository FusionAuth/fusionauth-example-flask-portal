from requests_oauthlib import OAuth2Session
from flask import Flask, request, redirect, session, url_for, render_template
from flask.json import jsonify
from fusionauth.fusionauth_client import FusionAuthClient

import json
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config.from_object('settings.Config')

@app.route('/', methods=["GET"])
def homepage():
    user=None
    user_data=None
    if session.get('user') != None:
        user = session['user']
        fusionauth_api_client = FusionAuthClient(app.config['API_KEY'], app.config['FA_URL'])
        user_id = user['sub']
        application_id = user['applicationId']
        client_response = fusionauth_api_client.retrieve_registration(user_id, application_id)
        if client_response.was_successful():
            print(client_response.success_response)
            user_data = client_response.success_response['registration'].get('data')
        else:
            print(client_response.error_response)
    return render_template('index.html', user=user, user_data=user_data)

@app.route("/update", methods=["POST"])
def update():
    user=None
    user_data=None
    error=None
    new_user_data = request.form.get('user_data','')
    fusionauth_api_client = FusionAuthClient(app.config['API_KEY'], app.config['FA_URL'])
    if session.get('user') != None:
        user = session['user']
        user_id = user['sub']
        print(new_user_data)
        try: 
            json_object = json.loads(new_user_data) 
        except ValueError as e: 
            print(e)
            client_response = fusionauth_api_client.retrieve_user(user_id)
            if client_response.was_successful():
                user_data = json.dumps(client_response.success_response['user'].get('data'))
            else:
                print(client_response.error_response)
            return render_template('index.html', user=user, user_data=user_data, error='User data must be valid JSON')
  
        patch_request = { 'user' : {'data' : json_object }}
        client_response = fusionauth_api_client.patch_user(user_id, patch_request)
        if client_response.was_successful():
            print(client_response.success_response)
            user_data = json.dumps(client_response.success_response['user'].get('data'))
        else:
            print(client_response.error_response)
            return render_template('index.html', user=user, user_data=user_data, error=client_response.error_response)

    return render_template('index.html', user=user, user_data=new_user_data, error=error)

@app.route("/login", methods=["GET"])
def login():
    fusionauth = OAuth2Session(app.config['CLIENT_ID'], redirect_uri=app.config['REDIRECT_URI'])
    authorization_url, state = fusionauth.authorization_url(app.config['AUTHORIZATION_BASE_URL'])
    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state

    return redirect(authorization_url)

@app.route("/register", methods=["GET"])
def register():
    fusionauth = OAuth2Session(app.config['CLIENT_ID'], redirect_uri=app.config['REDIRECT_URI'])
    authorization_url, state = fusionauth.authorization_url(app.config['AUTHORIZATION_BASE_URL'])

    # registration lives under non standard url, but otherwise takes exactly the same parameters
    registration_url = authorization_url.replace("authorize","register", 1)

    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state

    return redirect(registration_url)

@app.route("/callback", methods=["GET"])
def callback():
    expected_state = session['oauth_state']
    state = request.args.get('state','')
    if state != expected_state:
        print("Error, state doesn't match, redirecting without getting token.")
        return redirect('/')
      
    fusionauth = OAuth2Session(app.config['CLIENT_ID'], redirect_uri=app.config['REDIRECT_URI'])
    token = fusionauth.fetch_token(app.config['TOKEN_URL'], client_secret=app.config['CLIENT_SECRET'], authorization_response=request.url)

    session['oauth_token'] = token
    session['user'] = fusionauth.get(app.config['USERINFO_URL']).json()

    return redirect('/')

if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"
    app.config.from_object('settings.Config')

    app.secret_key = os.urandom(24)
    app.run(debug=True)
