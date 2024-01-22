from requests_oauthlib import OAuth2Session
from flask import Flask, request, redirect, session, url_for, render_template
from fusionauth.fusionauth_client import FusionAuthClient
import pkce
import requests
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config.from_object('settings.Config')

@app.route('/', methods=["GET"])
def homepage():
    user=None
    registration_data=None
    fields = {}
    if session.get('user') != None:
        user = session['user']
        fusionauth_api_client = FusionAuthClient(app.config['API_KEY'], app.config['FA_URL'])
        user_id = user['sub']
        application_id = user['applicationId']
        client_response = fusionauth_api_client.retrieve_registration(user_id, application_id)
        if client_response.was_successful():
            registration_data = client_response.success_response['registration'].get('data')
            fields = get_fields(fusionauth_api_client)
        else:
            print(client_response.error_response)
    return render_template('index-interview.html', user=user, registration_data=registration_data, fields=fields)

@app.route("/update", methods=["POST"])
def update():
    user=None
    error=None
    fields=[]
    fusionauth_api_client = FusionAuthClient(app.config['API_KEY'], app.config['FA_URL'])
    if session.get('user') != None:
        user = session['user']
        user_id = user['sub']
        application_id = user['applicationId']

        client_response = fusionauth_api_client.retrieve_registration(user_id, application_id)
        if client_response.was_successful():
            #print(client_response.success_response)
            registration_data = client_response.success_response['registration'].get('data')
            fields = get_fields(fusionauth_api_client)
            for key in fields.keys():
                field = fields[key]
                form_key = field['key'].replace('registration.data.','')
                new_value = request.form.get(form_key,'')
                if field['control'] == 'number':
                    # TODO must handle all types here otherwise the data gets out of sync
                    registration_data[form_key] = int(new_value)
                else:
                    registration_data[form_key] = new_value
            patch_request = { 'registration' : {'applicationId': application_id, 'data' : registration_data }}
            client_response = fusionauth_api_client.patch_registration(user_id, patch_request)
            if client_response.was_successful():
               pass
            else:
               error = "Unable to save data"
               return render_template('index-interview.html', user=user, registration_data=registration_data, fields=fields, error=error)
    return redirect('/')

@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(app.config['FA_URL']+'/oauth2/logout?client_id='+app.config['CLIENT_ID'])


@app.route("/login", methods=["GET"])
def login():
    code_verifier, code_challenge = pkce.generate_pkce_pair()
    fusionauth = OAuth2Session(app.config['CLIENT_ID'], redirect_uri=app.config['REDIRECT_URI'])
    authorization_url, state = fusionauth.authorization_url(app.config['AUTHORIZATION_BASE_URL'])
    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state

    # save the verifier in session to send it later to the token endpoint
    session['code_verifier'] = code_verifier
    return redirect(authorization_url+'&code_challenge='+code_challenge+'&code_challenge_method=S256')

@app.route("/register", methods=["GET"])
def register():
    code_verifier, code_challenge = pkce.generate_pkce_pair()
    fusionauth = OAuth2Session(app.config['CLIENT_ID'], redirect_uri=app.config['REDIRECT_URI'])
    authorization_url, state = fusionauth.authorization_url(app.config['AUTHORIZATION_BASE_URL'])

    # registration lives under non standard url, but otherwise takes exactly the same parameters
    registration_url = authorization_url.replace("authorize", "register", 1)

    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    # save the verifier in session to send it later to the token endpoint
    session['code_verifier'] = code_verifier
    return redirect(registration_url+'&code_challenge='+code_challenge+'&code_challenge_method=S256')

@app.route("/callback", methods=["GET"])
def callback():
    expected_state = session.get('oauth_state', '')
    state = request.args.get('state','')
    auth_code = request.args.get('code','')
    if state != expected_state:
        print("Error, state doesn't match, redirecting without getting token.")
        return redirect('/')

    # call token endpoint url
    resp = requests.post(
        url=app.config['TOKEN_URL'],
        data={
            'grant_type': 'authorization_code',
            'client_id': app.config['CLIENT_ID'],
            'client_secret': app.config['CLIENT_SECRET'],
            'redirect_uri': app.config['REDIRECT_URI'],
            'code': auth_code,
            'code_verifier': session['code_verifier']
        }
    )
    result = resp.json()
    token_dict = {
        'access_token': result['access_token'],
        'token_type': 'bearer'
    }

    fusionauth = OAuth2Session(client_id=app.config['CLIENT_ID'], token=token_dict)
    session['oauth_token'] = result['access_token']
    session['user'] = fusionauth.get(app.config['USERINFO_URL']).json()
    return redirect('/')

def get_fields(fusionauth_api_client):
        fields = {}
        client_response = fusionauth_api_client.retrieve_form(app.config['FORM_ID'])
        if client_response.was_successful():
            field_ids = client_response.success_response['form']['steps'][1]['fields']
            for id in field_ids:
                client_response = fusionauth_api_client.retrieve_form_field(id)
                if client_response.was_successful(): 
                    field = client_response.success_response['field']
                    fields[field['key']] = field
        else:
            print(client_response.error_response)
        return fields

if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    app.config.from_object('settings.Config')

    app.secret_key = os.urandom(24)
    app.run(debug=True)
