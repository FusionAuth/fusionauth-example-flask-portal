python3 -m venv venv

. venv/bin/activate
pip3 install Flask
pip3 install requests_oauthlib
pip3 install fusionauth-client


update client and secret

OAUTHLIB_INSECURE_TRANSPORT=1 FLASK_APP=oauth.py python3 -m flask run
