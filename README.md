
## Setup

* python3 -m venv venv
* . venv/bin/activate
* pip3 install Flask
* pip3 install requests_oauthlib
* pip3 install fusionauth-client
* `cp samplesettings.py settings.py`
* update settings.cfg with your app values

## Running 
OAUTHLIB_INSECURE_TRANSPORT=1 FLASK_APP=oauth.py python3 -m flask run

## When you're done
run `deactivate` to leave the venv environment.
