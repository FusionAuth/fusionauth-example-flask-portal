
# Flask user portal

This user portal allows you to read and update a user's registration.data field, which is an arbitrary key value store in FusionAuth.

## Prerequisites

You need to make sure FusionAuth is running and that you have python3/pip3 available. 

## Setup

* `python3 -m venv venv`
* `. venv/bin/activate`
* `pip3 install Flask`
* `pip3 install requests_oauthlib`
* `pip3 install fusionauth-client`
* create an application in FusionAuth:
  * Set the redirect url to `http://localhost:5000/callback`
  * Set the logout url to `http://localhost:5000`
  * Follow form creation as documented here: https://fusionauth.io/blog/2020/08/27/advanced-registration-form and note the form id
  * Create an API key
* `cp samplesettings.py settings.py`
* Update `settings.py` with your values

## Running 
To run this:

`OAUTHLIB_INSECURE_TRANSPORT=1 FLASK_APP=oauth.py python3 -m flask run`

Visit the application at http://localhost:5000

## To leave venv

run `deactivate` to leave the venv environment.
