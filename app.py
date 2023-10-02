# -*- coding: utf-8 -*-
import logging
import os
import uuid

from flask import Flask
from flask import redirect
from flask import request
from flask import url_for
from flask.ext.login import LoginManager
from flask.ext.login import UserMixin
from flask.ext.login import current_user
from flask.ext.login import login_required
from flask.ext.login import login_user
from flask.ext.login import logout_user
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import entity
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
import requests

# PER APPLICATION configuration settings.
# Each SAML service that you support will have different values here.
metadata_url_for = {
    # For testing with http://saml.oktadev.com
    'test': 'http://idp.oktadev.com/metadata'
    }

app = Flask(__name__)
app.secret_key = str(uuid.uuid4())  # Replace with your secret key
login_manager = LoginManager()
login_manager.setup_app(app)
logging.basicConfig(level=logging.DEBUG)
# Replace this with your own user store
user_store = {}


def saml_client_for(idp_name=None):
    '''
    Given the name of an IdP, return a configuation.
    The configuration is a hash for use by saml2.config.Config
    '''

    if idp_name not in metadata_url_for:
        raise Exception("Settings for IDP '{}' not found".format(idp_name))
    acs_url = url_for(
        "idp_initiated",
        idp_name=idp_name,
        _external=True)

    rv = requests.get(metadata_url_for[idp_name])
    # I have to do this because
    # the "inline" metadata type isn't working in PySAML2
    import tempfile
    tmp = tempfile.NamedTemporaryFile()
    f = open(tmp.name, 'w')
    f.write(rv.text)
    f.close()

    settings = {
        'metadata': {
            # 'remote': {
            #     'url': metadata_url_for[idp_name],
            #     'cert': 'asdfasf'
            #     }
            # 'inline': metadata,
            "local": [tmp.name]
            },
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST)
                    ],
                },
                # Don't verify that the incoming requests originate from us via
                # the built-in cache for authn request ids in pysaml2
                'allow_unsolicited': True,
                # Don't sign authn requests
                'authn_requests_signed': False,
                'logout_requests_signed': True,
                'want_assertions_signed': True,
                'want_response_signed': False,
            },
        },
    }
    spConfig = Saml2Config()
    spConfig.load(settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    tmp.close()
    return saml_client


class User(UserMixin):
    def __init__(self, user_id):
        user = {}
        self.id = None
        self.first_name = None
        self.last_name = None
        try:
            user = user_store[user_id]
            self.id = unicode(user_id)
            self.first_name = user['first_name']
            self.last_name = user['last_name']
        except:
            pass


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


@app.route("/")
def main_page():
    return "Hello"


@app.route("/saml/sso/<idp_name>", methods=['POST'])
def idp_initiated(idp_name):
    saml_client = saml_client_for(idp_name)
    authn_response = saml_client.parse_authn_request_response(
        request.form['SAMLResponse'],
        entity.BINDING_HTTP_POST)
    authn_response.get_identity()
    user_info = authn_response.get_subject()
    username = user_info.text

    # "JIT provisioning"
    if username not in user_store:
        user_store[username] = {
            'first_name': authn_response.ava['FirstName'][0],
            'last_name': authn_response.ava['LastName'][0],
            }
    user = User(username)
    login_user(user)
    # TODO: If it exists, redirect to request.form['RelayState']
    return redirect(url_for('user'))


@app.route("/saml/login/<idp_name>")
def sp_initiated(idp_name):
    saml_client = saml_client_for(idp_name)
    reqid, info = saml_client.prepare_for_authenticate()

    # NOTE:
    # I realize I _technically_ don't need to set Cache-Control or Pragma here:
    #     http://stackoverflow.com/a/5494469
    # However,
    # Section 3.2.3.2 explicitly of this part of the SAML spec requires it:
    #     http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
    # We set those headers here as a "belt and suspenders" approach,
    # since enterprise environments don't always coform to RFCs
    redirect_url = None
    for key, value in info['headers']:
        if key is 'Location':
            redirect_url = value
    response = redirect(redirect_url, code=302)
    response.headers['Cache-Control'] = 'no-cache, no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route("/user")
@login_required
def user():
    msg = u"Hello {user.first_name} {user.last_name}".format(user=current_user)
    return msg


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main_page"))

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    if port == 5000:
        app.debug = True
    app.run(host='0.0.0.0', port=port)
