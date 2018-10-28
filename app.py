import email
import base64
import os
import flask
import requests
from bs4 import BeautifulSoup

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

from flask import render_template, redirect

CLIENT_SECRETS_FILE = "client_secret.json"

SCOPES = ["https://mail.google.com/", "https://www.googleapis.com/auth/gmail.compose",
          "https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/gmail.readonly"]
API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'

app = flask.Flask(__name__)
app.secret_key = 'N7N95fr282We3qVMAlYiJwNz'


@app.route('/oops')
def index():
    return print_index_table()


@app.route('/')
def test_api_request():
    if 'credentials' not in flask.session:
        return flask.redirect('authorize')

    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    mail = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)

    messages = mail.users().messages().list(userId='me', maxResults=15).execute()
    data = []
    for msg in messages['messages']:
        m = mail.users().messages().get(userId='me', id=msg['id'], format='raw').execute()
        msg_str = base64.urlsafe_b64decode(m['raw']).decode("utf-8")
        mime_msg = email.message_from_string(msg_str)
        body = ""
        if mime_msg.is_multipart():
            for part in mime_msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get('text/html'))
                if ctype == 'text/html' and 'attachment' not in cdispo:
                    body = part.get_payload(decode=True).decode("utf-8")  # decode
                    data.append(body)

    flask.session['credentials'] = credentials_to_dict(credentials)
    bodies = []
    for d in data:
        soup = BeautifulSoup(d, features="html.parser")
        bodies.append(str(soup.find('body').findChildren()[0]))
    # bodies = data
    # print('----------------')
    # print(body)
    # print('----------------')
    data = {
        'bodies': bodies,
        'label': 'Работа',
    }
    return render_template('postman.html', data=data)


@app.route('/authorize')
def authorize():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')

    flask.session['state'] = state

    return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_response = flask.request.url
    print(authorization_response)
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.redirect(flask.url_for('test_api_request'))


@app.route('/revoke')
def revoke():
    if 'credentials' not in flask.session:
        return ('You need to <a href="/authorize">authorize</a> before ' +
                'testing the code to revoke credentials.')

    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    revoke = requests.post('https://accounts.google.com/o/oauth2/revoke',
                           params={'token': credentials.token},
                           headers={'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return ('Credentials successfully revoked.' + print_index_table())
    else:
        return ('An error occurred.' + print_index_table())


@app.route('/clear')
def clear_credentials():
    if 'credentials' in flask.session:
        del flask.session['credentials']
    return ('Credentials have been cleared.<br><br>' +
            print_index_table())


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}


def print_index_table():
    return ('<table>' +
            '<tr><td><a href="/">Test an API request</a></td>' +
            '</tr></table>')


if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    app.run('0.0.0.0', 5000, debug=True)
