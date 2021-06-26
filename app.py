from flask import Flask, request
import os
import time
import json
from jwcrypto import jwk, jwt
import requests
import base64
import hashlib
import hmac

app = Flask(__name__)


@app.route('/webhook', methods=['POST'])
def webhook():
    check_result = __check_signature(
        request.headers.get("x-line-signature"), request.data)

    return ''


def __generate_client_assertion():
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": os.environ.get('LINE_CHANNEL_KID')
    }
    channel_id = os.environ.get('LINE_CHANNEL_ID')
    payload = {
        "iss": channel_id,
        "sub": channel_id,
        "aud": "https://api.line.me/",
        "exp": int(time.time()) + 30 * 60,
        "token_exp": 86400
    }
    token = jwt.JWT(header=header, claims=payload)
    token.make_signed_token(
        jwk.JWK(**json.loads(os.environ.get('LINE_ASSERTION_PRIVATE_KEY'))))
    return token.serialize()


def __request_access_token():
    payload = {
        "grant_type": "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": __generate_client_assertion()
    }
    return requests.post("https://api.line.me/oauth2/v2.1/token", data=payload).json()


def __check_signature(x_line_signature, body):
    channel_secret = os.environ.get('LINE_CHANNEL_SECRET')
    hash = hmac.new(channel_secret.encode('utf-8'),
                    body, hashlib.sha256).digest()
    return base64.b64encode(hash).decode() == x_line_signature


if __name__ == '__main__':
    app.run()
