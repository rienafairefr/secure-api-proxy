# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import calendar
import datetime

import google.auth.crypt
import google.auth.jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from magicproxy.config import parse_permission, Config
from magicproxy.keys import _PADDING
from magicproxy.types import DecodeResult, _Keys

VALIDITY_PERIOD = 365 * 5  # 5 years.


def _datetime_to_secs(value: datetime.datetime) -> int:
    return calendar.timegm(value.utctimetuple())


def _encrypt(key, plain_text: bytes) -> bytes:
    return key.encrypt(plain_text, _PADDING)


def _decrypt(key, cipher_text: bytes) -> bytes:
    return key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def create(keys: _Keys, token, scopes=None, allowed=None) -> str:
    # NOTE: This is the *public key* that we use to encrypt this token. It's
    # *extremely* important that the public key is used here, as we want only
    # our *private key* to be able to decrypt this value.
    encrypted_api_token = _encrypt(keys.public_key, token.encode("utf-8"))
    encoded_api_token = base64.b64encode(encrypted_api_token).decode("utf-8")

    issued_at = datetime.datetime.utcnow()
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=VALIDITY_PERIOD)

    claims = {
        "iat": _datetime_to_secs(issued_at),
        "exp": _datetime_to_secs(expires_at),
        "token": encoded_api_token,
    }

    if allowed:
        claims["allowed"] = allowed

    claims["scopes"] = scopes

    jwt = google.auth.jwt.encode(keys.private_key_signer, claims)

    return jwt.decode("utf-8")


def decode(keys, token) -> DecodeResult:
    claims = dict(google.auth.jwt.decode(token, verify=True, certs=[keys.certificate_pem]))

    decoded_token = base64.b64decode(claims["token"])
    decrypted_token = _decrypt(keys.private_key, decoded_token).decode("utf-8")
    claims["token"] = decrypted_token

    return DecodeResult(claims["token"], claims.get("scopes"), claims.get("allowed"))


def magictoken_params_validate(config: Config, params: dict):
    if not params:
        raise ValueError("Request must be json")

    if "token" not in params:
        raise ValueError("We need a token for the API behind, in the 'token' field")

    if ("scope" in params or "scopes" in params) and "allowed" in params:
        raise ValueError(
            "allowed (spelling out the allowed requests) "
            "OR scope/scopes (naming one or more scopes configured on the proxy), not both"
        )

    if "scopes" in params or "scope" in params:
        params_scopes = [params["scope"]] if "scope" in params else []
        params_scopes.extend(params.pop("scopes", []))
        for params_scope in params_scopes:
            if not isinstance(params_scope, str):
                raise ValueError("scope must be a string")
            if params_scope not in config.scopes:
                raise ValueError(f"scope must be configured on the proxy (valid: {' '.join(config.scopes)})")
        params["scopes"] = params_scopes

    elif "allowed" in params:
        if not isinstance(params.get("allowed"), list):
            raise ValueError("allowed must be a list of ")
        if not all(isinstance(r, str) for r in params["allowed"]):
            raise ValueError("allowed must be a list of strings")
        for value in params["allowed"]:
            parse_permission(value)
    else:
        raise ValueError(
            "need one of allowed (spelling out the allowed requests) "
            "OR scopes (naming a scope configured on the proxy)"
        )
