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
import logging
import os
import pdb
import sys
import threading
import traceback
from io import BytesIO
from queue import Queue
from typing import Tuple, Set, BinaryIO

import flask
import requests
from flask import Response, make_response

import magicproxy
import magicproxy.types
from .config import Config, load_config
from . import magictoken
from . import queries
from . import scopes
from .config import API_ROOT
from .headers import clean_request_headers, clean_response_headers
from .magictoken import magictoken_params_validate

logger = logging.getLogger(__name__)

app = flask.Flask(__name__)

query_params_to_clean: Set[str] = set()

custom_request_headers_to_clean: Set[str] = set()


@app.route("/__magictoken", methods=["POST", "GET"])
def create_magic_token():
    CONFIG: Config = app.config["CONFIG"]
    api_root = CONFIG.api_root
    if flask.request.method == "GET":
        return "magic API proxy for " + api_root + " version " + magicproxy.__version__
    params = flask.request.json
    try:
        magictoken_params_validate(CONFIG, params)
    except ValueError as e:
        return str(e), 400

    token = magictoken.create(
        CONFIG.keys, params["token"], params.get("scopes"), params.get("allowed")
    )

    return token, 200, {"Content-Type": "application/jwt"}


def _proxy_request(
        request: flask.Request, url: str, headers=None, **kwargs
) -> Tuple[Response, dict]:
    clean_headers = clean_request_headers(
        request.headers, custom_request_headers_to_clean
    )

    if headers:
        clean_headers.update(headers)

    queue = Queue()
    chunk_size = 1024
    sentinel = object()

    def read_input_stream():
        while True:
            b = flask.request.stream.read(chunk_size)
            if b == b'':
                break
            queue.put(b)
        queue.put(sentinel)

    #t = threading.Thread(target=read_input_stream)
    #t.start()

    # Make the API request
    resp = requests.request(
        url=url,
        method=request.method,
        headers=clean_headers,
        params=dict(request.args),
        data=request.stream,
        stream=True,
        **kwargs,
    )

    response_headers = clean_response_headers(resp.headers)

    return resp, response_headers


class tee:
    def __init__(self, _fd1, _fd2):
        self.fd1 = _fd1
        self.fd2 = _fd2

    def __del__(self):
        if self.fd1 != sys.stdout and self.fd1 != sys.stderr:
            self.fd1.close()
        if self.fd2 != sys.stdout and self.fd2 != sys.stderr:
            self.fd2.close()

    def write(self, text):
        self.fd1.write(text)
        self.fd2.write(text)

    def flush(self):
        self.fd1.flush()
        self.fd2.flush()


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["POST", "GET", "PATCH", "PUT", "DELETE"])
def proxy_api(path):
    CONFIG = app.config["CONFIG"]
    auth_token = flask.request.headers.get("Authorization")
    if auth_token is None:
        return "No authorization token presented", 401
    # strip out "Bearer " if needed
    if auth_token.startswith("Bearer "):
        auth_token = auth_token[len("Bearer "):]

    try:
        # Validate the magic token
        token_info = magictoken.decode(CONFIG.keys, auth_token)
    except ValueError:
        return "Not a valid magic token", 400

    # Validate scopes against URL and method.
    if not scopes.validate_request(
        CONFIG, flask.request.method, path, token_info.scopes, token_info.allowed
            flask.request.method, path, token_info.scopes, token_info.allowed
    ):
        return (
            "Disallowed by API proxy",
            401,
        )

    path = queries.clean_path_queries(query_params_to_clean, path)

    response, headers = _proxy_request(
        request=flask.request,
        url=f"{CONFIG.api_root}/{path}",
        headers={"Authorization": f"Bearer {token_info.token}"},
    )

    if int(response.headers['content-Length']) > 1_000_000:
        response_callback_queue = Queue()
        response_queue = Queue()
        response_exhausted = threading.Event()

        poison = object()

        class ResponseCallbackData:
            def __init__(self, queue: Queue):
                self.queue = queue

            def read(self):
                if not response_exhausted.is_set():
                    return self.queue.get(block=True)
                else:
                    return b''

        def pass_the_bucket():
            for l in response:
                response_callback_queue.put(l)
                response_queue.put(l)
            response_callback_queue.put(poison)
            response_queue.put(poison)

        t1 = threading.Thread(target=pass_the_bucket)
        t1.start()

        # response_callback reads data, that writes to

        def maybe_response_callback(method, path, data, scopes):
            try:
                scopes.response_callback(
                    method, path, data, scopes
                )
            except Exception as e:
                logger.error("exception in response_callback")
                logger.error(e)
                logger.error(traceback.format_exc())

        t2 = threading.Thread(target=maybe_response_callback, args=(
        flask.request.method, path, ResponseCallbackData(response_callback_queue), headers, token_info.scopes))
        t2.start()

        def generate_response():
            while True:
                if not response_exhausted.is_set():
                    yield response_queue.get(block=True)
                else:
                    t1.join()
                    t2.join()

        return Response(generate_response())
    else:
        try:
            scopes.response_callback(flask.request.method, path, BytesIO(response.content), response.status_code,
                                     token_info.scopes)
        except Exception as e:
            logger.error("exception in response_callback")
            logger.error(e)
            logger.error(traceback.format_exc())
        resp = make_response(response.content, response.status_code)
        for key, value in response.headers.items():
            resp.headers.set(key, value)
        return resp


def create_app():
    global keys
    keys = magictoken.Keys.from_env()
    return app


def run_app(host, port):
    create_app().run(host=host, port=port, use_reloader=True)
