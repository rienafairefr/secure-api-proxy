import io
import os
import pdb
import sys

import flask
from flask import request, send_file

app = flask.Flask("api")


@app.route("/", methods=["GET", "POST"])
def route():
    incoming_data = flask.request.get_data(cache=False)
    authorization_header = flask.request.headers.get("authorization")

    if authorization_header:
        if authorization_header.startswith("Bearer "):
            if authorization_header[len("Bearer "):] == "fake_token":
                return "authorized by API", 200

    return "not authorized by API", 401


@app.route("/endpoint", methods=["GET", "POST"])
def route_non_protected():
    incoming_data = flask.request.get_data(cache=False)
    return "hello there", 200


@app.route("/big_data", methods=["GET", "POST"])
def big_data_route():
    incoming_data = flask.request.get_data(cache=False)
    body = bytearray(os.urandom(int(request.args.get('size', 100))))
    return send_file(io.BytesIO(body), mimetype='image/jpg')


if __name__ == "__main__":
    app.run(host=sys.argv[1], port=int(sys.argv[2]), use_reloader=False, threaded=True)
