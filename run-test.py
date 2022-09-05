import multiprocessing
import os
import time

import psutil
import requests

from tests.test_integration import wait_for_port

API_HOST = "localhost"
API_PORT = 50000
API_ROOT = f"http://{API_HOST}:{API_PORT}"
PROXY_HOST = "localhost"
PROXY_PORT = 50001
PROXY_ROOT = f"http://{PROXY_HOST}:{PROXY_PORT}"
TIMEOUT = 15

print("API_PORT %s" % API_PORT)
print("PROXY_PORT %s" % PROXY_PORT)

wait_for_port(API_HOST, API_PORT)
wait_for_port(PROXY_HOST, PROXY_PORT)

time.sleep(5)

body_size = 500 * 1e6

proxy_token_response = requests.post(
    f"{PROXY_ROOT}/__magictoken",
    json={"allowed": ["* .*"], "token": "fake_token"},
)
assert proxy_token_response.ok
proxy_token = proxy_token_response.text


stream_plugin_response = requests.post(
    f"{PROXY_ROOT}/__magictoken",
    json={"scope": "stream_plugin", "token": "fake_token"},
)
assert stream_plugin_response.ok
stream_plugin_token = stream_plugin_response.text


def error_on_memory_above_100m(stop):
    pids = []
    while True:
        for proc in psutil.process_iter():
            if "magicproxy" in ' '.join(proc.cmdline()):
                pids.append(proc.pid)
        if pids:
            break
        time.sleep(1)

    while True:
        for pid in pids:
            memory = psutil.Process(pid).memory_info().rss / 1024 ** 2
            if memory > 100:
                print(f'memory {memory} above 100M')
            if stop():
                break
            time.sleep(0.01)


stop_thread = False
p = multiprocessing.Process(target=error_on_memory_above_100m, args=(lambda: stop_thread,))
p.start()


def verify_get(root):
    if root == 'API':
        rroot = API_ROOT
        token = "fake_token"
    elif root == 'PROXY':
        rroot = PROXY_ROOT
        token = proxy_token
    else:
        raise RuntimeError()

    data = bytearray(os.urandom(int(body_size)))

    # get big data from api
    response = requests.get(
        f"{rroot}/big_data",
        params={'size': int(200e6)},
        data=data,
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    print(f"{root} GET big_data {response.status_code}")


def verify_post(root):
    if root == 'API':
        rroot = API_ROOT
        token = "fake_token"
    elif root == 'PROXY':
        rroot = PROXY_ROOT
        token = proxy_token
    else:
        raise RuntimeError()

    data = bytearray(os.urandom(int(body_size)))
    # send big data to api
    response = requests.post(
        f"{rroot}/endpoint",
        data=data,
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    print(f"{root} POST endpoint {response.status_code}")


while True:
    try:
        verify_get("PROXY")
        #verify("API")

        time.sleep(2)
    except ConnectionError:
        time.sleep(2)