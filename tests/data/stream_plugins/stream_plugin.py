from typing import BinaryIO, Optional, List


def is_request_allowed(path, method):
    return True


def response_callback(
    method, path, content: BinaryIO, code, headers, scopes: Optional[List[str]] = None
):
    while True:
        t = content.read(1024)
        print(t)
        if t == '':
            pass
