"""
Utils
"""
from urllib.request import urlopen
from urllib.error import HTTPError
import contextlib
import urllib.parse
import json
from .errors import APIError
import hmac
import hashlib
import base64


def send_and_decode(req):
    """
    Send the request and return the decoded json of response.

    Args:
        req: urllib2.Request

    Returns:
        A dict of decoded response
    """

    res = None
    try:
        res = urlopen(req)
        if res.getcode() == 204:
            return None
        raw = res.read()
        res.close()
        return json.loads(raw)
    except HTTPError as e:
        print(e)
        if res:
            raw = res.read()
            try:
                data = json.loads(raw)
            except ValueError:
                raise APIError(res.reason)
            else:
                raise APIError(data["error"])


def __hmac_sha1__(data, key):
    """
    hmac-sha1
    """

    hashed = hmac.new(bytes(key, encoding='utf8'), bytes(data, encoding='utf8'), hashlib.sha1)
    # return base64.urlsafe_b64encode(hashed.digest())
    s1 = base64.urlsafe_b64encode(hashed.digest()).decode(encoding='utf-8')
    return s1
