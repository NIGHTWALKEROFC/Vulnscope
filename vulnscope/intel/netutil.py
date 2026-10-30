import time

import requests

UA = {"User-Agent": "VulnScope-intel/0.1"}


def get_json(url, params=None, headers=None, timeout=60, retries=4, backoff=8, etag=None):
    attempt = 0
    sent = dict(UA)
    if headers:
        sent.update(headers)
    if etag:
        sent["If-None-Match"] = etag
    while True:
        try:
            resp = requests.get(url, params=params, headers=sent, timeout=timeout)
        except requests.exceptions.RequestException:
            attempt += 1
            if attempt > retries:
                raise
            time.sleep(backoff * attempt / 2)
            continue
        if resp.status_code == 304:
            return None, resp.headers
        if resp.status_code in (403, 429, 502, 503, 504):
            attempt += 1
            if attempt > retries:
                resp.raise_for_status()
            time.sleep(backoff * attempt)
            continue
        resp.raise_for_status()
        return resp.json(), resp.headers


def post_json(url, payload, timeout=60, retries=3):
    attempt = 0
    while True:
        try:
            resp = requests.post(url, json=payload, headers=UA, timeout=timeout)
        except requests.exceptions.RequestException:
            attempt += 1
            if attempt > retries:
                raise
            time.sleep(2 * attempt)
            continue
        if resp.status_code in (429, 502, 503, 504):
            attempt += 1
            if attempt > retries:
                resp.raise_for_status()
            time.sleep(3 * attempt)
            continue
        resp.raise_for_status()
        return resp.json()
