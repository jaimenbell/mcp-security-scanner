"""Fixture: one ssrf sink per HTTP-verb category, same underlying issue.

Every call below is the SAME finding class (`ssrf`): a caller-influenced URL
fetched with no host restriction. They differ only in the HTTP verb the sink
name states, which is exactly what the verb calibration keys on.

(Deliberately avoids the words this detector treats as evidence of URL
validation -- naming one in prose is enough to silence the whole file, since
that check is a raw-text substring test.)
"""

import requests
import urllib.request


def fetch_it(url):
    # read-only verbs -- base severity, unchanged
    a = requests.get(url)
    b = requests.head(url)
    return a, b


def change_it(url, body):
    # state-changing verbs -- escalated
    c = requests.post(url, data=body)
    d = requests.put(url, data=body)
    e = requests.delete(url)
    return c, d, e


def verb_not_stated(url, method):
    # The verb is a RUNTIME argument, not part of the sink name. Unknown,
    # never guessed -- stays at base severity.
    f = requests.request(method, url)
    g = urllib.request.urlopen(url)
    return f, g
