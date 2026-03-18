#!/usr/bin/env python3
"""OIDC token exchange helper.

Workaround for httplib OpenSSL client issues on Windows.
Called by the Yuzu server to exchange an authorization code for tokens.

Usage: oidc_token_exchange.py <token_endpoint> <json_params>
  json_params: {"code":"...","redirect_uri":"...","client_id":"...","code_verifier":"...","client_secret":"..."}

Prints JSON response to stdout.  Exits 0 on success, 1 on error.
"""
import json
import sys
import urllib.request
import urllib.parse
import urllib.error
import ssl

def main():
    if len(sys.argv) != 3:
        print(json.dumps({"error": "usage: oidc_token_exchange.py <endpoint> <json_params>"}))
        sys.exit(1)

    endpoint = sys.argv[1]
    params = json.loads(sys.argv[2])

    form = {
        "grant_type": "authorization_code",
        "code": params["code"],
        "redirect_uri": params["redirect_uri"],
        "client_id": params["client_id"],
        "code_verifier": params["code_verifier"],
    }
    if params.get("client_secret"):
        form["client_secret"] = params["client_secret"]

    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(endpoint, data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    ctx = ssl.create_default_context()

    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=15)
        body = resp.read().decode()
        print(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(body)
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    main()
