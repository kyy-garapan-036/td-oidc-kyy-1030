#!/usr/bin/env python3
"""OIDC oracle runner: executes matrix.json steps against updates.todesktop.com.

Step types:
  claims                         -> decode + print the OIDC token claims
  token   {app|path}             -> POST /v2/ci/{app}/token with the OIDC token
  http    {method,path,auth,body,headers}
         auth: none | oidc | token:<saved-name>
Saved: any step with "save": "name" stores the JSON body (and token if present)
for later steps. All output is JSON lines so the job log is machine-readable.
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("TD_BASE", "https://updates.todesktop.com")
AUD = os.environ.get("TD_AUD", "todesktop")


def oidc():
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=" + AUD
    req = urllib.request.Request(url, headers={"Authorization": "bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["value"]


def decode(tok):
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception as exc:  # noqa: BLE001
        return {"decode_error": str(exc)}


def call(method, path, headers=None, body=None, timeout=30):
    url = path if path.startswith("http") else BASE + path
    h = {"User-Agent": "td-ci-oracle/1.0"}
    if headers:
        h.update(headers)
    data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
    req = urllib.request.Request(url, headers=h, method=method, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        return 0, {}, repr(exc)


def main():
    with open(os.environ.get("MATRIX", "matrix.json"), encoding="utf-8") as f:
        matrix = json.load(f)
    tok = oidc()
    print(json.dumps({"step": "oidc", "len": len(tok), "claims": decode(tok)}))
    saved = {}
    for step in matrix["steps"]:
        name = step.get("name")
        kind = step.get("type")
        if kind == "claims":
            print(json.dumps({"step": name, "claims": decode(tok)}))
            continue
        if kind == "token":
            app = step.get("app", "")
            path = step.get("path") or f"/v2/ci/{app}/token"
            status, hdr, body = call("POST", path, {"Authorization": "Bearer " + tok})
            rec = {"step": name, "path": path, "status": status, "body": body[:1500]}
            loc = hdr.get("location") or hdr.get("Location")
            if loc:
                rec["location"] = loc
            try:
                parsed = json.loads(body)
            except Exception:  # noqa: BLE001
                parsed = None
            if isinstance(parsed, dict):
                if parsed.get("token"):
                    rec["token_claims"] = decode(parsed["token"])
                    saved[name] = parsed
                elif isinstance(parsed.get("data"), dict) and parsed["data"].get("token"):
                    rec["token_claims"] = decode(parsed["data"]["token"])
                    saved[name] = parsed["data"]
            print(json.dumps(rec))
            continue
        if kind == "http":
            auth = step.get("auth", "none")
            headers = dict(step.get("headers") or {})
            if auth == "oidc":
                headers["Authorization"] = "Bearer " + tok
            elif auth.startswith("token:"):
                name2 = auth.split(":", 1)[1]
                if name2 not in saved:
                    print(json.dumps({"step": name, "error": "no saved token " + name2}))
                    continue
                headers["Authorization"] = "Bearer " + saved[name2]["token"]
            body = step.get("body")
            if isinstance(body, str):
                body = body.encode()
            status, hdr, resp = call(step.get("method", "GET"), step["path"], headers, body)
            rec = {"step": name, "path": step["path"], "status": status, "body": resp[:3000]}
            loc = hdr.get("location") or hdr.get("Location")
            if loc:
                rec["location"] = loc
            try:
                parsed = json.loads(resp)
            except Exception:  # noqa: BLE001
                parsed = None
            if step.get("save") and parsed is not None:
                saved[step["save"]] = parsed if isinstance(parsed, dict) else {"raw": parsed}
            if step.get("show_headers"):
                rec["headers"] = {k: v for k, v in hdr.items() if k.lower() in ("location", "content-type", "cache-control", "cf-ray", "set-cookie", "access-control-allow-origin", "vary")}
            print(json.dumps(rec))
            continue
        print(json.dumps({"step": name, "error": "unknown type " + str(kind)}))


if __name__ == "__main__":
    main()
