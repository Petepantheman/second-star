"""A tiny pay-per-call HTTP API in the L402 style, served from a Lightning node.

A request without proof gets `402 Payment Required` with an invoice and a token. The client pays the invoice, then sends
`Authorization: L402 <token>:<preimage>`. The server checks that the token is its own (an HMAC over the payment hash)
and that sha256(preimage) is that payment hash. This follows the L402 flow; the token is a plain HMAC, not a full
macaroon.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .lightning import LightningNode
from .node import _free_port


class PaidAPI:
    def __init__(self, node: LightningNode, price_sats: int):
        self.node, self.price = node, price_sats
        self.key = secrets.token_bytes(32)
        self.port = _free_port()
        self.served = 0
        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # quiet
                pass

            def do_GET(self):
                auth = self.headers.get("Authorization", "")
                if auth.startswith("L402 ") and ":" in auth:
                    token, preimage = auth[5:].split(":", 1)
                    try:
                        payment_hash = hashlib.sha256(bytes.fromhex(preimage)).digest()
                    except ValueError:
                        payment_hash = b""
                    good = hmac.compare_digest(token, hmac.new(api.key, payment_hash, "sha256").hexdigest())
                    if good:
                        api.served += 1
                        return self._send(200, {"data": f"answer #{api.served}", "paid_hash": payment_hash.hex()})
                    return self._send(401, {"error": "token and preimage do not match"})
                inv = api.node.cli("addinvoice", "--amt", str(api.price), "--memo", "paid api call")
                token = hmac.new(api.key, bytes.fromhex(inv["r_hash"]), "sha256").hexdigest()
                self._send(402, {"invoice": inv["payment_request"], "token": token},
                           {"WWW-Authenticate": f'L402 token="{token}", invoice="{inv["payment_request"]}"'})

            def _send(self, code: int, body: dict, headers: dict | None = None):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/data"

    def close(self) -> None:
        self.server.shutdown()


def call(url: str, wallet: LightningNode, max_cost_sats: int) -> tuple[int, dict]:
    """One paid call as an agent would make it: get the 402, check the price against a software cap, pay, retry."""
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as err:
        if err.code != 402:
            return err.code, json.loads(err.read() or b"{}")
        challenge = json.loads(err.read())
    decoded = wallet.cli("decodepayreq", challenge["invoice"])
    if int(decoded["num_satoshis"]) > max_cost_sats:
        return 0, {"refused_by_client": f"price {decoded['num_satoshis']} > cap {max_cost_sats}"}
    preimage = pay(wallet, challenge["invoice"])
    req = urllib.request.Request(url, headers={"Authorization": f"L402 {challenge['token']}:{preimage}"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status, json.loads(resp.read())


def pay(wallet: LightningNode, payment_request: str, attempts: int = 15, cltv_limit: int | None = None) -> str:
    """Pay an invoice and return the preimage. Retries only while the payment never left (a fresh channel link).
    `cltv_limit` caps how many blocks from now the payment's HTLCs may stay locked, whatever the route."""
    import time
    payment_hash = wallet.cli("decodepayreq", payment_request)["payment_hash"]
    limit = ["--cltv_limit", str(cltv_limit)] if cltv_limit is not None else []
    last = ""
    for _ in range(attempts):
        try:
            wallet.cli("payinvoice", "--force", *limit, payment_request)
        except RuntimeError as err:
            last = str(err)
        for p in reversed(wallet.cli("listpayments", "--include_incomplete").get("payments", [])):
            if p.get("payment_hash") == payment_hash and p.get("status") == "SUCCEEDED":
                return p["payment_preimage"]
        time.sleep(2)
    raise RuntimeError(f"payment {payment_hash[:16]} did not succeed: {last[:300]}")
