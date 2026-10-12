"""A throwaway regtest node: start it in a fresh folder, talk JSON-RPC to it, stop it, delete the folder."""
from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


class RpcError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(f"{code}: {message}")


def find_bitcoind(explicit: str | None) -> Path:
    for candidate in (explicit, os.environ.get("SECONDSTAR_BITCOIND"), shutil.which("bitcoind")):
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    raise SystemExit("bitcoind not found. Pass --bitcoind PATH or set SECONDSTAR_BITCOIND. It must be a Bitcoin "
                     "Inquisition build (29.x) with CTV and TEMPLATEHASH active on regtest.")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Node:
    def __init__(self, bitcoind: Path, keep: bool = False, zmq: bool = False):
        self.bitcoind, self.keep = bitcoind, keep
        self.datadir = Path(tempfile.mkdtemp(prefix="secondstar-"))
        self.port = _free_port()
        self.zmq = (f"tcp://127.0.0.1:{_free_port()}", f"tcp://127.0.0.1:{_free_port()}") if zmq else None
        self.user, self.password = "ss", secrets.token_hex(16)
        self.proc: subprocess.Popen | None = None

    def call(self, method: str, *params, wallet: str | None = None):
        url = f"http://127.0.0.1:{self.port}" + (f"/wallet/{wallet}" if wallet else "")
        body = json.dumps({"jsonrpc": "1.0", "id": "ss", "method": method, "params": list(params)}).encode()
        auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        req = urllib.request.Request(url, body, {"Content-Type": "application/json", "Authorization": "Basic " + auth})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                out = json.loads(resp.read().decode())
        except urllib.error.HTTPError as err:
            out = json.loads(err.read().decode() or "{}")
        if out.get("error"):
            raise RpcError(out["error"].get("code"), out["error"].get("message", ""))
        return out.get("result")

    def start(self) -> None:
        cmd = [str(self.bitcoind), f"-datadir={self.datadir}", "-regtest", "-server=1", "-listen=0",
               "-txindex=1", f"-rpcport={self.port}", f"-rpcuser={self.user}", f"-rpcpassword={self.password}",
               "-fallbackfee=0.0001", "-printtoconsole=0"]
        if self.zmq:   # Lightning nodes follow the chain through these
            cmd += [f"-zmqpubrawblock={self.zmq[0]}", f"-zmqpubrawtx={self.zmq[1]}"]
        kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        if os.name == "nt":
            kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
        else:
            kwargs["start_new_session"] = True
        self.proc = subprocess.Popen(cmd, **kwargs)
        deadline = time.time() + 90
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise SystemExit(f"bitcoind exited with code {self.proc.returncode}; see {self.datadir}/regtest/debug.log")
            try:
                self.call("getblockcount")
                return
            except (OSError, RpcError, ValueError):
                time.sleep(0.5)
        raise SystemExit("bitcoind did not answer within 90 s")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                self.call("stop")
            except Exception:
                pass
            try:
                self.proc.wait(timeout=90)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=30)
        if not self.keep:
            shutil.rmtree(self.datadir, ignore_errors=True)

    def __enter__(self) -> "Node":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
