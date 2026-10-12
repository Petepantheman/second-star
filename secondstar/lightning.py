"""Throwaway Lightning nodes (LND) next to the throwaway regtest node.

Each node gets its own temporary folder and free ports, follows the regtest node over RPC and ZMQ, and is stopped and
deleted with it. `noseedbackup` makes LND create and unlock a wallet on start; that is for test networks only.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from .node import Node, _free_port


def find_lnd(explicit: str | None) -> tuple[Path, Path]:
    for candidate in (explicit, os.environ.get("SECONDSTAR_LND"), shutil.which("lnd")):
        if candidate and Path(candidate).is_file():
            lnd = Path(candidate)
            lncli = lnd.with_name("lncli.exe" if lnd.suffix == ".exe" else "lncli")
            if lncli.is_file():
                return lnd, lncli
    raise SystemExit("lnd not found. Pass --lnd PATH (lncli must sit next to it) or set SECONDSTAR_LND.")


class LightningNode:
    def __init__(self, name: str, chain: Node, lnd: Path, lncli: Path):
        if not chain.zmq:
            raise ValueError("start the regtest node with zmq=True")
        self.name, self.chain, self.lnd, self.lncli = name, chain, lnd, lncli
        self.dir = chain.datadir / f"lnd-{name}"
        self.rpc, self.rest, self.p2p = _free_port(), _free_port(), _free_port()
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        conf = (
            "[Application Options]\n"
            f"alias=ss-{self.name}\nrpclisten=127.0.0.1:{self.rpc}\nrestlisten=127.0.0.1:{self.rest}\n"
            f"listen=127.0.0.1:{self.p2p}\nnoseedbackup=true\naccept-keysend=true\nmaxpendingchannels=10\n"
            "trickledelay=50\ndebuglevel=info\n"
            "[Bitcoin]\nbitcoin.regtest=true\nbitcoin.node=bitcoind\nbitcoin.defaultchanconfs=1\n"
            "[Bitcoind]\n"
            f"bitcoind.rpchost=127.0.0.1:{self.chain.port}\nbitcoind.rpcuser={self.chain.user}\n"
            f"bitcoind.rpcpass={self.chain.password}\n"
            f"bitcoind.zmqpubrawblock={self.chain.zmq[0]}\nbitcoind.zmqpubrawtx={self.chain.zmq[1]}\n"
            "[protocol]\nprotocol.simple-taproot-chans=true\n"
        )
        (self.dir / "lnd.conf").write_text(conf, encoding="utf-8")
        kwargs = {"stdout": (self.dir / "stdout.log").open("ab"), "stderr": subprocess.STDOUT}
        if os.name == "nt":
            kwargs["creationflags"] = 0x08000000
        else:
            kwargs["start_new_session"] = True
        self.proc = subprocess.Popen([str(self.lnd), f"--lnddir={self.dir}", f"--configfile={self.dir / 'lnd.conf'}"],
                                     **kwargs)
        deadline = time.time() + 120
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise SystemExit(f"lnd-{self.name} exited; see {self.dir / 'stdout.log'}")
            try:
                if self.cli("getinfo").get("identity_pubkey"):
                    return
            except RuntimeError:
                time.sleep(1)
        raise SystemExit(f"lnd-{self.name} did not answer within 120 s; see {self.dir / 'stdout.log'}")

    def cli(self, *args) -> dict:
        cmd = [str(self.lncli), f"--lnddir={self.dir}", "--network=regtest", f"--rpcserver=127.0.0.1:{self.rpc}", *args]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"{' '.join(args[:1])}: lncli timed out after 180 s")
        if out.returncode != 0:
            raise RuntimeError(f"{' '.join(args[:1])}: {(out.stderr + ' ' + out.stdout).strip()[:1500]}")
        text = out.stdout.strip()
        if not text:
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # some commands stream several JSON objects; keep the last one
            last = text[text.rfind("\n{") + 1:] if "\n{" in text else text
            try:
                return json.loads(last)
            except json.JSONDecodeError:
                return {"raw": text}

    # ---- convenience -------------------------------------------------------------------------------------------
    @property
    def pubkey(self) -> str:
        return self.cli("getinfo")["identity_pubkey"]

    def wait_synced(self, timeout: float = 90) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            info = self.cli("getinfo")
            if info.get("synced_to_chain") and info.get("block_height") == self.chain.call("getblockcount"):
                return
            time.sleep(0.5)
        raise RuntimeError(f"lnd-{self.name} did not sync to the chain tip")

    def new_address(self, kind: str = "p2tr") -> str:
        return self.cli("newaddress", kind)["address"]

    def onchain(self) -> int:
        return int(self.cli("walletbalance").get("confirmed_balance", 0))

    def local_balance(self) -> int:
        return int(self.cli("channelbalance").get("local_balance", {}).get("sat", 0))

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                self.cli("stop")
            except RuntimeError:
                pass
            try:
                self.proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=30)
