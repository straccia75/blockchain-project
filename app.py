# app.py
import os
import time
import logging
from typing import Dict, List, Tuple
from binascii import hexlify

import requests
from flask import Flask, jsonify, render_template, request
from mnemonic import Mnemonic
from eth_utils import to_checksum_address
from eth_account import Account
from dotenv import load_dotenv
from eth_account.messages import encode_defunct
from apscheduler.schedulers.background import BackgroundScheduler

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("wallet_scanner")

load_dotenv()

ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "")
RENDER_EXTERNAL_URL = os.environ.get("RENDER_EXTERNAL_URL")
if not ETHERSCAN_API_KEY:
    log.error("ETHERSCAN_API_KEY not set. Define it in your environment variables.")

# NOTE: In production, set this to False. In the demo it's True to show the seed phrase with timed reveal.
INCLUDE_MNEMONIC = True

REQUEST_TIMEOUT = 60
RATE_SLEEP_SECONDS = 1.0

# Token map: symbol -> (contract, decimals)
TOKENS: Dict[str, Tuple[str, int]] = {
    "USDT": ("0xdAC17F958D2ee523a2206206994597C13D831ec7", 6),
    "USDC": ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6),
    "LINK": ("0x514910771AF9Ca656af840dff83E8264EcF986CA", 18),
    "UNI" : ("0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", 18),
    "SHIB": ("0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE", 18),
}

mnemo = Mnemonic("english")
Account.enable_unaudited_hdwallet_features()

# --- Etherscan V2 helper ---
def _etherscan_get(params: Dict, chain_id: int = 1) -> Dict:
    base = "https://api.etherscan.io/v2/api"
    params_with_chain = {**params, "chainid": chain_id, "apikey": ETHERSCAN_API_KEY}
    r = requests.get(base, params=params_with_chain, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if data.get("status") == "0" and data.get("message") not in ("No transactions found",):
        raise RuntimeError(f"Etherscan error: {data.get('message')} / {data.get('result')}")
    return data

def _safe_int(x: str) -> int:
    try:
        return int(x)
    except:
        return 0

# --- Core generator + validation ---
def generate_and_check_wallet_data(include_mnemonic: bool = False) -> Dict:
    if not ETHERSCAN_API_KEY:
        return {"error": "ETHERSCAN_API_KEY not configured."}

    mnemonic_phrase = mnemo.generate(strength=128)
    try:
        bip39_checksum_ok = mnemo.check(mnemonic_phrase)
    except Exception:
        bip39_checksum_ok = False

    derivation_path = "m/44'/60'/0'/0/0"
    acct = Account.from_mnemonic(mnemonic_phrase, account_path=derivation_path)
    address = to_checksum_address(acct.address)
    eip55_checksum_ok = address == to_checksum_address(address)

    # Signature roundtrip
    try:
        msg_text = f"wallet-proof:{address}"
        msg = encode_defunct(text=msg_text)
        signed = acct.sign_message(msg)
        recovered = Account.recover_message(msg, signature=signed.signature)
        signature_roundtrip_ok = (to_checksum_address(recovered) == address)
    except Exception:
        signature_roundtrip_ok = False

    # Balances
    etherscan_ok = True
    balance_eth = 0.0
    try:
        eth_data = _etherscan_get({
            "module": "account",
            "action": "balance",
            "address": address,
            "tag": "latest"
        })
        balance_eth = _safe_int(eth_data.get("result", "0")) / 1e18
    except Exception as e:
        logging.warning(f"ETH balance failed for {address}: {e}")
        etherscan_ok = False

    token_balances: List[Dict] = []
    for symbol, (token_addr, decimals) in TOKENS.items():
        try:
            tok = _etherscan_get({
                "module": "account",
                "action": "tokenbalance",
                "address": address,
                "contractaddress": token_addr,
                "tag": "latest"
            })
            raw = _safe_int(tok.get("result", "0"))
            bal = raw / (10**decimals)
        except Exception as e:
            logging.warning(f"Token {symbol} failed for {address}: {e}")
            bal = 0.0
        token_balances.append({"token_address": token_addr, "balance": bal})
        time.sleep(RATE_SLEEP_SECONDS)

    resp = {
        "wallet_address": address,
        "balance_eth": balance_eth,
        "token_balances": token_balances,
        "token_meta": { addr: {"symbol": sym, "decimals": dec} for sym, (addr, dec) in TOKENS.items() },
        "validation": {
            "bip39_checksum": bool(bip39_checksum_ok),
            "derivation_path": derivation_path,
            "eip55_checksum": bool(eip55_checksum_ok),
            "signature_roundtrip": bool(signature_roundtrip_ok),
            "etherscan_ok": bool(etherscan_ok),
        }
    }

    if include_mnemonic:
        resp["mnemonic_phrase"] = mnemonic_phrase

    return resp

def scan_one_wallet(include_mnemonic: bool = False) -> Dict:
    return generate_and_check_wallet_data(include_mnemonic=include_mnemonic)

def scan_batch(count: int) -> List[Dict]:
    count = max(1, min(count, 50))
    results: List[Dict] = []
    for i in range(count):
        results.append(scan_one_wallet(include_mnemonic=False))
        if i < count - 1:
            time.sleep(2.0)
    return results

# --- Educational Mode derivation steps ---
def derive_educational_steps(passphrase: str = "", derivation_path: str = "m/44'/60'/0'/0/0") -> Dict:
    """
    Generate a 12-word mnemonic and show step-by-step derivation to an Ethereum address.
    WARNING: For educational/demo use only. Never fund or reuse these secrets.
    """
    if not ETHERSCAN_API_KEY:
        # Not required for this endpoint, but keep logging consistent
        log.warning("ETHERSCAN_API_KEY missing; proceeding (not required for /educational_mnemonic)")

    # (1) Mnemonic & checksum
    mnemonic_phrase = mnemo.generate(strength=128)
    try:
        bip39_checksum_ok = mnemo.check(mnemonic_phrase)
    except Exception:
        bip39_checksum_ok = False

    # (2) Seed derivation (PBKDF2-HMAC-SHA512, 2048 iterations)
    seed_bytes = mnemo.to_seed(mnemonic_phrase, passphrase=passphrase or "")
    seed_hex = "0x" + hexlify(seed_bytes).decode()

    # (3) Keys via BIP-44 path
    acct = Account.from_mnemonic(mnemonic_phrase, account_path=derivation_path)
    private_key_hex = acct.key.hex()
    try:
        pubkey_hex = acct._key_obj.public_key.to_hex()  # uncompressed 0x04...
    except Exception:
        pubkey_hex = None

    # (4) Address + EIP-55 checksum
    address_plain = acct.address
    address_checksum = to_checksum_address(address_plain)
    eip55_ok = (address_checksum == to_checksum_address(address_plain))

    # (5) Signature roundtrip demo
    message_text = f"wallet-proof:{address_checksum}"
    msg = encode_defunct(text=message_text)
    signed = acct.sign_message(msg)
    recovered = Account.recover_message(msg, signature=signed.signature)
    signature_ok = (to_checksum_address(recovered) == address_checksum)

    return {
        "mnemonic_phrase": mnemonic_phrase,
        "bip39": {
            "checksum_ok": bool(bip39_checksum_ok),
            "passphrase_used": bool(passphrase),
        },
        "seed": {
            "hex": seed_hex,
            "bytes_len": len(seed_bytes),
        },
        "derivation": {
            "path": derivation_path,
            "private_key_hex": private_key_hex,
            "public_key_hex": pubkey_hex,
        },
        "address": {
            "plain": address_plain,
            "checksum": address_checksum,
            "eip55_ok": bool(eip55_ok),
        },
        "signature_demo": {
            "message": message_text,
            "signature": "0x" + signed.signature.hex(),
            "recovered_address": recovered,
            "ok": bool(signature_ok),
        },
        "security": {
            "do_not_reuse": True,
            "note": "Never fund or reuse educational mnemonics. Values may exist in browser memory.",
        },
    }

# --- Keep-alive for hosting ---
def keep_alive():
    """Makes a request to the /ethereum_scanner_batch endpoint to prevent idleness."""
    try:
        log.info("Sending keep-alive request to avoid server sleep...")
        url = RENDER_EXTERNAL_URL or "http://127.0.0.1:5000"
        requests.get(f"{url}/ethereum_scanner_batch?count=1")
        log.info("Keep-alive request successful.")
    except Exception as e:
        log.error(f"Keep-alive request failed: {e}")

# --- Flask app & routes ---
app = Flask(__name__, template_folder="templates", static_folder="static")

@app.route("/")
@app.route("/index.html")
def home():
    return render_template("index.html")

@app.route("/ethereum_scanner_batch", methods=["GET"])
def ethereum_scanner_batch():
    try:
        count = int(request.args.get("count", "5"))
        data = scan_batch(count)
        data_sorted = sorted(
            data,
            key=lambda w: float(w.get("balance_eth") or 0),
            reverse=True
        )
        return jsonify({"count": len(data_sorted), "wallets": data_sorted}), 200
    except requests.exceptions.RequestException as net_err:
        log.exception("Network error while querying Etherscan")
        return jsonify({"error": "Network error while querying Etherscan", "details": str(net_err)}), 502
    except Exception as e:
        log.exception("Internal server error")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@app.route("/ethereum_scanner", methods=["GET"])
def ethereum_scanner():
    try:
        data = generate_and_check_wallet_data(include_mnemonic=INCLUDE_MNEMONIC)
        status = 200 if "error" not in data else 500
        return jsonify(data), status
    except requests.exceptions.RequestException as net_err:
        log.exception("Network error while querying Etherscan")
        return jsonify({"error": "Network error while querying Etherscan", "details": str(net_err)}), 502
    except Exception as e:
        log.exception("Internal server error")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@app.route("/educational_mnemonic", methods=["GET"])
def educational_mnemonic():
    """
    Returns step-by-step derivation: mnemonic -> seed -> keys -> address (+ signature demo).
    """
    try:
        derivation_path = request.args.get("path", "m/44'/60'/0'/0/0")
        passphrase = request.args.get("passphrase", "")
        data = derive_educational_steps(passphrase=passphrase, derivation_path=derivation_path)
        return jsonify(data), 200
    except Exception as e:
        log.exception("Internal error in /educational_mnemonic")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@app.route('/health')
def health_check():
    return jsonify({"status": "up"})

if __name__ == "__main__":
    port = 5000
    log.info(f"Server on http://localhost:{port}")

    scheduler = BackgroundScheduler()
    scheduler.add_job(func=keep_alive, trigger="interval", minutes=10)
    scheduler.start()

    app.run(host="0.0.0.0", port=port, debug=True)
