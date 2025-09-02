# app.py
import os
import time
import logging
from typing import Dict, List, Tuple

import requests
from flask import Flask, jsonify, render_template, request
from mnemonic import Mnemonic
from eth_utils import to_checksum_address
from eth_account import Account
from dotenv import load_dotenv
from eth_account.messages import encode_defunct
from flask import Flask, request, make_response

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("wallet_scanner")

# USANDO VARIABLES DE ENTORNO PARA EVITAR EL HARDCODE DE LA API KEY DE ETHERESCAN

load_dotenv()
 
ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "")
if not ETHERSCAN_API_KEY:
    log.error("ETHERSCAN_API_KEY no configurada. Defínela en las variables de entorno.")

INCLUDE_MNEMONIC = True  # en prod ponlo False

REQUEST_TIMEOUT = 15
RATE_SLEEP_SECONDS = 0.22  # ~4.5 req/s (free tier)

TOKENS: Dict[str, Tuple[str, int]] = {
    "USDT": ("0xdAC17F958D2ee523a2206206994597C13D831ec7", 6),
    "BNB" : ("0xB8c77482e45F1F44dE1745F52C74426C631bDD52", 18),  # opcional demo
    "USDC": ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6),
    "LINK": ("0x514910771AF9Ca656af840dff83E8264EcF986CA", 18),
    "UNI" : ("0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", 18),
    "SHIB": ("0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE", 18),
}

mnemo = Mnemonic("english")
Account.enable_unaudited_hdwallet_features()

def _etherscan_get(params: Dict) -> Dict:
    base = "https://api.etherscan.io/api"
    r = requests.get(base, params={**params, "apikey": ETHERSCAN_API_KEY}, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if data.get("status") == "0" and data.get("message") not in ("No transactions found",):
        raise RuntimeError(f"Etherscan error: {data.get('message')} / {data.get('result')}")
    return data

def _safe_int(x: str) -> int:
    try: return int(x)
    except: return 0

def generate_and_check_wallet_data(include_mnemonic: bool = False) -> Dict:
    if not ETHERSCAN_API_KEY:
        return {"error": "ETHERSCAN_API_KEY no configurada."}

    # 1) Generación y validación BIP-39
    mnemonic_phrase = mnemo.generate(strength=128)
    bip39_checksum_ok = False
    try:
        bip39_checksum_ok = mnemo.check(mnemonic_phrase)
    except Exception:
        bip39_checksum_ok = False

    # 2) Derivación estándar m/44'/60'/0'/0/0
    derivation_path = "m/44'/60'/0'/0/0"
    acct = Account.from_mnemonic(mnemonic_phrase, account_path=derivation_path)
    address = to_checksum_address(acct.address)  # Normaliza a EIP-55
    eip55_checksum_ok = address == to_checksum_address(address)

    # 3) Firma y verificación local (prueba de control real)
    signature_roundtrip_ok = False
    try:
        msg_text = f"wallet-proof:{address}"
        msg = encode_defunct(text=msg_text)
        signed = acct.sign_message(msg)
        recovered = Account.recover_message(msg, signature=signed.signature)
        signature_roundtrip_ok = (to_checksum_address(recovered) == address)
    except Exception:
        signature_roundtrip_ok = False

    # 4) Consulta Etherscan (marca de salud de red)
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
        logging.warning(f"Fallo balance ETH para {address}: {e}")
        etherscan_ok = False

    # 5) Tokens
    token_balances: List[Dict] = []
    for symbol, (token_addr, decimals) in TOKENS.items():
        try:
            tok = _etherscan_get({
                "module": "account", "action": "tokenbalance",
                "address": address, "contractaddress": token_addr, "tag": "latest"
            })
            raw = _safe_int(tok.get("result", "0"))
            bal = raw / (10**decimals)
        except Exception as e:
            logging.warning(f"Fallo token {symbol} para {address}: {e}")
            bal = 0.0
        token_balances.append({"token_address": token_addr, "balance": bal})
        time.sleep(RATE_SLEEP_SECONDS)

    # 6) Respuesta
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

    # Control explícito por parámetro
    if include_mnemonic:
        resp["mnemonic_phrase"] = mnemonic_phrase

    return resp

def scan_one_wallet(include_mnemonic: bool = False) -> Dict:
    """Scan single wallet. Mnemonic inclusion is controlled by parameter."""
    return generate_and_check_wallet_data(include_mnemonic=include_mnemonic)


def scan_batch(count: int) -> List[Dict]:
    """
    Generate and scan multiple wallets. Hard-limit to [1, 50] for demo safety.
    Mnemonics are NEVER included in batch responses.
    """
    count = max(1, min(count, 50))
    results: List[Dict] = []
    for _ in range(count):
        results.append(scan_one_wallet(include_mnemonic=False))
        time.sleep(0.1)
    return results



app = Flask(__name__, template_folder="templates", static_folder="static")

@app.route("/")
@app.route("/index.html")  # alias para evitar 404 si alguien navega directo
def home():
    return render_template("index.html")

@app.route("/ethereum_scanner_batch", methods=["GET"])
def ethereum_scanner_batch():
    try:
        # ?count=10  (default 5)
        count = int(request.args.get("count", "5"))
        data = scan_batch(count)

        # Ordena por ETH desc en el servidor (opcional)
        data_sorted = sorted(
            data,
            key=lambda w: float(w.get("balance_eth") or 0),
            reverse=True
        )
        return jsonify({"count": len(data_sorted), "wallets": data_sorted}), 200
    except requests.exceptions.RequestException as net_err:
        log.exception("Error de red al consultar Etherscan")
        return jsonify({"error": "Error de red al consultar Etherscan", "details": str(net_err)}), 502
    except Exception as e:
        log.exception("Error interno del servidor")
        return jsonify({"error": "Error interno del servidor", "details": str(e)}), 500
    
    
@app.route("/ethereum_scanner", methods=["GET"])
def ethereum_scanner():
    try:
        # Forzar inclusión de mnemónica siempre en el endpoint individual
        data = generate_and_check_wallet_data(include_mnemonic=True)
        status = 200 if "error" not in data else 500
        return jsonify(data), status
    except requests.exceptions.RequestException as net_err:
        log.exception("Error de red al consultar Etherscan")
        return jsonify({"error": "Error de red al consultar Etherscan", "details": str(net_err)}), 502
    except Exception as e:
        log.exception("Error interno del servidor")
        return jsonify({"error": "Error interno del servidor", "details": str(e)}), 500
    
@app.after_request
def add_security_headers(resp):
    # Evita que navegadores/CDN almacenen la respuesta
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"

    # Evita fuga en cabeceras Referer
    resp.headers["Referrer-Policy"] = "no-referrer"

    # Endurece manejo de tipos
    resp.headers["X-Content-Type-Options"] = "nosniff"

    # Evita indexación por crawlers
    resp.headers["X-Robots-Tag"] = "noindex, noarchive, nosnippet"

    # Importante: NO establecer X-Frame-Options aquí; lo haremos con CSP en el paso 2
    return resp



if __name__ == "__main__":
    port = 5000
    log.info(f"Servidor en http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
