import os
import sys
import json
import time
from decimal import Decimal
from web3 import Web3, HTTPProvider
from eth_account import Account
import requests

RPC = "https://arb1.arbitrum.io/rpc"
ETHERSCAN_API_KEY = "JKWC2SSA98471H7531YIHUH7YCIBIFDIFE"
ARBISCAN_API_KEY = "AY9RUFYWMHHUP89K1VNBTFQ9NUD2EBF2D1"

USDT_ADDRESS = Web3.to_checksum_address("0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9")
USDC_ADDRESS = Web3.to_checksum_address("0xaf88d065e77c8cC2239327C5EDb3A432268e5831")
USDT_DECIMALS = 6
USDC_DECIMALS = 6
CHAIN_ID = 42161

w3 = Web3(HTTPProvider(RPC))

if not w3.is_connected():
    print("Ошибка: не удалось подключиться к RPC:", RPC, file=sys.stderr)
    sys.exit(1)

ERC20_ABI = [
    {"constant":True,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"},
    {"constant":False,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"success","type":"bool"}],"type":"function"},
    {"constant":True,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"},
    {"constant":True,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"type":"function"},
]

usdt_contract = w3.eth.contract(address=USDT_ADDRESS, abi=ERC20_ABI)
usdc_contract = w3.eth.contract(address=USDC_ADDRESS, abi=ERC20_ABI)


WALLET_FILE = os.path.expanduser("~/.arb_wallet.json")

def save_wallet(data):
    with open(WALLET_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    try:
        os.chmod(WALLET_FILE, 0o600)
    except Exception:
        pass

def load_wallet():
    if not os.path.exists(WALLET_FILE):
        return {}
    try:
        with open(WALLET_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def create_wallet(save=True):
    acct = Account.create(os.urandom(32))
    data = {"address": acct.address, "private_key": acct.key.hex()}
    if save:
        save_wallet(data)
    return data


def import_wallet(privkey_hex, save=True):
    priv = privkey_hex.strip()
    if priv.startswith("0x"):
        priv = priv[2:]
    acct = Account.from_key(bytes.fromhex(priv))
    data = {"address": acct.address, "private_key": "0x"+priv}
    if save:
        save_wallet(data)
    return data


def eth_balance(address):
    b = w3.eth.get_balance(address)
    return Decimal(b) / Decimal(10**18)


def erc20_balance(token_contract, address, decimals):
    """Получить баланс ERC-20 через RPC"""
    raw = token_contract.functions.balanceOf(Web3.to_checksum_address(address)).call()
    return Decimal(raw) / Decimal(10**decimals)


def get_usdc_balance_v2(wallet_address, api_key=None, use_rpc=True):
    wallet_address = Web3.to_checksum_address(wallet_address)

    if use_rpc:
        try:
            raw = usdc_contract.functions.balanceOf(wallet_address).call()
            balance = Decimal(raw) / Decimal(10**USDC_DECIMALS)
            return balance
        except Exception as e:
            print(f"⚠️  RPC ошибка: {e}, попытаемся использовать API V2...")

    if api_key:
        try:
            url = "https://api.etherscan.io/v2/api"
            params = {
                "chainid": CHAIN_ID,
                "address": wallet_address,
                "module": "account",
                "action": "tokenbalance",
                "contractaddress": USDC_ADDRESS,
                "tag": "latest",
                "apikey": api_key
            }
            response = requests.get(url, params=params, timeout=10)
            data = response.json()
            
            if data.get('status') == '1':
                balance = Decimal(data['result']) / Decimal(10**USDC_DECIMALS)
                return balance
            else:
                raise Exception(f"API Error: {data.get('message', 'Unknown')}")
        except Exception as e:
            print(f"❌ API V2 ошибка: {e}")
            return Decimal(-1)
    
    return Decimal(-1)


def get_eth_price_usd():
    try:
        r = requests.get("https://api.coingecko.com/api/v3/simple/price",
                         params={"ids":"ethereum","vs_currencies":"usd"}, timeout=10)
        r.raise_for_status()
        data = r.json()
        return Decimal(str(data.get("ethereum", {}).get("usd", 0)))
    except Exception:
        return Decimal(0)


def sign_and_send_tx(tx, privkey):
    if privkey.startswith("0x"):
        k = privkey[2:]
    else:
        k = privkey
    try:
        signed = Account.sign_transaction(tx, bytes.fromhex(k))
        if hasattr(signed, 'rawTransaction'):
            raw_tx = signed.rawTransaction
        else:
            raw_tx = signed[0] if isinstance(signed, tuple) else signed
        tx_hash = w3.eth.send_raw_transaction(raw_tx)
        return tx_hash.hex()
    except Exception as e:
        print(f"❌ Ошибка подписи/отправки: {e}")
        return None


def build_common_tx(from_addr, to_addr, value_wei=None, gas=None, max_priority_fee_gwei=None, max_fee_gwei=None):
    nonce = w3.eth.get_transaction_count(from_addr)
    chain_id = w3.eth.chain_id
    if max_priority_fee_gwei is None:
        try:
            mpf = w3.eth.max_priority_fee
            max_priority_fee_gwei = w3.fromWei(mpf, "gwei")
        except Exception:
            max_priority_fee_gwei = 1
    if max_fee_gwei is None:
        try:
            base = w3.eth.gas_price
            max_fee_gwei = w3.fromWei(base, "gwei") * 2
        except Exception:
            max_fee_gwei = max_priority_fee_gwei + 2

    tx = {
        "chainId": chain_id,
        "nonce": nonce,
        "to": Web3.to_checksum_address(to_addr),
        "type": 2,
        "maxPriorityFeePerGas": int(Decimal(max_priority_fee_gwei) * Decimal(10**9)),
        "maxFeePerGas": int(Decimal(max_fee_gwei) * Decimal(10**9)),
    }
    if value_wei is not None:
        tx["value"] = int(value_wei)
    if gas is not None:
        tx["gas"] = int(gas)
    return tx


def send_eth(privkey, to, amount_eth, gas_limit=None, max_priority_fee_gwei=None, max_fee_gwei=None, send_all=False):
    if privkey.startswith("0x"):
        priv = privkey[2:]
    else:
        priv = privkey
    acct = Account.from_key(bytes.fromhex(priv))

    current_balance = w3.eth.get_balance(acct.address)

    if send_all:
        temp_tx = build_common_tx(acct.address, to, current_balance, gas_limit, max_priority_fee_gwei, max_fee_gwei)
        try:
            gas_est = w3.eth.estimate_gas(temp_tx)
            gas_to_use = int(gas_est * 1.2)
        except Exception:
            gas_to_use = 21000
        
        fee_per_gas = temp_tx.get("maxFeePerGas", w3.eth.gas_price)
        gas_cost = gas_to_use * fee_per_gas
        
        value_wei = current_balance - gas_cost
        if value_wei < 0:
            print(f"❌ Недостаточно ETH для покрытия газа. Баланс: {Decimal(current_balance)/Decimal(10**18):.6f} ETH, требуется ~{Decimal(gas_cost)/Decimal(10**18):.6f} ETH")
            return None
        
        print(f"📤 Отправка всего баланса минус газ: {Decimal(value_wei)/Decimal(10**18):.6f} ETH")
    else:
        value_wei = int(Decimal(amount_eth) * Decimal(10**18))
    
    tx = build_common_tx(acct.address, to, value_wei, gas_limit, max_priority_fee_gwei, max_fee_gwei)
    if "gas" not in tx:
        try:
            tx_est = tx.copy()
            tx_est["from"] = acct.address
            tx_est["value"] = value_wei
            gas_est = w3.eth.estimate_gas(tx_est)
            tx["gas"] = int(gas_est * 1.2)
        except Exception:
            tx["gas"] = 21000
    return sign_and_send_tx(tx, "0x"+priv)


def send_erc20(privkey, token_contract, to, amount_token, gas_limit=None, max_priority_fee_gwei=None, max_fee_gwei=None, send_all=False):
    if privkey.startswith("0x"):
        priv = privkey[2:]
    else:
        priv = privkey
    acct = Account.from_key(bytes.fromhex(priv))
    decimals = token_contract.functions.decimals().call()
    
    eth_balance_wei = w3.eth.get_balance(acct.address)
    eth_balance = Decimal(eth_balance_wei) / Decimal(10**18)
    
    
    if send_all:
        balance_raw = token_contract.functions.balanceOf(acct.address).call()
        raw_amount = balance_raw
        amount_display = Decimal(balance_raw) / Decimal(10**decimals)
        print(f"📤 Отправка всего баланса: {amount_display:.6f} токенов")
    else:
        raw_amount = int(Decimal(amount_token) * (10 ** decimals))
    
    tx_func = token_contract.functions.transfer(Web3.to_checksum_address(to), raw_amount)

    nonce = w3.eth.get_transaction_count(acct.address)
    if max_priority_fee_gwei is None:
        try:
            mpf = w3.eth.max_priority_fee
            max_priority_fee_gwei = w3.fromWei(mpf, "gwei")
        except Exception:
            max_priority_fee_gwei = 0.1
    if max_fee_gwei is None:
        try:
            base = w3.eth.gas_price
            max_fee_gwei = w3.fromWei(base, "gwei") + 1
        except Exception:
            max_fee_gwei = 0.5

    tx_for_estimate = tx_func.build_transaction({
        "chainId": w3.eth.chain_id,
        "nonce": nonce,
        "from": acct.address,
        "type": 2,
        "maxPriorityFeePerGas": int(Decimal(str(max_priority_fee_gwei)) * Decimal(10**9)),
        "maxFeePerGas": int(Decimal(str(max_fee_gwei)) * Decimal(10**9)),
    })
    
    if gas_limit:
        estimated_gas = int(gas_limit)
    else:
        try:
            estimated_gas = w3.eth.estimate_gas(tx_for_estimate)
            estimated_gas = int(estimated_gas * 1.3)
        except Exception as e:
            print(f"⚠️  Ошибка оценки газа: {e}")
            estimated_gas = 100_000
    
    tx_for_estimate["gas"] = estimated_gas
    
    max_fee_wei = int(Decimal(str(max_fee_gwei)) * Decimal(10**9))
    gas_cost = estimated_gas * max_fee_wei
    
    print(f"⛽ Оценка газа: {estimated_gas} units (~{Decimal(gas_cost)/Decimal(10**18):.6f} ETH)")
    
    if gas_cost > eth_balance_wei:
        print(f"❌ ОШИБКА: Недостаточно ETH для газа!")
        print(f"   Баланс ETH: {eth_balance:.6f} ETH")
        print(f"   Требуется для газа: ~{Decimal(gas_cost)/Decimal(10**18):.6f} ETH")
        return None
    
    return sign_and_send_tx(tx_for_estimate, "0x"+priv)


def tx_history_arbiscan(address, startblock=0, endblock=99999999, page=1, offset=50, sort='desc'):
    if not ARBISCAN_API_KEY:
        print("ARBISCAN_API_KEY не установлен — история по API недоступна.", file=sys.stderr)
        return
    url = "https://api.arbiscan.io/api"
    params = {"module":"account","action":"txlist","address":address,
              "startblock":startblock,"endblock":endblock,"page":page,"offset":offset,"sort":sort,"apikey":ARBISCAN_API_KEY}
    r = requests.get(url, params=params, timeout=20)
    r.raise_for_status()
    data = r.json()
    if data.get("status") != "1":
        print("Arbiscan:", data.get("message"))
        return
    txs = data.get("result", [])
    for t in txs:
        ts = int(t.get("timeStamp", 0))
        print(f"{t.get('hash')} | block {t.get('blockNumber')} | {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ts))} | {t.get('from')} -> {t.get('to')} | {Decimal(t.get('value'))/Decimal(10**18)} ETH | gasUsed {t.get('gasUsed')}")


def pretty_header(wallet):
    addr = wallet.get("address") if wallet else "—"
    eth = Decimal(0)
    usdt = Decimal(0)
    usdc = Decimal(0)
    eth_price = Decimal(0)
    total_usd = Decimal(0)
    
    if wallet and wallet.get("address"):
        try:
            eth = eth_balance(wallet["address"])
        except Exception:
            eth = Decimal(-1)
        try:
            usdt = erc20_balance(usdt_contract, wallet["address"], USDT_DECIMALS)
        except Exception:
            usdt = Decimal(-1)
        try:
            usdc = get_usdc_balance_v2(wallet["address"], api_key=ETHERSCAN_API_KEY, use_rpc=True)
        except Exception:
            usdc = Decimal(-1)
        
        eth_price = get_eth_price_usd()

        stable_total = Decimal(0)
        if usdt >= 0:
            stable_total += usdt
        if usdc >= 0:
            stable_total += usdc
        eth_usd = eth * eth_price if eth >= 0 else Decimal(0)
        total_usd = eth_usd + stable_total

    print("="*64)
    print("Arbitrum Wallet".center(64))
    print("-"*64)
    print(f"Адрес: {addr}")
    if eth >= 0:
        print(f"ETH: {eth:.6f}")
    else:
        print("ETH: n/a")
    if usdt >= 0:
        print(f"USDT: {usdt:.6f}")
    else:
        print("USDT: n/a")
    if usdc >= 0:
        print(f"USDC: {usdc:.6f}")
    else:
        print("USDC: n/a")

    if eth_price > 0:
        print("-"*64)
        print(f"Portfolio (USD): {(total_usd):,.2f}  (ETH price {eth_price:.2f} USD)".center(64))
    else:
        print("-"*64)
        print(f"Portfolio (USD): {(total_usd):,.2f}".center(64))
    print("="*64)


def main_loop():
    wallet = load_wallet()
    while True:
        try:
            pretty_header(wallet)
            print("Меню:")
            print("1) Создать новый кошелёк (создаст и сохранит приватный ключ в ~/.arb_wallet.json)")
            print("2) Импортировать приватный ключ (сохранить в ~/.arb_wallet.json)")
            print("3) Показать балансы (ETH, USDT, USDC)")
            print("4) Отправить ETH")
            print("5) Отправить USDT")
            print("6) Отправить USDC")
            print("7) Показать историю транзакций (Arbiscan API required)")
            print("8) Показать приватный ключ (Осторожно!)")
            print("9) Удалить сохранённый кошелёк")
            print("0) Выход")
            choice = input("Выберите пункт: ").strip()
            
            if choice == "1":
                w = create_wallet(save=True)
                wallet = w
                print("Создан и сохранён кошелёк:", wallet["address"])
            elif choice == "2":
                pk = input("Вставьте приватный ключ (0x...): ").strip()
                try:
                    w = import_wallet(pk, save=True)
                    wallet = w
                    print("Импортирован и сохранён:", wallet["address"])
                except Exception as e:
                    print("Ошибка импорта:", e)
            elif choice == "3":
                if not wallet.get("address"):
                    print("Кошелёк не настроен. Сначала создайте или импортируйте.")
                    continue
                try:
                    eth = eth_balance(wallet["address"])
                    usdt = erc20_balance(usdt_contract, wallet["address"], USDT_DECIMALS)

                    usdc = get_usdc_balance_v2(wallet["address"], api_key=ETHERSCAN_API_KEY, use_rpc=True)
                    print(f"ETH: {eth:.6f}")
                    print(f"USDT: {usdt:.6f}")
                    print(f"USDC: {usdc:.6f}")
                except Exception as e:
                    print("Ошибка получения балансов:", e)
            elif choice == "4":
                if not wallet.get("private_key"):
                    print("У вас нет приватного ключа в хранилище. Импортируйте приватный ключ (пункт 2) или создайте кошелёк (1).")
                    continue
                to = input("Кому (адрес): ").strip()
                amt = input("Сколько ETH (например 0.01, или 'all' для отправки всего минус газ): ").strip()
                gas = input("gas limit (enter для автоподбора): ").strip() or None
                try:
                    if amt.lower() == "all":
                        txh = send_eth(wallet["private_key"], to, None, gas_limit=int(gas) if gas else None, send_all=True)
                    else:
                        txh = send_eth(wallet["private_key"], to, Decimal(amt), gas_limit=int(gas) if gas else None)
                    if txh:
                        print("✅ Отправлено, tx hash:", txh)
                except Exception as e:
                    print("❌ Ошибка отправки ETH:", e)
            elif choice == "5":
                if not wallet.get("private_key"):
                    print("Нужен приватный ключ в хранилище.")
                    continue
                to = input("Кому (адрес): ").strip()
                amt = input(f"Сколько USDT (десятичные, {USDT_DECIMALS}, или 'all' для отправки всего): ").strip()
                gas = input("gas limit (enter для автоподбора, обычно ~100k): ").strip() or None
                try:
                    if amt.lower() == "all":
                        txh = send_erc20(wallet["private_key"], usdt_contract, to, None, gas_limit=int(gas) if gas else None, send_all=True)
                    else:
                        txh = send_erc20(wallet["private_key"], usdt_contract, to, Decimal(amt), gas_limit=int(gas) if gas else None)
                    if txh:
                        print("✅ Отправлено, tx hash:", txh)
                except Exception as e:
                    print("❌ Ошибка отправки USDT:", e)
            elif choice == "6":
                if not wallet.get("private_key"):
                    print("Нужен приватный ключ в хранилище.")
                    continue
                to = input("Кому (адрес): ").strip()
                amt = input(f"Сколько USDC (десятичные, {USDC_DECIMALS}, или 'all' для отправки всего): ").strip()
                gas = input("gas limit (enter для автоподбора, обычно ~100k): ").strip() or None
                try:
                    if amt.lower() == "all":
                        txh = send_erc20(wallet["private_key"], usdc_contract, to, None, gas_limit=int(gas) if gas else None, send_all=True)
                    else:
                        txh = send_erc20(wallet["private_key"], usdc_contract, to, Decimal(amt), gas_limit=int(gas) if gas else None)
                    if txh:
                        print("✅ Отправлено, tx hash:", txh)
                except Exception as e:
                    print("❌ Ошибка отправки USDC:", e)
            elif choice == "7":
                if not wallet.get("address"):
                    print("Кошелёк не настроен.")
                    continue
                if not ARBISCAN_API_KEY:
                    print("ARBISCAN_API_KEY не установлен — невозможно получить историю через API.")
                    continue
                try:
                    start = input("startblock (enter=0): ").strip() or "0"
                    end = input("endblock (enter=99999999): ").strip() or "99999999"
                    tx_history_arbiscan(wallet["address"], startblock=int(start), endblock=int(end))
                except Exception as e:
                    print("Ошибка запроса истории:", e)
            elif choice == "8":
                if not wallet.get("private_key"):
                    print("Приватный ключ не сохранён.")
                    continue
                confirm = input("Показать приватный ключ? Это опасно! Подтвердите y/N: ").strip().lower()
                if confirm == "y":
                    print("Private key:", wallet["private_key"])
            elif choice == "9":
                confirm = input("Удалить файл ~/.arb_wallet.json? y/N: ").strip().lower()
                if confirm == "y":
                    try:
                        os.remove(WALLET_FILE)
                    except Exception:
                        pass
                    wallet = {}
                    print("Сохранённый кошелёк удалён.")
            elif choice == "0":
                print("Пока.")
                break
            else:
                print("Неизвестный пункт.")
            input("Нажмите Enter чтобы продолжить...")
        except KeyboardInterrupt:
            print("\nВыход.")
            break


if __name__ == "__main__":
    try:
        main_loop()
    except Exception as e:
        print("Fatal:", e, file=sys.stderr)
        raise
