import random
import sympy
import concurrent.futures
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

p = secp256k1.p
G = secp256k1.G

def dbns_representation(n):
    bases = [2, 3, 5]
    dbns_form = []
    while n > 0:
        base = random.choice(bases)
        exp = sympy.ilog(n, base)
        if exp > 0:
            dbns_form.append((base, exp))
            n -= base ** exp
    return dbns_form

def check_dbns_weakness(public_key):
    for _ in range(10000):  
        n = random.randint(1, p - 1)
        dbns_form = dbns_representation(n)
        reconstructed_n = sum(b ** e for b, e in dbns_form)
        if reconstructed_n == n:
            with open("found.txt", "a") as f:
                f.write(f"{public_key.x},{public_key.y}\n")
            return n
    return None

def process_public_key(line):
    line = line.strip()
    if len(line) < 130:
        return

    try:
        public_key = Point(int(line[:64], 16), int(line[64:], 16), secp256k1)
        result = check_dbns_weakness(public_key)
        if result:
            with open("found.txt", "a") as f:
                f.write(f"Private Key Extracted: {result}\n")
            print(f"[✔] DBNS Weakness Found: {line}")
        else:
            print(f"[-] No Weakness: {line}")
    except:
        return

def process_public_keys():
    try:
        with open("pub.txt", "r") as file:
            public_keys = file.readlines()
    except FileNotFoundError:
        print("[-] pub.txt file not found.")
        return

    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(process_public_key, public_keys)

process_public_keys()
