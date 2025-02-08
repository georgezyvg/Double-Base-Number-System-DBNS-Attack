from sympy import Matrix, mod_inverse
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

def hex_to_point(pubkey_hex):
    print(f"\n[STEP 1] Converting Public Key to Point on secp256k1 Curve")
    if pubkey_hex.startswith("04"):  
        x = int(pubkey_hex[2:66], 16)
        y = int(pubkey_hex[66:], 16)
        print(f"   ↳ X-Coordinate: {x}\n   ↳ Y-Coordinate: {y}")
    else:  
        raise ValueError("Compressed public keys are not supported yet.")

    return Point(x, y, secp256k1)

def dbns_representation(point, base=2):
    print("\n[STEP 2] Computing DBNS Representation")
    x = point.x
    dbns = []
    while x > 0:
        exp = x.bit_length() - 1
        dbns.append((base, exp))
        print(f"   ↳ Base: {base}, Exponent: {exp}, Remaining X: {x}")
        x -= base**exp
    return dbns

def check_vulnerability(dbns):
    print("\n[STEP 3] Checking for Vulnerability")
    pattern_count = {}
    for _, exp in dbns:
        pattern_count[exp] = pattern_count.get(exp, 0) + 1

    repeated_exponents = [exp for exp, count in pattern_count.items() if count > 1]
    print(f"   ↳ Repeated Exponents: {repeated_exponents}")
    
    return len(repeated_exponents) > 5  

def extract_private_key(point, dbns):
    print("\n[STEP 4] Attempting Private Key Extraction using DBNS Matrix")
    n = secp256k1.q  
    max_exp = max(exp for _, exp in dbns)

    matrix = []
    for base, exp in dbns:
        row = [0] * (max_exp + 1)
        row[exp] = base
        matrix.append(row)

    print(f"   ↳ Constructed Matrix ({len(matrix)}x{len(matrix[0])}):\n", Matrix(matrix))

    while len(matrix) < len(matrix[0]):  
        matrix.append([0] * len(matrix[0]))

    M = Matrix(matrix)
    det = M.det()
    print(f"   ↳ Determinant of Matrix: {det}")

    if det == 0:
        print("[ERROR] Singular Matrix Detected. Private Key Extraction Failed.")
        return None  

    k = mod_inverse(det, n)
    print(f"   ↳ Extracted Private Key: {k}")
    return k  

def main():
    pubkey_hex = input("\nEnter Public Key: ").strip()
    
    try:
        point = hex_to_point(pubkey_hex)
    except ValueError as e:
        print(f"[ERROR] {e}")
        return
    
    dbns = dbns_representation(point, base=2)  
    vulnerability = check_vulnerability(dbns)

    print("\n[FINAL RESULT]")
    if vulnerability:
        print(f"✅ [VULNERABILITY FOUND] DBNS Representation: {dbns}")
        private_key = extract_private_key(point, dbns)
        if private_key:
            print(f"🔑 [PRIVATE KEY EXTRACTED] {private_key}")
        else:
            print("❌ [ERROR] Unable to extract private key.")
    else:
        print("🔒 [SAFE] No DBNS Vulnerability Detected.")

if __name__ == "__main__":
    main()
