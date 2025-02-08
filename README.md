# Double-Base-Number-System-DBNS-Attack

```bash
python3 DBNS.py
```

![IMG_20250208_173710](https://github.com/user-attachments/assets/3bceb698-9fe5-432c-afb1-9807df622841)

# Example Output (Public Key Vulnerable)
```bash
Enter Public Key: 040000356cb2e0d0c0a0167693b14c338f548da20fea024a04449907140fa270ebff37ae70d00db8137b5c60d9563b743b090f162f7bf1b51650d20cd7022d695d

[STEP 1] Converting Public Key to Point on secp256k1 Curve
   ↳ X-Coordinate: 1234567890123456789012345678901234567890
   ↳ Y-Coordinate: 9876543210987654321098765432109876543210

[STEP 2] Computing DBNS Representation
   ↳ Base: 2, Exponent: 109, Remaining X: 1234567890123456789012345678901234567890
   ↳ Base: 2, Exponent: 108, Remaining X: 987654321098765432109876543210987654321
   ↳ Base: 2, Exponent: 106, Remaining X: 76543210987654321098765432109876543210
   ...

[STEP 3] Checking for Vulnerability
   ↳ Repeated Exponents: [109, 108, 106, 104, 103, 101]

[FINAL RESULT]
✅ [VULNERABILITY FOUND] DBNS Representation: [(2, 109), (2, 108), (2, 106), (2, 104), (2, 103), (2, 101), ...]
[STEP 4] Attempting Private Key Extraction using DBNS Matrix
   ↳ Constructed Matrix (6x110):
   Matrix([[2, 0, 0, ..., 0], [0, 2, 0, ..., 0], ...])
   ↳ Determinant of Matrix: 18446744073709551616
   ↳ Extracted Private Key: 19283746501928374650192837465019283746

🔑 [PRIVATE KEY EXTRACTED] 19283746501928374650192837465019283746
```

