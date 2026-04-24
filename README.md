# S-AES with CTR Mode — IN410 Cryptography Project

## Overview
Implementation of **Simplified AES (S-AES)** combined with **Counter (CTR)** operation mode, built entirely from scratch in Python — no AES/DES standard libraries used.

---

## Algorithm Summary

### S-AES
S-AES is a pedagogical cipher designed by Stalling & Musa that mirrors full AES structure but operates on smaller data:

| Property | S-AES | Full AES |
|----------|-------|----------|
| Block size | 16 bits | 128 bits |
| Key size | 16 bits | 128/192/256 bits |
| Rounds | 2 | 10/12/14 |
| State | 2×2 nibble matrix | 4×4 byte matrix |

**S-AES Operations:**
1. `AddRoundKey` — XOR state with round key
2. `NibbleSub` — substitute nibbles via 4-bit S-Box (GF(2⁴))
3. `ShiftRows` — rotate row 1 of the 2×2 state
4. `MixColumns` — matrix multiply in GF(2⁴) using matrix [[1,4],[4,1]]
5. **Key Schedule** — expands 16-bit key into 3 round keys (K0, K1, K2)

### CTR (Counter) Mode
CTR turns S-AES into a **stream cipher**:

```
Counter_i  = Nonce (8 bits) || i (8 bits)
Keystream_i = S-AES_Encrypt(Key, Counter_i)
Ciphertext_i = Plaintext_i XOR Keystream_i
```

- Encryption and decryption are **identical operations**
- Supports **parallel** processing (each block is independent)
- Requires a unique **nonce** per key to ensure security

---

## File Structure

```
saes_ctr.py          # Main implementation
README.md            # This file
```

---

## Usage

### Encrypt / Decrypt Text

```python
from saes_ctr import encrypt_ctr, decrypt_ctr

KEY   = 0x3A4B        # 16-bit integer key
NONCE = 0xB4          # 8-bit nonce (must be unique per encryption)
MSG   = b"Secret message"

# Encrypt
ciphertext = encrypt_ctr(MSG, KEY, NONCE)
print(ciphertext.hex())

# Decrypt
plaintext = decrypt_ctr(ciphertext, KEY, NONCE)
print(plaintext)      # b"Secret message"
```

### Brute-Force Attack

```python
from saes_ctr import brute_force

# Known-plaintext attack (fastest — finds exact key)
hits = brute_force(ciphertext, NONCE, known_plaintext=b"Secret")

# Ciphertext-only (heuristic: printable ASCII filter)
candidates = brute_force(ciphertext, NONCE)

for key, plaintext in hits:
    print(f"Key: 0x{key:04X} → {plaintext}")
```

### Frequency Analysis

```python
from saes_ctr import frequency_analysis

stats = frequency_analysis(ciphertext)
print(stats['index_of_coincidence'])  # ~0.038 for CTR (pseudo-random)
```

---

## Cryptanalysis Methods

### 1. Brute-Force Attack
- Key space: 2¹⁶ = **65,536** possible keys
- **Known-plaintext attack**: XOR first bytes and check — O(n) per key
- All 65,536 keys can be tested in milliseconds on modern hardware

### 2. Known-Plaintext Attack (KPA)
If any portion of plaintext is known:
```
keystream = ciphertext XOR known_plaintext
```
Then test each key to find which one generates that keystream.

### 3. Ciphertext-Only Attack (COA)
Use linguistic heuristics:
- Printable ASCII filter
- Index of Coincidence (IoC) — English text ≈ 0.065
- Byte frequency analysis

### 4. Frequency / IoC Analysis
Since CTR produces pseudo-random output, the IoC ≈ 0.038 (flat distribution), confirming the mode is working correctly. However with a **wrong key guess**, decrypted output often contains non-printable bytes — used as the brute-force filter.

---

## Security Note
S-AES is **not secure** for real-world use — its 16-bit key space is trivially brute-forced. It is designed purely for learning the AES structure and cryptanalysis concepts.

---

## Dependencies
- Python 3.8+
- No external libraries required

---

## Running the Demo

```bash
python3 saes_ctr.py
```

---

## References
- Stallings, W. — *Cryptography and Network Security* (S-AES chapter)
- NIST FIPS 197 — Advanced Encryption Standard
- Stinson, D.R. — *Cryptography: Theory and Practice*
