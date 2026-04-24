
SBOX = [0x9, 0x4, 0xA, 0xB,
        0xD, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3,
        0xC, 0xE, 0xF, 0x7]

INV_SBOX = [0xA, 0x5, 0x9, 0xB,
            0x1, 0x7, 0x8, 0xF,
            0x6, 0x0, 0x2, 0x3,
            0xC, 0x4, 0xD, 0xE]

RCON1 = 0x80 
RCON2 = 0x30 


def gf_mult(a: int, b: int) -> int:

    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a
        hi = a & 0x8
        a = (a << 1) & 0xF
        if hi:
            a ^= 0x3        
        b >>= 1
    return p


def sub_nibbles_byte(byte: int) -> int:
    hi = SBOX[(byte >> 4) & 0xF]
    lo = SBOX[byte & 0xF]
    return (hi << 4) | lo


def key_schedule(key: int) -> tuple:
    w0 = (key >> 8) & 0xFF
    w1 = key & 0xFF

    w2 = w0 ^ RCON1 ^ sub_nibbles_byte(w1)
    w3 = w2 ^ w1

    w4 = w2 ^ RCON2 ^ sub_nibbles_byte(w3)
    w5 = w4 ^ w3

    K0 = (w0 << 8) | w1
    K1 = (w2 << 8) | w3
    K2 = (w4 << 8) | w5
    return K0, K1, K2


def get_nibble(state: int, row: int, col: int) -> int:
    shift = 12 - (col * 8 + row * 4)
    return (state >> shift) & 0xF


def set_nibble(state: int, row: int, col: int, val: int) -> int:
    shift = 12 - (col * 8 + row * 4)
    mask = ~(0xF << shift) & 0xFFFF
    return (state & mask) | ((val & 0xF) << shift)


def add_round_key(state: int, key: int) -> int:
    return state ^ key


def nibble_sub(state: int, inverse: bool = False) -> int:
    box = INV_SBOX if inverse else SBOX
    result = 0
    for i in range(4):
        shift = i * 4
        nibble = (state >> shift) & 0xF
        result |= box[nibble] << shift
    return result


def shift_rows(state: int) -> int:
    s00 = get_nibble(state, 0, 0)
    s10 = get_nibble(state, 1, 0)
    s01 = get_nibble(state, 0, 1)
    s11 = get_nibble(state, 1, 1)
    result = 0
    result = set_nibble(result, 0, 0, s00)
    result = set_nibble(result, 1, 0, s11)  
    result = set_nibble(result, 0, 1, s01)
    result = set_nibble(result, 1, 1, s10)   
    return result


def inv_shift_rows(state: int) -> int:
    return shift_rows(state)


def mix_columns(state: int) -> int:
    result = 0
    for col in range(2):
        s0 = get_nibble(state, 0, col)
        s1 = get_nibble(state, 1, col)
        n0 = s0 ^ gf_mult(4, s1)
        n1 = gf_mult(4, s0) ^ s1
        result = set_nibble(result, 0, col, n0)
        result = set_nibble(result, 1, col, n1)
    return result


def inv_mix_columns(state: int) -> int:
    result = 0
    for col in range(2):
        s0 = get_nibble(state, 0, col)
        s1 = get_nibble(state, 1, col)
        n0 = gf_mult(9, s0) ^ gf_mult(2, s1)
        n1 = gf_mult(2, s0) ^ gf_mult(9, s1)
        result = set_nibble(result, 0, col, n0)
        result = set_nibble(result, 1, col, n1)
    return result


def saes_encrypt_block(plaintext: int, key: int) -> int:
    K0, K1, K2 = key_schedule(key)
    state = add_round_key(plaintext, K0)

    state = nibble_sub(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, K1)

    state = nibble_sub(state)
    state = shift_rows(state)
    state = add_round_key(state, K2)
    return state & 0xFFFF


def saes_decrypt_block(ciphertext: int, key: int) -> int:

    K0, K1, K2 = key_schedule(key)
    state = add_round_key(ciphertext, K2)

    state = inv_shift_rows(state)
    state = nibble_sub(state, inverse=True)
    state = add_round_key(state, K1)

    state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = nibble_sub(state, inverse=True)
    state = add_round_key(state, K0)
    return state & 0xFFFF


def ctr_keystream_block(key: int, nonce: int, counter: int) -> int:

    counter_block = ((nonce & 0xFF) << 8) | (counter & 0xFF)
    return saes_encrypt_block(counter_block, key)


def ctr_process(data: bytes, key: int, nonce: int, initial_counter: int = 0) -> bytes:
   

    output = bytearray()
    counter = initial_counter

    i = 0
    while i < len(data):
        ks_block = ctr_keystream_block(key, nonce, counter & 0xFF)

        ks_bytes = [(ks_block >> 8) & 0xFF, ks_block & 0xFF]
        for kb in ks_bytes:
            if i < len(data):
                output.append(data[i] ^ kb)
                i += 1
        counter = (counter + 1) & 0xFF  

    return bytes(output)


def encrypt_ctr(plaintext: bytes, key: int, nonce: int) -> bytes:
    return ctr_process(plaintext, key, nonce)


def decrypt_ctr(ciphertext: bytes, key: int, nonce: int) -> bytes:
    return ctr_process(ciphertext, key, nonce)



def brute_force(ciphertext: bytes, nonce: int,
                known_plaintext: bytes = None,
                plaintext_hint: str = None) -> list:
   
    results = []
    total = 0x10000

    for key in range(total):
        candidate = ctr_process(ciphertext, key, nonce)

        if known_plaintext:
            if candidate == known_plaintext:
                results.append((key, candidate))
                break 

        elif plaintext_hint:
            try:
                text = candidate.decode('utf-8', errors='strict')
                if plaintext_hint.lower() in text.lower():
                    results.append((key, candidate))
            except Exception:
                pass

        else:

            if all(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in candidate):
                results.append((key, candidate))

    return results


def frequency_analysis(ciphertext: bytes) -> dict:
 
    freq = {}
    for b in ciphertext:
        freq[b] = freq.get(b, 0) + 1

    n = len(ciphertext)
    ioc = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1)) if n > 1 else 0

    return {
        'byte_frequency': dict(sorted(freq.items(), key=lambda x: -x[1])[:10]),
        'index_of_coincidence': round(ioc, 6),
        'total_bytes': n,
        'unique_bytes': len(freq),
        'note': 'English text IoC ≈ 0.065; random ≈ 0.038'
    }

def get_int_input(prompt, bits):
    while True:
        val = input(prompt)
        try:
            if val.startswith("0x"):
                num = int(val, 16)
            else:
                num = int(val)
            if 0 <= num < (1 << bits):
                return num
            else:
                print(f"❌ Must be {bits}-bit value")
        except:
            print("❌ Invalid number format")


def encrypt_text():
    text = input("Enter plaintext: ").encode()
    key = get_int_input("Enter key (16-bit): ", 16)
    nonce = get_int_input("Enter nonce (8-bit): ", 8)

    cipher = encrypt_ctr(text, key, nonce)
    print(f"\n🔐 Cipher (hex): {cipher.hex()}\n")


def decrypt_text():
    text = input("Enter ciphertext (hex): ")
    key = get_int_input("Enter key (16-bit): ", 16)
    nonce = get_int_input("Enter nonce (8-bit): ", 8)

    try:
        data = bytes.fromhex(text)
        plain = decrypt_ctr(data, key, nonce)
        print(f"\n🔓 Decrypted: {plain.decode(errors='ignore')}\n")
    except:
        print("❌ Invalid hex input")


def encrypt_file():
    path = input("Enter file path: ")
    key = get_int_input("Enter key (16-bit): ", 16)
    nonce = get_int_input("Enter nonce (8-bit): ", 8)

    try:
        with open(path, "rb") as f:
            data = f.read()

        result = encrypt_ctr(data, key, nonce)

        out_path = path + ".enc"
        with open(out_path, "wb") as f:
            f.write(result)

        print(f"✅ Encrypted file saved as: {out_path}")
    except Exception as e:
        print("❌ Error:", e)


def decrypt_file():
    path = input("Enter encrypted file path: ")
    key = get_int_input("Enter key (16-bit): ", 16)
    nonce = get_int_input("Enter nonce (8-bit): ", 8)

    try:
        with open(path, "rb") as f:
            data = f.read()

        result = decrypt_ctr(data, key, nonce)

        out_path = path + ".dec"
        with open(out_path, "wb") as f:
            f.write(result)

        print(f"✅ Decrypted file saved as: {out_path}")
    except Exception as e:
        print("❌ Error:", e)


def run_bruteforce():
    text = input("Enter ciphertext (hex): ")
    nonce = get_int_input("Enter nonce (8-bit): ", 8)

    data = bytes.fromhex(text)

    mode = input("Use (1) known plaintext or (2) hint? ")

    if mode == "1":
        known = input("Enter known plaintext: ").encode()
        results = brute_force(data, nonce, known_plaintext=known)

    else:
        hint = input("Enter hint (word inside plaintext): ")
        results = brute_force(data, nonce, plaintext_hint=hint)

    print("\n🔍 Results:")
    for k, pt in results[:5]:
        print(f"Key: 0x{k:04X} → {pt}")


def run_frequency():
    text = input("Enter ciphertext (hex): ")
    data = bytes.fromhex(text)

    stats = frequency_analysis(data)

    print("\n📊 Frequency Analysis:")
    for k, v in stats.items():
        print(f"{k}: {v}")


def main():
    while True:
        print("\n" + "="*50)
        print("   🔐 S-AES CTR Interactive Tool")
        print("="*50)
        print("1. Encrypt Text")
        print("2. Decrypt Text")
        print("3. Encrypt File")
        print("4. Decrypt File")
        print("5. Brute Force Attack")
        print("6. Frequency Analysis")
        print("0. Exit")

        choice = input("\nSelect option: ")

        if choice == "1":
            encrypt_text()
        elif choice == "2":
            decrypt_text()
        elif choice == "3":
            encrypt_file()
        elif choice == "4":
            decrypt_file()
        elif choice == "5":
            run_bruteforce()
        elif choice == "6":
            run_frequency()
        elif choice == "0":
            print("👋 Bye!")
            break
        else:
            print("❌ Invalid choice")


if __name__ == "__main__":
    main()