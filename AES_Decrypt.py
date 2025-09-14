#!/usr/bin/env python3
"""
AES-128 ECB-only decryption helper using PyCryptodome.

Now accepts:
 - Key as UTF-8 string via --key (exactly 16 bytes required)
 - Key as hex via --key-hex (exactly 16 bytes required after decoding)
 - Ciphertext as hex via --hex (backwards compatible)
 - Ciphertext as decimal via --dec:
     * either a big integer (e.g. 1234567890)
     * or a list of decimal bytes separated by spaces or commas (e.g. "34 255 0 16")

Usage examples:
  python aes128_decryptor.py --hex 32F168... --key mysecretpassword
  python aes128_decryptor.py --hex 32F168... --key-hex 00112233445566778899AABBCCDDEEFF
  python aes128_decryptor.py --dec "12345678901234567890" --key mysecretpassword
  python aes128_decryptor.py --dec "34,255,0,16" --key-hex 00112233445566778899AABBCCDDEEFF
"""

import argparse
from binascii import unhexlify, hexlify

try:
    from Crypto.Cipher import AES
except Exception as e:
    raise SystemExit("PyCryptodome não encontrado. Instale com: pip install pycryptodome\n" + str(e))

BLOCK_SIZE = 16


def unpad_pkcs7(b: bytes) -> bytes:
    if not b:
        return b
    pad = b[-1]
    if pad < 1 or pad > BLOCK_SIZE:
        return b
    if b[-pad:] != bytes([pad]) * pad:
        return b
    return b[:-pad]


def decrypt_ecb(key: bytes, ct: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ct)


def safe_decode(b: bytes) -> str:
    try:
        return b.decode('utf-8')
    except Exception:
        return hexlify(b).decode('ascii')


def _clean_hex_prefix(s: str) -> str:
    if s.lower().startswith('0x'):
        return s[2:]
    if s.lower().startswith('hex:'):
        return s[4:]
    return s


def parse_key(args) -> bytes:
    if args.key_hex:
        s = _clean_hex_prefix(args.key_hex).strip().replace(" ", "")
        if len(s) % 2 != 0:
            s = '0' + s  # pad odd length
        try:
            kb = unhexlify(s)
        except Exception as e:
            raise SystemExit("Chave-hex inválida: " + str(e))
        if len(kb) != 16:
            raise SystemExit(f"Chave-hex inválida: precisa ser exatamente 16 bytes (obteve {len(kb)} bytes).")
        return kb
    else:
        # key as string
        kb = args.key.encode('utf-8')
        if len(kb) != 16:
            raise SystemExit(f"Chave-string inválida: a chave em UTF-8 deve ter exatamente 16 bytes (obteve {len(kb)} bytes).")
        return kb


def parse_ct_from_hex(hexstr: str) -> bytes:
    s = _clean_hex_prefix(hexstr).strip().replace(" ", "")
    if len(s) % 2 != 0:
        s = '0' + s
    try:
        ct = unhexlify(s)
    except Exception as e:
        raise SystemExit("Ciphertext hex inválido: " + str(e))
    if len(ct) % BLOCK_SIZE != 0:
        raise SystemExit(f"Ciphertext inválido: comprimento deve ser múltiplo de {BLOCK_SIZE} bytes (obteve {len(ct)} bytes).")
    return ct


def parse_ct_from_decimal(decstr: str) -> bytes:
    s = decstr.strip()
    # if it contains spaces or commas, treat as list of decimal bytes
    if any(ch in s for ch in (' ', ',', ';')):
        # split on spaces, commas or semicolons
        parts = [p for p in (s.replace(',', ' ').replace(';', ' ').split()) if p != ""]
        try:
            b_list = [int(p) for p in parts]
        except Exception as e:
            raise SystemExit("Formato decimal inválido (lista): " + str(e))
        for b in b_list:
            if b < 0 or b > 255:
                raise SystemExit("Cada elemento na lista decimal deve estar entre 0 e 255.")
        ct = bytes(b_list)
    else:
        # treat as big integer
        try:
            n = int(s, 10)
            if n < 0:
                raise ValueError("Número decimal negativo não permitido.")
        except Exception as e:
            raise SystemExit("Formato decimal inválido (big integer): " + str(e))
        if n == 0:
            ct = b'\x00'
        else:
            byte_len = (n.bit_length() + 7) // 8
            ct = n.to_bytes(byte_len, 'big')
        # it's common for big-int textual representations to omit leading zero bytes,
        # so left-pad with zeros to next multiple of BLOCK_SIZE if needed
        if len(ct) % BLOCK_SIZE != 0:
            padded_len = ((len(ct) + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE
            ct = ct.rjust(padded_len, b'\x00')
    if len(ct) % BLOCK_SIZE != 0:
        raise SystemExit(f"Ciphertext decimal convertido tem comprimento {len(ct)} bytes — deve ser múltiplo de {BLOCK_SIZE}.")
    return ct


def main():
    p = argparse.ArgumentParser(description="AES-128 ECB-only decryption helper (aceita chaves string/hex e ct hex/decimal)")
    group_ct = p.add_mutually_exclusive_group(required=True)
    group_ct.add_argument('--hex', help='Ciphertext em hex (sem 0x). Mantido por compatibilidade.')
    group_ct.add_argument('--dec', help='Ciphertext em decimal (big integer) ou lista de bytes decimais separados por espaço/vírgula.')
    key_group = p.add_mutually_exclusive_group(required=True)
    key_group.add_argument('--key', help='Chave como string (16 bytes em UTF-8).')
    key_group.add_argument('--key-hex', help='Chave em hex (sem 0x). Deve representar exatamente 16 bytes.')
    p.add_argument('--no-unpad', action='store_true', help='Não remover PKCS#7 depois da decriptação')
    args = p.parse_args()

    # parse key
    key = parse_key(args)

    # parse ciphertext
    if args.hex:
        ct = parse_ct_from_hex(args.hex)
    else:
        ct = parse_ct_from_decimal(args.dec)

    try:
        pt = decrypt_ecb(key, ct)
    except Exception as e:
        raise SystemExit('Erro na decriptação ECB: ' + str(e))

    if not args.no_unpad:
        pt = unpad_pkcs7(pt)

    print('--- Resultado ---')
    if args.hex:
        print('Ciphertext (hex):', args.hex)
    else:
        print('Ciphertext (dec):', args.dec)
    if args.key_hex:
        print('Key (hex):', args.key_hex)
    else:
        print('Key (utf-8):', args.key)
    print('Plaintext (utf-8 se possível, caso contrário hex):')
    print(safe_decode(pt))


if __name__ == '__main__':
    main()
