#!/usr/bin/env python3
"""
AES-128 ECB encrypt/decrypt helper using PyCryptodome.

Usage examples:
  # decrypt (hex ct, key as string)
  python aes128_ecb.py --decrypt --hex 32F1685843C9D45C... --key my16bytepassword

  # decrypt (dec ct, key as hex)
  python aes128_ecb.py --decrypt --dec "12345678901234567890" --key-hex 00112233445566778899AABBCCDDEEFF

  # encrypt (plaintext string -> output hex)
  python aes128_ecb.py --encrypt --pt "mensagem secreta" --key "my16bytepass"

  # encrypt (plaintext hex -> output decimal big-int)
  python aes128_ecb.py --encrypt --pt-hex 48656c6c6f --key-hex 00112233445566778899AABBCCDDEEFF --out dec

Notes:
 - Key must be exactly 16 bytes (AES-128).
 - ECB mode only (no IV).
 - Default behavior: encryption uses PKCS#7 padding; decryption attempts PKCS#7 unpad unless --no-unpad.
"""

import argparse
from binascii import unhexlify, hexlify

try:
    from Crypto.Cipher import AES
except Exception as e:
    raise SystemExit("PyCryptodome não encontrado. Instale com: pip install pycryptodome\n" + str(e))

BLOCK_SIZE = 16


def pad_pkcs7(b: bytes) -> bytes:
    if len(b) % BLOCK_SIZE == 0:
        pad_len = BLOCK_SIZE
    else:
        pad_len = BLOCK_SIZE - (len(b) % BLOCK_SIZE)
    return b + bytes([pad_len]) * pad_len


def unpad_pkcs7(b: bytes) -> bytes:
    if not b:
        return b
    pad = b[-1]
    if pad < 1 or pad > BLOCK_SIZE:
        return b
    if b[-pad:] != bytes([pad]) * pad:
        return b
    return b[:-pad]


def encrypt_ecb(key: bytes, pt: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pt)


def decrypt_ecb(key: bytes, ct: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ct)


def safe_decode(b: bytes) -> str:
    try:
        return b.decode('utf-8')
    except Exception:
        return hexlify(b).decode('ascii')


def _clean_hex_prefix(s: str) -> str:
    if s is None:
        return s
    s = s.strip()
    if s.lower().startswith('0x'):
        return s[2:]
    if s.lower().startswith('hex:'):
        return s[4:]
    return s


def parse_key(args) -> bytes:
    if getattr(args, 'key_hex', None):
        s = _clean_hex_prefix(args.key_hex).strip().replace(" ", "")
        if len(s) % 2 != 0:
            s = '0' + s
        try:
            kb = unhexlify(s)
        except Exception as e:
            raise SystemExit("Chave-hex inválida: " + str(e))
        if len(kb) != 16:
            raise SystemExit(f"Chave-hex inválida: precisa ser exatamente 16 bytes (obteve {len(kb)} bytes).")
        return kb
    else:
        if getattr(args, 'key', None) is None:
            raise SystemExit("Chave não informada.")
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
    # Se for lista de bytes separados, tratar como lista
    if any(ch in s for ch in (' ', ',', ';')):
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
        # big integer
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
        if len(ct) % BLOCK_SIZE != 0:
            padded_len = ((len(ct) + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE
            ct = ct.rjust(padded_len, b'\x00')
    if len(ct) % BLOCK_SIZE != 0:
        raise SystemExit(f"Ciphertext decimal convertido tem comprimento {len(ct)} bytes — deve ser múltiplo de {BLOCK_SIZE}.")
    return ct


def ct_to_decimal_bigint(ct: bytes) -> str:
    return str(int.from_bytes(ct, 'big'))


def ct_to_decimal_list(ct: bytes) -> str:
    return ','.join(str(b) for b in ct)


def parse_plaintext_from_hex(hexstr: str) -> bytes:
    s = _clean_hex_prefix(hexstr).strip().replace(" ", "")
    if len(s) % 2 != 0:
        s = '0' + s
    try:
        return unhexlify(s)
    except Exception as e:
        raise SystemExit("Plaintext hex inválido: " + str(e))


def main():
    p = argparse.ArgumentParser(description="AES-128 ECB encrypt/decrypt helper (key string/hex, ct hex/dec)")
    mode_group = p.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--encrypt', action='store_true', help='Modo encriptar')
    mode_group.add_argument('--decrypt', action='store_true', help='Modo decriptar')

    # decrypt inputs (mutually exclusive hex/dec)
    dec_group = p.add_argument_group('decrypt options')
    dec_ct_group = dec_group.add_mutually_exclusive_group()
    dec_ct_group.add_argument('--hex', help='Ciphertext em hex (sem 0x). Compatível com versões anteriores.')
    dec_ct_group.add_argument('--dec', help='Ciphertext em decimal (big integer) ou lista de bytes decimais separados por espaço/vírgula.')

    # encrypt inputs (plaintext)
    enc_group = p.add_argument_group('encrypt options')
    enc_pt_group = enc_group.add_mutually_exclusive_group()
    enc_pt_group.add_argument('--pt', help='Plaintext como string (será codificado em UTF-8).')
    enc_pt_group.add_argument('--pt-hex', help='Plaintext em hex (bytes).')

    # key selection
    key_group = p.add_mutually_exclusive_group(required=True)
    key_group.add_argument('--key', help='Chave como string (16 bytes em UTF-8).')
    key_group.add_argument('--key-hex', help='Chave em hex (sem 0x). Deve representar exatamente 16 bytes.')

    # padding / unpadding
    p.add_argument('--no-pad', action='store_true', help='(encrypt) Não aplicar PKCS#7 pad antes de encriptar')
    p.add_argument('--no-unpad', action='store_true', help='(decrypt) Não desempacotar PKCS#7 depois da decriptação')

    # encryption output format
    p.add_argument('--out', choices=['hex', 'dec'], default='hex', help='(encrypt) formato de saída do ciphertext: hex (padrão) ou dec (big integer)')
    p.add_argument('--out-list', action='store_true', help='(encrypt) mostrar também a lista de bytes decimais separados por vírgula (útil com --out dec)')

    args = p.parse_args()

    # parse key
    key = parse_key(args)

    if args.decrypt:
        if not (args.hex or args.dec):
            raise SystemExit("Para --decrypt forneça --hex ou --dec com o ciphertext.")
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

        print('--- Resultado (DECRYPT) ---')
        if args.hex:
            print('Ciphertext (hex):', args.hex)
        else:
            print('Ciphertext (dec):', args.dec)
        if getattr(args, 'key_hex', None):
            print('Key (hex):', args.key_hex)
        else:
            print('Key (utf-8):', args.key)
        print('Plaintext (utf-8 se possível, caso contrário hex):')
        print(safe_decode(pt))
        return

    # encrypt branch
    # require plaintext
    if not (args.pt or args.pt_hex):
        raise SystemExit("Para --encrypt forneça --pt (string) ou --pt-hex (hex bytes).")

    if args.pt_hex:
        pt_bytes = parse_plaintext_from_hex(args.pt_hex)
    else:
        pt_bytes = args.pt.encode('utf-8')

    if not args.no_pad:
        pt_bytes = pad_pkcs7(pt_bytes)
    else:
        if len(pt_bytes) % BLOCK_SIZE != 0:
            raise SystemExit(f"Plaintext sem padding deve ter comprimento múltiplo de {BLOCK_SIZE} bytes; obteve {len(pt_bytes)} bytes. Use padding automático (remova --no-pad) ou forneça dados já alinhados.")

    try:
        ct = encrypt_ecb(key, pt_bytes)
    except Exception as e:
        raise SystemExit('Erro na encriptação ECB: ' + str(e))

    print('--- Resultado (ENCRYPT) ---')
    if getattr(args, 'key_hex', None):
        print('Key (hex):', args.key_hex)
    else:
        print('Key (utf-8):', args.key)

    if args.out == 'hex':
        print('Ciphertext (hex):', hexlify(ct).decode('ascii'))
    else:
        # decimal big-int representation
        print('Ciphertext (dec):', ct_to_decimal_bigint(ct))

    if args.out_list:
        print('Ciphertext (dec list):', ct_to_decimal_list(ct))

    # helpful extra: show plaintext info
    print('Plaintext (utf-8 se possível, caso contrário hex):')
    print(safe_decode(args.pt.encode('utf-8')) if args.pt else hexlify(parse_plaintext_from_hex(args.pt_hex)).decode('ascii'))


if __name__ == '__main__':
    main()
