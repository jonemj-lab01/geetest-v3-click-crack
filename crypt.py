import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = "Dt8j9wGw%6HbxfFn".encode('utf-8')
IV  = "0123456789ABCDEF".encode('utf-8')


def decrypt(encrypted_hex: str) -> str:
    try:
        encrypted_bytes = binascii.unhexlify(encrypted_hex)

        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        decrypted_padded = cipher.decrypt(encrypted_bytes)

        decrypted = unpad(decrypted_padded, AES.block_size)

        return decrypted.decode('utf-8')

    except Exception as e:
        raise ValueError(f"解密失败: {e}") from e


def encrypt(plain_text: str) -> str:
    data = plain_text.encode('utf-8')
    padded = pad(data, AES.block_size)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_bytes = cipher.encrypt(padded)
    return binascii.hexlify(encrypted_bytes).decode('ascii')


if __name__ == "__main__":
    ciphertext = '5f660e9063c40ead5d372a67665addb1c3c7d2eafb43397e612220d516bc7a65ab018f09faa4477785e6fa1a75c490ac4a313c42f20a7bb5057eb1adc086d73d'

    try:
        plain = decrypt(ciphertext)
        print("解密结果:", plain)

        # 再加密一次，验证是否与原密文一致
        # re_encrypt = encrypt(plain)
        # print("重新加密:", re_encrypt)
        # print("是否一致:", re_encrypt.lower() == ciphertext.lower())

    except Exception as e:
        print(e)