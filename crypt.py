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
    ciphertext = '638d882f721469a32cd0948d5e35d40e8730fc739f1b92f440817cf7863678d74616ef937b91e28dd54f6921c166c58466ea438769128167415e041afe6dc16d829c6fc117155d1820ff84f130699a9f73c2fbd6e40621113760d70c456081ba64599cf96230393a24e9f0e1049a6080f9ba2efd503de04041d07162a74a98c7a569ae052dc383c96fdd99a9f98e9478e13c0e790bf32c50b4a9bee06371c943561b92b11396b28018b5f18988f1fd96'

    try:
        plain = decrypt(ciphertext)
        print("解密结果:", plain)

        # 再加密一次，验证是否与原密文一致
        # re_encrypt = encrypt(plain)
        # print("重新加密:", re_encrypt)
        # print("是否一致:", re_encrypt.lower() == ciphertext.lower())

    except Exception as e:
        print(e)