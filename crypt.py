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
    ciphertext = '5588a9e126c91a28cc2f6813e379336923bf42c9814280cca7955d2725a88b28aa9f67ba49e38bba18200c236f59ee56cd5f102797f6156556892827e735513be8454527e37c692849daa1545e11e9256c1ca97e88a5d50e2fe0cd49a6a2b0048693d4c289e183b15e82b4dee122456812e5c0fecac8f1e6ca81233320d470656f1bd70ab942536ea68a33c5bacfb75f6d7ceaa22bdcf404ceb781339cb833a482d6572177cf2e34dbf0e08ca96406d51b912e167837b7284e966b7eff72533c4e85fcbc1ec347b523b5480d2b6ab7517e4e2a0d6be070508c70cc6b1bef3702997cedaf8226efbc9fb1a045eb0638c64b392df1ffaaf10beaa6a98ae957a305ac0efb22c6ca8cfc18543824d82cdf4dee0efdbd65a61e3c064f89cf227432d57bbd07b11cf95031430edab77875f7537bcad6b989491ae00dfd1c8a001db56181c0399e1b62b80fd4de16da3f8cf82f84610bb9f57d1158523547a60b457071445f0d4461ae575fbc3c8b53c6728cb6f100f357f07090cce4b637a05526e4c8ead04c2fdb18be1c939acea202713624341a463cfb5fdb0dd375526af0dbea49f1a0d98b0fdbcdd31754aebba9beebdee2c6d7da47f82fda82f37980025b2608afbb21b736a44a67c65b704e7ef69619c3dac0d4e2129bc39d9d2d9a56cd01d9364abef30fb51f033fb28f53f2aeb1821cec32d9ed0e5869175d00c609f566b737f59b5247b0e72cca8f476121b18df401f64ce66b31dc84eb4cf030e3ca1b20133c36954b959139f32a9525b96550dbdc554b805c8ec6d2cccab6458753ed44a1241c18634a99aef092be766197a2ef1ac0952810755c26e69e35fd3bf47f4255a8cd5a880e204a2c1dda37a6d383136081e5fc44a9e762ac1e6aa24c4f943f3b18d0496f8cd96626ef5b0497fbad5f3020d97089ec0e6a402799bb5679bc57bba2baa521e0df24194afc607c3bb7b84d1532eda927c5f8ef2030088207e63c'

    try:
        plain = decrypt(ciphertext)
        print("解密结果:", plain)

        # 再加密一次，验证是否与原密文一致
        # re_encrypt = encrypt(plain)
        # print("重新加密:", re_encrypt)
        # print("是否一致:", re_encrypt.lower() == ciphertext.lower())

    except Exception as e:
        print(e)