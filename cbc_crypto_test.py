from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
import os

BLOCK_SIZE = 16


def encrypt_block(cipher, block):
    """
    AESモードでの暗号化
    """
    return cipher.encrypt(block)


def decrypt_block(cipher, block):
    """
    AESモードでの復号
    """
    return cipher.decrypt(block)


def cbc_encrypt(plaintext, key):
    """
    CBCモードでブロック暗号を生成する
    """
    # 初回暗号化に必要なランダムのビット列を生成する
    iv = os.urandom(BLOCK_SIZE)

    # AES-256方式でAES暗号を生成する (32バイトのランダムな鍵を生成)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # 最初にバイト列にしてパディングを追加しておく
    byte_encoded_plaintext = pad(plaintext, BLOCK_SIZE)

    # 暗号化
    ciphertext = cipher.encrypt(byte_encoded_plaintext)

    # 復号時のためにIVを先頭に追加しておく
    return iv + ciphertext


def cbc_decrypt(cbc_crypted_text, key):
    """
    復号
    """
    # 暗号化時に追加した初期化ベクトルIVを取り出しておく
    iv = cbc_crypted_text[:BLOCK_SIZE]
    # 残りの暗号文
    cbc_crypted_text_without_iv = cbc_crypted_text[BLOCK_SIZE:]

    # AES-256方式でAES暗号を生成する (32バイトのランダムな鍵を生成)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # 復号
    plaintext = cipher.decrypt(cbc_crypted_text_without_iv)

    # パディングを削除して返す
    return unpad(plaintext, BLOCK_SIZE)


key = os.urandom(32)  # AES-256用の鍵を生成

plaintext = b"Hello, World!"

ciphertext = cbc_encrypt(plaintext, key)
print("-------------------------------------")
print(f"暗号文: {str(plaintext.decode('utf-8'))}")
print(f"HEX: {ciphertext.hex()}")
print("-------------------------------------")

decrypted_text = cbc_decrypt(ciphertext, key)
print(f"復号文: {decrypted_text.decode('utf-8')}")
print("-------------------------------------")
