from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
import os

BLOCK_SIZE = 16


def xor_bytes(b1, b2):
    """
    2つのバイト列をXOR
    """
    return bytes([b11 ^ b22 for b11, b22 in zip(b1, b2)])


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

    # CBC暗号では前の暗号化ブロックを用いて暗号化を行うので格納用
    previous_block = iv

    # 暗号化結果
    cbc_crypted_result = b""

    for i in range(0, len(byte_encoded_plaintext), BLOCK_SIZE):
        # スライスを用いてブロックサイズごとバイト列を取り出し
        block = byte_encoded_plaintext[i:i+BLOCK_SIZE]

        # 前の暗号化ブロックとXORを取る
        block = xor_bytes(block, previous_block)

        # AESを用いて暗号化
        encrypted_block = encrypt_block(cipher, block)

        cbc_crypted_result += encrypted_block

        previous_block = encrypted_block

    # 復号時のためにIVを先頭に追加しておく
    return iv + cbc_crypted_result


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

    plaintext = b""
    previous_block = iv

    for i in range(0, len(cbc_crypted_text_without_iv), BLOCK_SIZE):
        block = cbc_crypted_text_without_iv[i:i+BLOCK_SIZE]

        decrypted_block = decrypt_block(cipher, block)

        decrypted_block = xor_bytes(decrypted_block, previous_block)

        plaintext += decrypted_block

        previous_block = block

    # パディングを削除して返す
    return unpad(plaintext, BLOCK_SIZE)


plaintext = b"Hello, World!"

key = os.urandom(16)

ciphertext = cbc_encrypt(plaintext, key)

print("------------------------------------------")
print(f"暗号文: {plaintext.decode('utf-8')}")
print("HEX:", ' '.join(f"{byte:02x}" for byte in ciphertext))

print("------------------------------------------")
decrypted_text = cbc_decrypt(ciphertext, key)
print(f"復号文: {decrypted_text.decode('utf-8')}")
print("------------------------------------------")
