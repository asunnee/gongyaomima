# algorithms/ecc_module.py
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256
import json, base64

class ECC:
    """
    ECC 加密模块，基于 ECIES (Elliptic Curve Integrated Encryption Scheme) 实现。
    使用 SECP256k1 椭圆曲线和 AES-GCM 对称加密。

    方法:
    - generate_keys(): 生成 ECC 密钥对
    - encrypt(message: str, public_key): 使用接收方公钥加密字符串消息，返回 JSON 格式密文字符串
    - decrypt(ciphertext_str: str, private_key): 使用私钥解密 ECIES 密文，返回原始字符串
    """

    def generate_keys(self):
        """
        生成 ECC 密钥对。
        :return: (public_key: VerifyingKey, private_key: SigningKey)
        """
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key = private_key.verifying_key
        return public_key, private_key

    def encrypt(self, message: str, public_key: VerifyingKey) -> str:
        """
        使用接收方的公钥加密字符串消息。
        实现步骤：
        1. 生成一次性临时密钥对 (ephemeral_sk, ephemeral_vk)
        2. 通过椭圆曲线点乘计算共享秘钥：shared_secret = SHA256(ephemeral_sk * public_key)
        3. 使用 AES-GCM 对 message 进行对称加密
        4. 将临时公钥、nonce、tag、加密数据打包成 JSON，base64 编码后返回
        """
        # 一次性密钥对
        ephemeral_sk = SigningKey.generate(curve=SECP256k1)
        ephemeral_vk = ephemeral_sk.verifying_key

        # 计算共享密钥（使用 x 坐标）
        shared_point = public_key.pubkey.point * ephemeral_sk.privkey.secret_multiplier
        shared_secret = sha256(int.to_bytes(shared_point.x(), 32, 'big')).digest()

        # 对称加密
        cipher = AES.new(shared_secret, AES.MODE_GCM)
        ciphertext_bytes, tag = cipher.encrypt_and_digest(message.encode())

        # 打包密文
        data = {
            'ephemeral_pub': base64.b64encode(ephemeral_vk.to_string()).decode(),
            'nonce': base64.b64encode(cipher.nonce).decode(),
            'tag': base64.b64encode(tag).decode(),
            'ciphertext': base64.b64encode(ciphertext_bytes).decode()
        }
        return json.dumps(data)

    def decrypt(self, ciphertext_str: str, private_key: SigningKey) -> str:
        """
        使用私钥解密 encrypt() 生成的 JSON 格式密文。
        实现步骤：
        1. 解析 JSON，base64 解码临时公钥、nonce、tag、密文
        2. 恢复临时公钥对象
        3. 计算共享秘钥：SHA256(ephemeral_vk * private_key)
        4. 使用 AES-GCM 解密并验证 tag，返回解密后文本
        """
        data = json.loads(ciphertext_str)

        # 恢复临时公钥
        ephemeral_bytes = base64.b64decode(data['ephemeral_pub'])
        ephemeral_vk = VerifyingKey.from_string(ephemeral_bytes, curve=SECP256k1)

        # 重新计算共享密钥
        shared_point = ephemeral_vk.pubkey.point * private_key.privkey.secret_multiplier
        shared_secret = sha256(int.to_bytes(shared_point.x(), 32, 'big')).digest()

        # 解密
        nonce = base64.b64decode(data['nonce'])
        tag = base64.b64decode(data['tag'])
        ciphertext_bytes = base64.b64decode(data['ciphertext'])
        cipher = AES.new(shared_secret, AES.MODE_GCM, nonce=nonce)
        plaintext_bytes = cipher.decrypt_and_verify(ciphertext_bytes, tag)
        return plaintext_bytes.decode()
