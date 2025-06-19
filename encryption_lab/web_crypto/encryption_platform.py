from algorithms.rsa_module import RSA
from algorithms.elgamal_module import ElGamal
from algorithms.ecc_module import ECC
import time

class EncryptionPlatform:
    def __init__(self):
        self.algorithms = {
            "RSA": RSA(),
            "ElGamal": ElGamal(),
            "ECC": ECC()
        }

    def generate_keys(self, algo_name):
        return self.algorithms[algo_name].generate_keys()

    def encrypt(self, algo_name, plaintext, public_key):
        return self.algorithms[algo_name].encrypt(plaintext, public_key)

    def decrypt(self, algo_name, ciphertext, private_key, public_key=None):
        if algo_name == "ElGamal":
            return self.algorithms[algo_name].decrypt(ciphertext, private_key, public_key)
        elif algo_name == "ECC":
            return self.algorithms[algo_name].decrypt(ciphertext, private_key)
        else:
            return self.algorithms[algo_name].decrypt(ciphertext, private_key)

    def timed_generate_keys(self, algo_name):
        start = time.time()
        keys = self.generate_keys(algo_name)
        end = time.time()
        return keys, end - start


    def timed_encrypt(self, algo_name, plaintext, public_key):
        start = time.time()
        ciphertext = self.encrypt(algo_name, plaintext, public_key)
        end = time.time()
        return ciphertext, end - start

    # 带计时的解密（ElGamal 需要公钥）
    def timed_decrypt(self, algo_name, ciphertext, private_key, public_key=None):
        start = time.time()
        if algo_name == "ElGamal":
            plaintext = self.decrypt(algo_name, ciphertext, private_key, public_key)
        else:
            plaintext = self.decrypt(algo_name, ciphertext, private_key)
        end = time.time()
        return plaintext, end - start