from algorithms.rsa_module import RSA
from algorithms.elgamal_module import ElGamal
from algorithms.ecc_module import ECC

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
