from Crypto.Util import number
import random

class ElGamal:
    def __init__(self, key_size=256):
        self.key_size = key_size

    def generate_keys(self):
        p = number.getPrime(self.key_size)
        g = random.randint(2, p - 2)
        x = random.randint(1, p - 2)
        y = pow(g, x, p)
        return (p, g, y), x

    def encrypt(self, plaintext: int, public_key):
        p, g, y = public_key
        k = random.randint(1, p - 2)
        a = pow(g, k, p)
        b = (plaintext * pow(y, k, p)) % p
        return a, b

    def decrypt(self, ciphertext: tuple, private_key, public_key):
        a, b = ciphertext
        p, _, _ = public_key
        s = pow(a, private_key, p)
        s_inv = pow(s, -1, p)
        return (b * s_inv) % p
