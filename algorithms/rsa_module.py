from Crypto.Util import number

class RSA:
    def __init__(self, key_size=1024):
        self.key_size = key_size

    def generate_keys(self):
        p = number.getPrime(self.key_size)
        q = number.getPrime(self.key_size)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        return (e, n), (d, n)

    def encrypt(self, plaintext: int, public_key):
        e, n = public_key
        return pow(plaintext, e, n)

    def decrypt(self, ciphertext: int, private_key):
        d, n = private_key
        return pow(ciphertext, d, n)
