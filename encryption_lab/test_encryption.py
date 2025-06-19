import unittest
from encryption_platform import EncryptionPlatform

class TestEncryptionPlatform(unittest.TestCase):
    def setUp(self):
        self.platform = EncryptionPlatform()
        self.plaintext = 123456789

        self.message = "hello ECC"

    def test_rsa(self):
        pub, priv = self.platform.generate_keys("RSA")
        encrypted = self.platform.encrypt("RSA", self.plaintext, pub)
        decrypted = self.platform.decrypt("RSA", encrypted, priv)
        self.assertEqual(decrypted, self.plaintext)

    def test_elgamal(self):
        pub, priv = self.platform.generate_keys("ElGamal")
        encrypted = self.platform.encrypt("ElGamal", self.plaintext, pub)
        decrypted = self.platform.decrypt("ElGamal", encrypted, priv, pub)
        self.assertEqual(decrypted, self.plaintext)

    def test_ecc(self):
        pub, priv = self.platform.generate_keys("ECC")
        encrypted = self.platform.encrypt("ECC", self.message, pub)
        decrypted = self.platform.decrypt("ECC", encrypted, priv)
        self.assertEqual(decrypted, self.message)  # 明文 vs 解密后


if __name__ == '__main__':
    unittest.main()