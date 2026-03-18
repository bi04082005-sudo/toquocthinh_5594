class VigenereCipher:

    def __init__(self):
        pass


    # ===== WRAPPER =====
    # để app.py gọi được

    def encrypt(self, plain_text, key):
        return self.vigenere_encrypt(plain_text, key)

    def decrypt(self, cipher_text, key):
        return self.vigenere_decrypt(cipher_text, key)


    # ===== ALGORITHM =====

    def generate_key(self, text, key):

        key = list(key)

        if len(text) == len(key):
            return key

        else:
            for i in range(len(text) - len(key)):
                key.append(key[i % len(key)])

        return "".join(key)


    def vigenere_encrypt(self, plain_text, key):

        plain_text = plain_text.upper()
        key = key.upper()

        key = self.generate_key(plain_text, key)

        cipher_text = []

        for i in range(len(plain_text)):

            x = (ord(plain_text[i]) + ord(key[i])) % 26
            x += ord('A')

            cipher_text.append(chr(x))

        return "".join(cipher_text)


    def vigenere_decrypt(self, cipher_text, key):

        cipher_text = cipher_text.upper()
        key = key.upper()

        key = self.generate_key(cipher_text, key)

        original_text = []

        for i in range(len(cipher_text)):

            x = (ord(cipher_text[i]) - ord(key[i]) + 26) % 26
            x += ord('A')

            original_text.append(chr(x))

        return "".join(original_text)