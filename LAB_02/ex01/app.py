from flask import Flask, render_template, request

from cipher.caesar.caesar_cipher import CaesarCipher
from cipher.playfair.playfair_cipher import PlayFairCipher
from cipher.railfence.railfence_cipher import RailFenceCipher
from cipher.transposition.transposition_cipher import TranspositionCipher
from cipher.vigenere.vigenere_cipher import VigenereCipher

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")



@app.route("/caesar")
def caesar():
    return render_template("caesar.html")


@app.route("/caesar/encrypt", methods=["POST"])
def caesar_encrypt():

    text = request.form["inputPlainText"]
    key = int(request.form["inputKeyPlain"])

    cipher = CaesarCipher()
    encrypted = cipher.encrypt_text(text, key)

    return render_template(
        "caesar.html",
        encrypted_text=encrypted,
        plain_text=text,
        key=key
    )


@app.route("/caesar/decrypt", methods=["POST"])
def caesar_decrypt():

    text = request.form["inputCipherText"]
    key = int(request.form["inputKeyCipher"])

    cipher = CaesarCipher()
    decrypted = cipher.decrypt_text(text, key)

    return render_template(
        "caesar.html",
        decrypted_text=decrypted,
        cipher_text=text,
        key=key
    )



@app.route("/playfair")
def playfair():
    return render_template("playfair.html")


@app.route("/playfair/encrypt", methods=["POST"])
def playfair_encrypt():

    text = request.form["plain_text"]
    key = request.form["key"]

    cipher = PlayFairCipher()

    matrix = cipher.create_playfair_matrix(key)
    encrypted = cipher.playfair_encrypt(text, matrix)

    return render_template(
        "playfair.html",
        encrypted_text=encrypted,
        plain_text=text,
        key=key
    )


@app.route("/playfair/decrypt", methods=["POST"])
def playfair_decrypt():

    text = request.form["cipher_text"]
    key = request.form["key"]

    cipher = PlayFairCipher()

    matrix = cipher.create_playfair_matrix(key)
    decrypted = cipher.playfair_decrypt(text, matrix)

    return render_template(
        "playfair.html",
        decrypted_text=decrypted,
        cipher_text=text,
        key=key
    )



@app.route("/railfence")
def railfence():
    return render_template("railfence.html")


@app.route("/railfence/encrypt", methods=["POST"])
def railfence_encrypt():

    text = request.form["plain_text"]
    key = int(request.form["key"])

    cipher = RailFenceCipher()

    encrypted = cipher.encrypt_text(text, key)

    return render_template(
        "railfence.html",
        encrypted_text=encrypted,
        plain_text=text,
        key=key
    )


@app.route("/railfence/decrypt", methods=["POST"])
def railfence_decrypt():

    text = request.form["cipher_text"]
    key = int(request.form["key"])

    cipher = RailFenceCipher()

    decrypted = cipher.decrypt_text(text, key)

    return render_template(
        "railfence.html",
        decrypted_text=decrypted,
        cipher_text=text,
        key=key
    )



@app.route("/transposition")
def transposition():
    return render_template("transposition.html")


@app.route("/transposition/encrypt", methods=["POST"])
def transposition_encrypt():

    text = request.form["plain_text"]
    key = int(request.form["key"])

    cipher = TranspositionCipher()

    encrypted = cipher.encrypt(text, key)

    return render_template(
        "transposition.html",
        encrypted_text=encrypted,
        plain_text=text,
        key=key
    )


@app.route("/transposition/decrypt", methods=["POST"])
def transposition_decrypt():

    text = request.form["cipher_text"]
    key = int(request.form["key"])

    cipher = TranspositionCipher()

    decrypted = cipher.decrypt(text, key)

    return render_template(
        "transposition.html",
        decrypted_text=decrypted,
        cipher_text=text,
        key=key
    )



@app.route("/vigenere")
def vigenere():
    return render_template("vigenere.html")


@app.route("/vigenere/encrypt", methods=["POST"])
def vigenere_encrypt():

    text = request.form["plain_text"]
    key = request.form["key"]

    cipher = VigenereCipher()

    encrypted = cipher.encrypt(text, key)

    return render_template(
        "vigenere.html",
        encrypted_text=encrypted,
        plain_text=text,
        key=key
    )


@app.route("/vigenere/decrypt", methods=["POST"])
def vigenere_decrypt():

    text = request.form["cipher_text"]
    key = request.form["key"]

    cipher = VigenereCipher()

    decrypted = cipher.decrypt(text, key)

    return render_template(
        "vigenere.html",
        decrypted_text=decrypted,
        cipher_text=text,
        key=key
    )



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=True)