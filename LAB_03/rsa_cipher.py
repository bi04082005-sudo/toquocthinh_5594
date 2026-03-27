import sys
import requests
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from ui.rsa import Ui_MainWindow

os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = "./platforms"

class RSAApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Connect buttons
        self.ui.btn_gen_key.clicked.connect(self.generate_keys)
        self.ui.btn_encrypt.clicked.connect(self.encrypt_message)
        self.ui.btn_decrypt.clicked.connect(self.decrypt_message)
        self.ui.btn_sign.clicked.connect(self.sign_message)
        self.ui.btn_verify.clicked.connect(self.verify_signature)

    def generate_keys(self):
        try:
            url = "http://127.0.0.1:5000/api/rsa/generate_keys"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                QMessageBox.information(self, "Success", data['message'])
            else:
                QMessageBox.warning(self, "Error", "Failed to generate keys")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def encrypt_message(self):
        try:
            url = "http://127.0.0.1:5000/api/rsa/encrypt"
            payload = {
                "message": self.ui.txt_plain_text.toPlainText(),
                "key_type": "public"  # Usually encrypt with public key
            }
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.ui.txt_cipher_text.setText(data['encrypted_message'])
                QMessageBox.information(self, "Success", "Encrypted successfully")
            else:
                QMessageBox.warning(self, "Error", "Encryption failed")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def decrypt_message(self):
        try:
            url = "http://127.0.0.1:5000/api/rsa/decrypt"
            payload = {
                "ciphertext": self.ui.txt_cipher_text.toPlainText(),
                "key_type": "private"  # Usually decrypt with private key
            }
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.ui.txt_plain_text.setText(data['decrypted_message'])
                QMessageBox.information(self, "Success", "Decrypted successfully")
            else:
                QMessageBox.warning(self, "Error", "Decryption failed")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def sign_message(self):
        try:
            url = "http://127.0.0.1:5000/api/rsa/sign"
            payload = {
                "message": self.ui.txt_plain_text.toPlainText()
            }
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.ui.txt_sign.setText(data['signature'])
                QMessageBox.information(self, "Success", "Message signed successfully")
            else:
                QMessageBox.warning(self, "Error", "Signing failed")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def verify_signature(self):
        try:
            url = "http://127.0.0.1:5000/api/rsa/verify"
            payload = {
                "message": self.ui.txt_plain_text.toPlainText(),
                "signature": self.ui.txt_sign.toPlainText()
            }
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                if data['is_verified']:
                    self.ui.txt_info.setText("Signature is VALID")
                    QMessageBox.information(self, "Verified", "Signature is VALID")
                else:
                    self.ui.txt_info.setText("Signature is INVALID")
                    QMessageBox.warning(self, "Invalid", "Signature is INVALID")
            else:
                QMessageBox.warning(self, "Error", "Verification failed")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RSAApp()
    window.show()
    sys.exit(app.exec_())
