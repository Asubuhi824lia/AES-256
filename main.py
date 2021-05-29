from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes
from PyQt5.QtWidgets import QApplication, QVBoxLayout, QWidget, QPushButton, QLineEdit, QLabel
import sys

def encrypt(plain_text, password):
    # generate a random salt
    salt = get_random_bytes(AES.block_size)

    # use the Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }

def decrypt(enc_dict, password):
    # decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])

    # generate the private key from the password and salt
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted

def calc ():
    encrypted = encrypt(smText.text(), pasText.text())
    encryptedText.setText(encrypted["cipher_text"])
    decryptedText.setText(bytes.decode(decrypt(encrypted, pasText.text())))

if __name__ == '__main__':
    app = QApplication(sys.argv)

    w = QWidget()
    w.resize(400, 200)
    w.move(400, 200)
    w.setWindowTitle('AES-256')
    w.show()

    qhBox = QVBoxLayout()
    w.setLayout(qhBox)

    qhBox.addWidget(QLabel("Password:"))
    pasText = QLineEdit("pas")
    qhBox.addWidget(pasText)

    qhBox.addWidget(QLabel("Secretest message:"))
    smText = QLineEdit("The secretest message here")
    qhBox.addWidget(smText)

    btn = QPushButton('Calculate', w)
    qhBox.addWidget(btn)
    btn.clicked.connect(calc)

    qhBox.addWidget(QLabel("Encrypted:"))
    encryptedText = QLineEdit()
    qhBox.addWidget(encryptedText)

    qhBox.addWidget(QLabel("Decrypted:"))
    decryptedText = QLineEdit()
    qhBox.addWidget(decryptedText)

    qhBox.addStretch(1)

    sys.exit(app.exec_())