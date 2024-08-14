from flask import Flask, render_template, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Util.Padding import pad
import base64
import binascii
import os
import random
import string
from markupsafe import escape

# Константы для шифрования
KEY_LENGTH = 16
IV_LENGTH = 16


def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


def create_keys():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key(), PKCS1_v1_5.new(key)


def encrypt_message(text, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = pad(text.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted).decode('utf-8')


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = binascii.hexlify(os.urandom(2048)).decode()
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True

    return app


app = create_app()

# Генерация ключей
private_key, public_key, decryptor = create_keys()
key = generate_random_string(KEY_LENGTH).encode()
iv = generate_random_string(IV_LENGTH).encode()
print(f"key: {key}")
print(f"iv: {iv}")

messages = []
encrypt_messages = []


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('chat.html', public_key=public_key)


@app.route('/post_message', methods=['POST'])
def post_message():
    try:
        encoded_message = request.form['message']
        encoded_name = request.form['name']
        message = decryptor.decrypt(base64.b64decode(encoded_message), "Error decrypting").decode("utf-8")
        name = decryptor.decrypt(base64.b64decode(encoded_name), "Error decrypting").decode("utf-8")

        name = escape(name)
        message = escape(message)

        messages.append({'name': name, 'message': message})

        encrypted_name = encrypt_message(name, key, iv)
        encrypted_message = encrypt_message(message, key, iv)

        encrypt_messages.append({'name': encrypted_name, 'message': encrypted_message})
        print(messages)
        return jsonify({'status': 'OK'})
    except Exception as e:
        return jsonify({'status': 'ERROR', 'message': str(e)})


@app.route('/get_messages')
def get_messages():
    return jsonify(encrypt_messages)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80, debug=False)
