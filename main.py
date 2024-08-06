from flask import Flask, render_template, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Util.Padding import pad
import base64
import binascii
from markupsafe import escape
import threading
import os
import random
import string

def generate_random_string(length):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))

messages = []
encrypt_messages = []

key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()
rsakey = RSA.importKey(private_key)
decryptor = PKCS1_v1_5.new(rsakey)

key = generate_random_string(16).encode()  # 16-байтный ключ
iv = generate_random_string(16).encode()    # 16-байтный вектор инициализации
print(f"key: {key}")
print(f"iv: {iv}")
cipher = AES.new(key, AES.MODE_CBC, iv)


def encrypt_message(text):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = pad(text.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted).decode('utf-8')

app = Flask(__name__)
app.config['SECRET_KEY'] = binascii.hexlify(os.urandom(2048)).decode()
app.config['WTF_CSRF_ENABLED'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('chat.html', public_key=public_key)


@app.route('/post_message', methods=['POST'])
def post_message():
    message = request.form['message']
    name = request.form['name']
    message = decryptor.decrypt(base64.b64decode(message),
                                "Error decrypting").decode("utf-8")
    name = decryptor.decrypt(base64.b64decode(name),
                            "Error decrypting").decode("utf-8")
    name = escape(name)
    message = escape(message)
    messages.append({'name': name, 'message': message})
    message = encrypt_message(message)
    name = encrypt_message(name)
    encrypt_messages.append({'name': name, 'message': message})
    print(messages)
    return jsonify({'status': 'OK'})


@app.route('/get_messages')
def get_messages():
    return jsonify(encrypt_messages)


def server():
    if __name__ == '__main__':
        app.run(host="0.0.0.0", port=80, debug=False)


server = threading.Thread(target=server)
server.start()
server.join()