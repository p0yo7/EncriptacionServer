from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

# Initialize flask server
app = Flask(__name__)
encryption_key = None
cipher_suite = None
keys = {}
messages = {}

# Hello World function
@app.route('/', methods=['GET'])
def hello_world():
        now = datetime.now()
        return jsonify({ "message": f"It's: {now.strftime('%Y-%m-%d %H:%M:%S')}" })

#Use token to make new token
def generate_key(encryption_key):
        return Fernet(encryption_key)
# New token function
@app.route('/generate-token', methods=['GET'])
def generate_token():
        global encryption_key, cipher_suite, keys
        encryption_key = Fernet.generate_key()
        cipher_suite = generate_key(encryption_key)
        keys[encryption_key] = datetime.now()
        return jsonify({ "message": f"encryption key: {encryption_key.decode()}" })

# Validar Token
@app.route('/verify-token', methods=['GET'])
def validate_token():
        headers = request.headers
        token = headers.get("Token")
        token = token.encode('utf-8')
        if token in keys and keys[token]+timedelta(hours=1)<datetime.now():
                return jsonify({ "message":"Valid Token" })
        else:
                return jsonify({ "message":"Invalid Token" }), 400

# Borrar Token
@app.route('/delete-token', methods=['POST'])
def delete_token():
        global cipher_suite
        headers = request.headers
        token = headers.get("Token")
        token = token.encode('utf-8')
        try:
                del keys[token]
                cipher_suite = None
                return jsonify({ "message": "Successfully deleted token" })
        except:
                return jsonify({ "message": "Token not deleted" }), 400

# Enviar Mensaje Encriptado Con Token
@app.route('/send-message', methods=['POST'])
def send_message():
        global cipher_suite
        try:
                if cipher_suite is None:
                        return jsonify({ "message": "Encryption failed" }), 400
                data = request.get_json()
                headers = request.headers
                token = request.headers.get("Token")
                token =  token.encode('utf-8')
                if keys[token]+timedelta(hours = 1) > datetime.now():
                    return jsonify({ "message":"Invalid Token" })
                message = data["message"]
                message_token = token + message.encode()
                encrypted_message = cipher_suite.encrypt(message_token)
                return jsonify({ "message": f"Encrypted message {encrypted_message.decode()}" })

        except:
                return jsonify({ "message": "Encryption failed" }), 400
                
@app.route('/receive-message', methods=['GET'])
def receive_message():
        global cipher_suite
        try:
                data = request.get_json()
                encrypted_message = data["message"]
                token = request.headers.get("Token")
                token =token.encode('utf-8')
                if keys[token]+timedelta(hours = 1) > datetime.now():
                    return jsonify({ "message":"Invalid Token" })
                decrypted_message = cipher_suite.decrypt(encrypted_message.encode())
                decrypted_token = decrypted_message[:len(token)]
                if decrypted_token == token:
                        message = decrypted_message[len(token):].decode()
                        return jsonify({ "message": f"Decrypted message: {message}" })
                else:
                        return jsonify({ "message": "Invalid Token" }), 400
        except Exception as ex:
                return jsonify({ "message": "Decrypting message failed" }), 400


if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0', port=3003)