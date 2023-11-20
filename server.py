from flask import Flask, request, jsonify

import aes_cbc
from frodokem import FrodoKEM
from nist_kat import NISTKAT
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Setting a secret key for the session


@app.route('/check', methods=['GET'])
def check_server():
    return 'Server is up and running!'


@app.route('/1st-interface', methods=['POST'])
def generate_keypair():
    data = request.get_json()
    if 'string' not in data:
        return jsonify({'error': 'String parameter(UID) is missing'}), 400
    uid = data['string']
    directory = 'student_files'
    if not os.path.exists(directory):
        os.makedirs(directory)
    filename = os.path.join(directory, f"{uid}.txt")
    kat_values = NISTKAT.run(FrodoKEM('FrodoKEM-640-SHAKE'))
    true_secret = kat_values['sk'][19264:]
    with open(filename, 'w') as file:
        file.write(f"Variant: {kat_values['variant']}\n")
        file.write(f"Count: {kat_values['count']}\n")
        file.write(f"Seed: {kat_values['seed']}\n")
        file.write(f"Public Key: {kat_values['pk']}\n")
        file.write(f"Secret Key: {kat_values['sk']}\n")
        file.write(f"True Secret: {true_secret}\n")
    return jsonify({'message': 'Key pair generated and stored.', 'public_key': kat_values['pk']}), 200


@app.route('/2nd-interface', methods=['POST'])
def decapsulate():
    data = request.get_json()
    if 'UID' not in data or 'cipher_text' not in data:
        return jsonify({'error': 'Missing parameters'}), 400
    uid = data['UID']
    cipher_text = data['cipher_text']
    filename = os.path.join('student_files', f"{uid}.txt")
    if not filename:
        return jsonify({'error': 'Invalid UID'}), 400
    with open(filename, 'r') as file:
        content = file.read()
        variant = content.split('Variant: ')[1].split('\n')[0]
        secret_key = content.split('Secret Key: ')[1].split('\n')[0]
    kem_instance = FrodoKEM(variant)
    ss_d = kem_instance.kem_decaps(bytes.fromhex(secret_key), bytes.fromhex(cipher_text))
    modified_cipher_text = aes_cbc.encrypt_aes_128_cbc(ss_d.hex().upper())
    with open(filename, 'a') as file:
        file.write(f"Shared Secret Decapsulated: {ss_d.hex().upper()}\n")
        file.write(f"Modified Cipher Text: {modified_cipher_text.hex().upper()}\n")
    return jsonify({'new_cipher': modified_cipher_text.hex().upper()}), 200


@app.route('/3rd-interface', methods=['POST'])
def check_sk():
    data = request.get_json()
    if 'UID' not in data or 'secret_key' not in data:
        return jsonify({'error': 'Missing parameters'}), 400
    uid = data['UID']
    secret_key = data['secret_key']
    filename = os.path.join('student_files', f"{uid}.txt")
    if not filename:
        return jsonify({'error': 'Invalid UID'}), 400
    with open(filename, 'r') as file:
        content = file.read()
        true_secret_key = content.split('True Secret: ')[1].split('\n')[0]
    if true_secret_key == secret_key:
        return jsonify({'message': "And hast thou slain the Jabberwock?\nCome to my arms, my beamish cryptographer!\nO frabjous day! Callooh! Callay!\nHe chortled in his joy."}), 200
    else:
        return jsonify({'message': "Secret Key guess was incorrect.\n The Server refused to yield!"}), 400


if __name__ == '__main__':
    app.run(debug=True)
