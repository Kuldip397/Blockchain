from collections import OrderedDict
from flask import Flask, jsonify, request
import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

class Transaction:

    def __init__(self, sender_address, sender_private_key, recipient_address, value):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.value = value

    def to_dict(self):
        '''
        Transaction info
        '''
        response = OrderedDict()
        response['sender_address'] = self.sender_address
        response['recipient_address'] = self.recipient_address
        response['amount'] =  self.value

        return response

    def sign_transaction(self):
        '''
        Sign the Transaction with sender's private key
        '''
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')

app = Flask(__name__)

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    '''
    Generate private and public KeyboardInterrupt
    '''
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
    }
    return jsonify(response), 200

@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    '''
    Create new Transaction
    '''
    values = request.get_json()
    required = ['sender_address', 'sender_private_key', 'recipient_address', 'amount']
    if not all(k in values for k in required):
        return "Missing values", 400
    transaction = Transaction(
        values['sender_address'],
        values['sender_private_key'],
        values['recipient_address'],
        values['amount']
    )
    print(transaction.to_dict())
    response = OrderedDict({'transaction': transaction.to_dict(), 'signature':transaction.sign_transaction()})

    return jsonify(response), 200

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
