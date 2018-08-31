from collections import OrderedDict

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request, render_template

class Blockchain:

    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes = set()
        self.node_id = str(uuid4()).replace('-', '')
        self.create_block(1, '7')

    def register_node(self, node_url):
        '''
        Add a new node to list of nodes
        '''
        parsed_url = urlparse(node_url)
        self.nodes.add(parsed_url.netloc)

    def create_block(self, nonce, prev_hash):
        '''
        Mine a new block into Blockchain
        :return:<dict> return new block
        '''
        block = {
            'block_number': len(self.chain)+1,
            'timestamp': time(),
            'transactions': self.transactions,
            'nonce': nonce,
            'prev_hash': prev_hash
        }
        self.transactions = []

        self.chain.append(block)
        return block

    def hash(self, block):
        '''
        Hash the Blockchain
        :return:<str> return hash of block of 64 length
        '''
        block_string = json.dumps(block, sort_keys=True).encode()

        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self):
        '''
        POW algo
        '''
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)

        nonce = 0
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1
        return nonce

    def valid_proof(self, transactions, prev_hash, nonce):
        '''
        whether hash value satisfy the mining condition
        '''
        guess_hash = hashlib.sha256((str(transactions) + str(prev_hash) + str(nonce)).encode()).hexdigest()
        return guess_hash[:4] == '0000'

    def valid_chain(self, chain):
        '''
        check whether blockchain is valid or not
        '''
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):

            block = chain[current_index]
            if block['prev_hash'] != self.hash(last_block):
                return False

            transactions = block['transactions'][:-1]
            transaction_info = ['sender_address', 'recipient_address', 'amount']

            transactions = [OrderedDict((k, transaction[k]) for k in transaction_info) for transaction in transactions]

            if not self.valid_proof(transactions, block['prev_hash'], block['nonce']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        '''
        Resolve_conflicts by replacing node's chain with the longest one
        '''
        neighbours = self.nodes
        new_chain = None

        max_length = len(self.chain)

        for node in neighbours:
            response = requests.get('http://' + node + '/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = new_chain
            return True

        return False

    def verify_transaction_signature(self, sender_address, signature, transaction):
        '''
        check whether the transaction is signed by the sender
        '''
        public_key = RSA.importKey(binascii.unhexlify(sender_address))
        public_key = RSA.importKey(binascii.unhexlify(sender_address))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction).encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(signature))


    def append_transaction(self, sender_address, recipient_address, amount, signature):
        '''
        add transaction to transaction list if verified
        '''
        transaction = OrderedDict()
        transaction['sender_address'] = sender_address
        transaction['recipient_address'] = recipient_address
        transaction['amount'] =  amount

        if sender_address == '0':
            self.transactions.append(transaction)
            return len(self.chain)+1
        else:
            transaction_verification = self.verify_transaction_signature(sender_address, signature, transaction)
            if transaction_verification:
                self.transactions.append(transaction)
                return len(self.chain)+1
            else:
                return False

app = Flask(__name__)

blockchain = Blockchain()

@app.route('/transaction/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    required = ['sender_address', 'recipient_address', 'amount', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400

    transaction_result = blockchain.append_transaction(values['sender_address'], values['recipient_address'], values['amount'], values['signature'])

    if transaction_result == False:
        response = {'message': 'Invalid Transaction'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction added to block' + str(transaction_result)}
        return jsonify(response), 201

@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    transactions = blockchain.transactions
    response = {
        'transactions': transactions
    }
    return jsonify(transactions), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200

@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.chain[-1]
    nonce = blockchain.proof_of_work()

    blockchain.append_transaction(sender_address='0', recipient_address=blockchain.node_id, amount=25, signature=None)

    prev_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, prev_hash)

    response = {
        'message': 'New Block forged',
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'prev_hash': block['prev_hash'],
    }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    '''
    :resquest:
        {
            'nodes':[http://127.0.0.1:5000,]
        }
    '''
    values = request.get_json()
    nodes = values.get('nodes')

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node for node in blockchain.nodes]
    }
    return jsonify(response), 201

@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = blockchain.nodes
    response = {
        'nodes': list(nodes)
    }
    return jsonify(response), 200

@app.route('/nodes/resolve', methods=['GET'])
def consesus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Chain is replaced',
            'new chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
