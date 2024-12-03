import hashlib
import json
import time
from flask import Flask, request, jsonify, render_template
from uuid import uuid4
import requests
from urllib.parse import urlparse
import threading


def get_public_ip():
    try:
        # Use an external service to get the public IP
        response = requests.get('https://api.ipify.org?format=json')
        if response.status_code == 200:
            ip_info = response.json()
            return ip_info['ip']
        else:
            print("Failed to get public IP address.")
            return None
    except Exception as e:
        print(f"Error obtaining public IP: {e}")
        return None
    

class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set(['s3y0yvftgi2cph5e.myfritz.net:8317'])

        # Create the genesis block
        self.new_block(previous_hash=1, proof=100)

    def new_block(self, proof, previous_hash=None):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        return self.last_block['index'] + 1

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Blockk
        """
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        """
        Returns the last Block in the chain
        """
        return self.chain[-1]

        
    def proof_of_work(self, last_block):
        """
        Bitcoin's SHA-256 mining algorithm:
        - Find a number p' such that hash(pp') contains leading 4 zeroes, where p is the previous p'
        - p is the previous proof, and p' is the new proof

        :param last_block: <dict> last Block
        :return: <int>
        """
        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.
        """
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: <list> A blockchain
        :return: <bool> True if valid, False if not
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], block['previous_hash']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: <bool> True if our chain was replaced, False if not
        """
        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')
            print("Requesting node "+f'http://{node}/chain'+" ... ")
            print(response)

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False
    
    def register_node(self, address):
        """
        Add a new node to the list of nodes.

        :param address: Address of the node. Eg. 'http://192.168.0.5:5000'
        :return: True if the node was added, False if it was already present
        """
        parsed_url = urlparse(address)
        netloc = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        if netloc not in self.nodes:
            self.nodes.add(netloc)
            return True
        return False
            
    def synchronize_nodes(self):
        """
        Synchronize the list of nodes with neighboring nodes.
        """
        new_nodes = set()

        for node in self.nodes:
            try:
                response = requests.get(f'http://{node}/nodes')
                if response.status_code == 200:
                    data = response.json()
                    neighbor_nodes = data.get('nodes', [])
                    new_nodes.update(neighbor_nodes)
            except requests.exceptions.RequestException:
                # Skip nodes that are not reachable
                pass

        # Update the local nodes list with new nodes discovered
        self.nodes.update(new_nodes)
        return True

    def register_with_network(self):
        #node_address = get_public_ip()+":8317"
        node_address = 'https://bcbf-80-187-114-41.ngrok-free.app'

        for node in self.nodes:
            # Register with the seed node
            payload = {
                'nodes': [node_address]
            }
            try:
                response = requests.post(f'http://{node}/nodes/register', json=payload)
                if response.status_code == 201:
                    print("Successfully registered with the seed node.")
                    # Retrieve the list of nodes from the seed node
                    nodes_response = requests.get(f'http://{node}/nodes')
                    if nodes_response.status_code == 200:
                        nodes_data = nodes_response.json()
                        other_nodes = nodes_data.get('nodes', [])
                        # Register with other nodes
                        for node in other_nodes:
                            if node != node_address:
                                try:
                                    url = f'http://{node}/nodes/register'
                                    requests.post(url, json=payload)
                                    print(f"Registered with node {node}")
                                except requests.exceptions.RequestException:
                                    print(f"Could not register with node {node}")
                    else:
                        print("Could not retrieve node list from seed node.")
                else:
                    print(f"Failed to register with the seed node: {response.text}")
            except Exception as e:
                print(f"Error registering with seed node: {e}")

        #register own address
        self.register_node(node_address)







app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()

blockchain_lock = threading.Lock()

def start_consensus_daemon():
    def consensus_worker():
        while True:
            with blockchain_lock:
                try:
                    replaced = blockchain.resolve_conflicts()
                    if replaced:
                        print("Our chain was replaced by a longer chain.")
                    else:
                        print("Our chain is authoritative.")
                except Exception as e:
                    print(f"Error running consensus algorithm: {e}")

                try:
                    blockchain.register_with_network()
                except Exception as e:
                    print(f"Error registering with the network: {e}")

                try:
                    blockchain.synchronize_nodes()
                except Exception as e:
                    print(f"Error synchronizing nodes: {e}")
                # Wait for a specified interval before running again
            time.sleep(10)  # Run every 10 seconds; adjust as needed

    # Start the worker thread
    consensus_thread = threading.Thread(target=consensus_worker)
    consensus_thread.daemon = True  # Daemonize thread to exit when main thread exits
    consensus_thread.start()


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/mine', methods=['GET'])
def mine():
    with blockchain_lock:
        # We run the proof of work algorithm to get the next proof...
        last_block = blockchain.last_block
        proof = blockchain.proof_of_work(last_block)

        # We must receive a reward for finding the proof.
        # The sender is "0" to signify that this node has mined a new coin.
        blockchain.new_transaction(
            sender="0",
            recipient=node_identifier,
            amount=1,
        )

        # Forge the new Block by adding it to the chain
        previous_hash = blockchain.hash(last_block)
        block = blockchain.new_block(proof, previous_hash)

        response = {
            'message': "New Block Forged",
            'index': block['index'],
            'transactions': block['transactions'],
            'proof': block['proof'],
            'previous_hash': block['previous_hash'],
        }
        return jsonify(response), 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/nodes', methods=['GET'])
def get_nodes():
    response = {
        'nodes': list(blockchain.nodes),
    }
    return jsonify(response), 200    

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    new_nodes = []
    for node in nodes:
        if blockchain.register_node(node):
            new_nodes.append(node)

    # Broadcast new nodes to other nodes
    if new_nodes:
        blockchain.broadcast_new_nodes(new_nodes)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/nodes/synchronize', methods=['GET'])
def synchronize():
    blockchain.synchronize_nodes()
    response = {
        'message': 'Node list synchronized',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 200

@app.route('/nodes/register_with_network', methods=['GET'])
def register_with_network():

    blockchain.register_with_network()
    response = {
        'message': 'We are registered',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 200


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200







if __name__ == '__main__':
    # Start the consensus daemon
    start_consensus_daemon()
    # Run the Flask app
    app.run(host='0.0.0.0', port=8317)