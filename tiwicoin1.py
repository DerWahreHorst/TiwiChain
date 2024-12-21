import hashlib
import json
import time
from flask import Flask, request, jsonify, render_template
import uuid
import requests
from urllib.parse import urlparse
import threading
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError, util
import random


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
        self.node_health = {}
        self.node_id = str(uuid.uuid4())
        self.used_transaction_ids = set()  # To track used transaction IDs
        self.fixed_mining_reward = 1
        self.transaction_fee = 0.01

        for n in self.nodes:
            self.node_health[n] = {"failures": 0, "quarantined": False}

        # Create the genesis block
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.current_transactions,
            'proof': 100,
            'previous_hash': 1,
        }
        self.chain.append(block)

    def new_transaction(self, transaction_id, sender_public_key, recipient_public_key, amount, signature):
        if transaction_id in self.used_transaction_ids:
            raise ValueError('Duplicate transaction ID')

        # If it's not a coinbase transaction, verify sender's balance
        if sender_public_key != '0':
            sender_balance = self.get_balance(sender_public_key)
            if sender_balance < amount+self.transaction_fee:
                raise ValueError('Insufficient balance')

        self.used_transaction_ids.add(transaction_id)
        self.current_transactions.append({
            'transaction_id': transaction_id,
            'sender_public_key': sender_public_key,
            'recipient_public_key': recipient_public_key,
            'amount': amount,
            'signature': signature
        })
        return self.last_block['index'] + 1
    
    def get_balance(self, public_key):
        balance = 0
        for block in self.chain:
            for tx in block['transactions']:
                if tx['sender_public_key'] == public_key:
                    balance -= tx['amount']+self.transaction_fee
                if tx['recipient_public_key'] == public_key:
                    balance += tx['amount']
        return balance
    
    def get_balance_for_chain_untill_index(self, public_key, chain, index):
        balance = 0
        current_index = 1
        while current_index < index:
            block = chain[current_index]
            for tx in block['transactions']:
                if tx['sender_public_key'] == public_key:
                    balance -= tx['amount']+self.transaction_fee
                if tx['recipient_public_key'] == public_key:
                    balance += tx['amount']
            current_index += 1
        return balance
    
    def get_all_addresses(self):
        """
        Retrieve all unique public keys (addresses) encountered in the chain.
        """
        addresses = set()
        for block in self.chain:
            for tx in block['transactions']:
                if tx['sender_public_key'] != '0':  # '0' often represents a coinbase tx
                    addresses.add(tx['sender_public_key'])
                addresses.add(tx['recipient_public_key'])
        return list(addresses)

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

        
    def proof_of_work(self, miner_public_key):
        """
        Bitcoin's SHA-256 mining algorithm:
        - Find a number p' such that hash(pp') contains leading 4 zeroes, where p is the previous p'
        - p is the previous proof, and p' is the new proof

        :param last_block: <dict> last Block
        :return: <int>
        """
        temp_transactions = self.current_transactions[:]
        
        # Create a unique transaction ID for the reward
        reward_transaction_id = str(uuid.uuid4())
        reward = self.mining_reward(len(temp_transactions))
        # Create a reward transaction to the miner
        temp_transactions.append({
            'transaction_id': reward_transaction_id,
            'sender_public_key': '0',  # '0' signifies a new coin
            'recipient_public_key': miner_public_key,
            'amount': reward,
            'signature': ''  # No signature needed for mining reward
        })

        proof = random.randint(0, 10**12)
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': temp_transactions,
            'proof': proof,
            'previous_hash': self.hash(self.chain[-1]),
        }
        while not self.valid_proof(block):
            proof += 1
            block['proof'] = proof

        return block
    

    def mining_reward(self, number_of_transactions): 
        return self.fixed_mining_reward/(2**(len(self.chain)//500000)) + self.transaction_fee*number_of_transactions
    

    def valid_proof(self, block):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.
        """
        guess_hash =  self.hash(block)
        return guess_hash[:6] == "000000"

    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: <list> A blockchain
        :return: <bool> True if valid, False if not
        """
        last_block = chain[0]
        current_index = 1
        seen_transaction_ids = set()

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")

            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                print("invalid hash")
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(block):
                print("invalid proof")
                return False

            # Check for duplicate transaction IDs and validate transactions
            coinbase_transactions = [tx for tx in block['transactions'] if tx['sender_public_key'] == '0']
            if len(coinbase_transactions) != 1:
                print("Invalid number of coinbase transactions.")
                return False

            coinbase_tx = coinbase_transactions[0]
            expected_reward = self.mining_reward(len(block['transactions'])-1)
            if coinbase_tx['amount'] != expected_reward:
                print("Invalid coinbase transaction amount.")
                return False

            # Ensure coinbase transaction ID is unique
            if coinbase_tx['transaction_id'] in seen_transaction_ids:
                print("Duplicate coinbase transaction ID.")
                return False
            seen_transaction_ids.add(coinbase_tx['transaction_id'])

            # Check for duplicate transaction IDs
            for tx in block['transactions']:
                # Skip signature verification for coinbase transactions
                if tx['sender_public_key'] == '0':
                    continue

                tx_id = tx['transaction_id']

                if tx_id in seen_transaction_ids:
                    print("Duplicate transaction ID found")
                    return False  # Duplicate transaction ID found
                seen_transaction_ids.add(tx_id)

                if not self.verify_transaction(tx):
                    print(f"Invalid transaction: {tx_id}")
                    return False
                
                if self.get_balance_for_chain_untill_index(tx['sender_public_key'], chain, current_index) < 0:
                    print("negative balance occured")
                    return False

            last_block = block
            current_index += 1
        print("chain valid!!!")
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
            # Skip if quarantined
            if self.node_health[node]["quarantined"]:
                continue

            try:
                response = requests.get(f'http://{node}/chain', timeout=15)
                print(f"Requesting node http://{node}/chain ...")
                print(response)

                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']

                    # Check if the length is longer and the chain is valid
                    if length > max_length and self.valid_chain(chain):
                        max_length = length
                        new_chain = chain
                else:
                    # Count as a failure
                    self.handle_node_failure(node)
            except requests.exceptions.RequestException as e:
                # This node can't be reached
                print(f"Could not reach node {node}: {e}")
                self.handle_node_failure(node)
                # Decide if you want to remove the node or just skip it
                # e.g., self.nodes.remove(node)
                continue

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            self.current_transactions = []
            return True

        return False
    
    def handle_node_failure(self, node):
        self.node_health[node]["failures"] += 1
        if self.node_health[node]["failures"] > 3:
            # Move node to quarantine set or remove it from active nodes
            self.node_health[node]["quarantined"] = True
            # Optionally remove from self.nodes if desired
            self.nodes.remove(node)

    def is_local_node(self, address):
        # Attempt to fetch the node_id from the given address
        try:
            response = requests.get(f"{address}/node_id", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('node_id') == self.node_id:
                    return True
        except requests.exceptions.RequestException:
            pass
        return False

    def register_node(self, address):
        """
        Add a new node to the list of nodes.

        :param address: Address of the node. Eg. 'http://192.168.0.5:5000'
        :return: True if the node was added, False if it was already present
        """
        # Before adding the node, check if it's the local node
        #if self.is_local_node(address):
        #    print("Skipping: The given address leads to the current node itself.")
        #    return False
        parsed_url = urlparse(address)
        netloc = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        if netloc not in self.nodes:
            self.nodes.add(netloc)
            self.node_health[netloc] = {"failures": 0, "quarantined": False}
            return True
        return False
            
    def synchronize_nodes(self):
        """
        Synchronize the list of nodes with neighboring nodes.
        """
        new_nodes = set()
        print("self.nodes = ", self.nodes)
        for node in self.nodes:
            print("node = ", node)
            if self.node_health[node]["quarantined"]:
                print("quarantined")
                continue
            try:
                response = requests.get(f'http://{node}/nodes', timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    neighbor_nodes = data.get('nodes', [])
                    for n in neighbor_nodes:
                        print("n = ",n)
                        if n not in self.node_health:
                            self.node_health[n] = {"failures": 0, "quarantined": False}
                        # If quarantined, try again
                        if self.node_health[n]["quarantined"]:
                            # Try contacting n again
                            if self.attempt_recovery_from_quarantine(n):
                                # If successful, remove quarantine
                                self.node_health[n]["quarantined"] = False
                                self.node_health[n]["failures"] = 0

                        # If node is not quarantined or successfully recovered
                        if not self.node_health[n]["quarantined"]:
                            new_nodes.add(n)
                else:
                    print(f"Could not retrieve nodes from {node}. Status Code: {response.status_code}")
            except requests.exceptions.RequestException:
                print("FEHLER1")
                self.handle_node_failure(node)
                continue

        # Update the local nodes list with new nodes discovered
        self.nodes.update(new_nodes)
        return True
    
    def attempt_recovery_from_quarantine(self, node):
        """
        Attempt to contact a quarantined node to see if it's now reachable.
        Returns True if reachable and should be restored, False otherwise.
        """
        try:
            response = requests.get(f'http://{node}/chain', timeout=15)
            if response.status_code == 200:
                print(f"Quarantined node {node} is now reachable. Removing quarantine.")
                return True
            else:
                print(f"Quarantined node {node} responded with status code {response.status_code}, remaining quarantined.")
        except requests.exceptions.RequestException:
            print(f"Quarantined node {node} still unreachable.")
        return False

    def register_with_network(self):
        node_address = "http://"+get_public_ip()+":8317"
        #node_address = 'https://77ce-2003-c1-8702-b100-a156-f967-b675-156.ngrok-free.app'
        
        if len(node_address)>7:
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
                                        requests.post(url, json=payload, timeout=15)
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


    def synchronize_transactions(self):
        """
        Synchronize current_transactions with all nodes in the network.
        Fetches pending transactions from each node and merges them locally,
        ensuring no duplicates based on transaction_id.
        """
        for node in self.nodes:
            node_url = f'http://{node}/transactions/pending'
            try:
                response = requests.get(node_url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    node_transactions = data.get('pending_transactions', [])
                    for tx in node_transactions:
                        tx_id = tx.get('transaction_id')
                        if tx_id and tx_id not in self.used_transaction_ids:
                            # Verify the transaction before adding
                            if self.verify_transaction(tx):
                                self.current_transactions.append(tx)
                                self.used_transaction_ids.add(tx_id)
                else:
                    print(f"Failed to fetch transactions from {node}. Status Code: {response.status_code}")
                    self.handle_node_failure(node)
            except requests.exceptions.RequestException as e:
                print(f"Error fetching transactions from {node}: {e}")
                self.handle_node_failure(node)

    def verify_transaction(self, transaction):
        """
        Verify the integrity and validity of a transaction.
        This includes signature verification and any other necessary checks.
        
        :param transaction: <dict> The transaction data.
        :return: <bool> True if valid, False otherwise.
        """
        required_fields = ['transaction_id', 'sender_public_key', 'recipient_public_key', 'amount', 'signature']
        if not all(field in transaction for field in required_fields):
            print("Transaction is missing required fields.")
            return False

        transaction_id = transaction['transaction_id']
        sender_public_key = transaction['sender_public_key']
        recipient_public_key = transaction['recipient_public_key']
        amount = transaction['amount']
        signature = transaction['signature']

        # Reconstruct transaction data for verification
        tx_data = {
            'transaction_id': transaction_id,
            'sender_public_key': sender_public_key,
            'recipient_public_key': recipient_public_key,
            'amount': amount
        }
        tx_data_string = json.dumps(tx_data, separators=(',', ':'))

        # Verify the signature
        try:
            vk = VerifyingKey.from_string(bytes.fromhex(sender_public_key), curve=SECP256k1)
            is_valid = vk.verify(
                bytes.fromhex(signature),
                tx_data_string.encode('utf-8'),
                hashfunc=hashlib.sha256,
                sigdecode=util.sigdecode_der
            )
        except (BadSignatureError, ValueError, Exception) as e:
            print(f"Signature verification failed for transaction {transaction_id}: {e}")
            is_valid = False

        if not is_valid:
            print(f"Invalid signature for transaction {transaction_id}.")
            return False

        # Additional validation checks can be added here (e.g., sufficient balance)

        return True







app= Flask(__name__)

# Instantiate the Blockchain
blockchain = Blockchain()

blockchain_lock = threading.Lock()


def consensus_worker():
    while True:
        time.sleep(10)  # Run every 10 seconds; adjust as needed
        with blockchain_lock:
            try:
                replaced = blockchain.resolve_conflicts()
                if replaced:
                    print("Our chain was replaced by a longer chain.")
                else:
                    print("Our chain is authoritative.")
            except Exception as e:
                print(f"Error running consensus algorithm: {e}")

def node_registration_worker():
    """
    Registers the node with the network once at startup.
    """
    print("node_registration_worker !!!")
    with blockchain_lock:
        try:
            print("Registering with network...")
            blockchain.register_with_network()
            print("Node registration complete.")
        except Exception as e:
            print(f"Error registering with network: {e}")

def node_sync_worker():
    """
    Periodically synchronizes the node list.
    """
    while True:
        print("node_sync_worker !!!")
        time.sleep(30)  # Adjust the interval as needed
        with blockchain_lock:
            try:
                print("Synchronizing node list...")
                blockchain.synchronize_nodes()
                print("Node synchronization complete.")
            except Exception as e:
                print(f"Error synchronizing nodes: {e}")

def transactions_sync_worker():
    """
    Periodically synchronize pending transactions across all nodes.
    """
    while True:
        with blockchain_lock:
            try:
                print("Synchronizing pending transactions...")
                blockchain.synchronize_transactions()
                print("Transaction synchronization complete.")
            except Exception as e:
                print(f"Error during transaction synchronization: {e}")
        time.sleep(30)  # Adjust the interval as needed (e.g., every 30 seconds)


def start_background_tasks():
     # Start node registration thread
    node_registration_thread = threading.Thread(target=node_registration_worker)
    node_registration_thread.daemon = True
    node_registration_thread.start()

    # Start node synchronization thread
    node_sync_thread = threading.Thread(target=node_sync_worker)
    node_sync_thread.daemon = True
    node_sync_thread.start()

    # Start chain synchronization thread
    consensus_thread = threading.Thread(target=consensus_worker)
    consensus_thread.daemon = True  # Daemonize thread to exit when main thread exits
    consensus_thread.start()

    # Start transactions synchronization thread
    transactions_sync_thread = threading.Thread(target=transactions_sync_worker)
    transactions_sync_thread.daemon = True
    transactions_sync_thread.start()


@app.route('/')
def index():
    #print("request.remote_addr = ",request.remote_addr)
    # Check the requester IP address
    if request.remote_addr != '127.0.0.1':
        abort(403)  # Forbidden if not localhost
    return render_template('index.html')

@app.route('/node_id', methods=['GET'])
def get_node_id():
    return jsonify({'node_id': blockchain.node_id}), 200

@app.route('/mine', methods=['POST'])
def mine():
    if request.remote_addr != '127.0.0.1':
        abort(403)  # Forbidden if not localhost
    values = request.get_json()

    required = ['miner_public_key']
    if not all(k in values for k in required):
        return 'Missing values', 400

    miner_public_key = values['miner_public_key']

    with blockchain_lock:
        # Run proof of work algorithm
        block = blockchain.proof_of_work(miner_public_key)
        blockchain.chain.append(block)        # Reset the current list of transactions
        blockchain.current_transactions = []

    response = {
        'message': "New Block Forged",
        'block': block,
    }
    print("response = ", response)
    print("new block = ",block)
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    if request.remote_addr != '127.0.0.1':
        abort(403)  # Forbidden if not localhost
    values = request.get_json()

    required = ['transaction_id', 'sender_public_key', 'recipient_public_key', 'amount', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400

    transaction_id = values['transaction_id']
    sender_public_key = values['sender_public_key']
    recipient_public_key = values['recipient_public_key']
    amount = values['amount']
    signature = values['signature']

    # Reconstruct transaction data for verification
    tx_data = {
        'transaction_id': transaction_id,
        'sender_public_key': sender_public_key,
        'recipient_public_key': recipient_public_key,
        'amount': amount
    }
    tx_data_string = json.dumps(tx_data, separators=(',', ':'))

    # Verify the signature
    try:
        vk = VerifyingKey.from_string(bytes.fromhex(sender_public_key), curve=SECP256k1)
        is_valid = vk.verify(
            bytes.fromhex(signature),
            tx_data_string.encode('utf-8'),
            hashfunc=hashlib.sha256,
            sigdecode=util.sigdecode_der
        )
    except (BadSignatureError, ValueError, Exception) as e:
        is_valid = False

    if not is_valid:
        return jsonify({'message': 'Invalid signature'}), 400

    # Attempt to create a new transaction
    try:
        with blockchain_lock:
            index = blockchain.new_transaction(
                transaction_id,
                sender_public_key,
                recipient_public_key,
                amount,
                signature
            )
    except ValueError as ve:
        return jsonify({'message': str(ve)}), 400
    except Exception as e:
        return jsonify({'message': 'An error occurred while adding the transaction.'}), 500

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
    #if new_nodes:
    #    blockchain.broadcast_new_nodes(new_nodes)

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
    if request.remote_addr != '127.0.0.1':
        abort(403)  # Forbidden if not localhost
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

@app.route('/balances', methods=['GET'])
def get_balances():
    addresses = blockchain.get_all_addresses()
    result = []
    for addr in addresses:
        bal = blockchain.get_balance(addr)
        result.append({
            'public_key': addr,
            'balance': bal
        })
    return jsonify(result), 200

@app.route('/transactions/pending', methods=['GET'])
def get_pending_transactions():
    response = {
        'pending_transactions': blockchain.current_transactions
    }
    return jsonify(response), 200






if __name__ == '__main__':
    # Start the consensus daemon
    start_background_tasks()
    # Run the Flask app
    app.run(host='0.0.0.0', port=8317)