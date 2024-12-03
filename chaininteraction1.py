import requests
import json



# Create a new transaction
new_transaction = {
    'sender': 'Malde',
    'recipient': 'Arsch',
    'amount': 4444,
}

# new_nodes = {
#     'nodes': ['http://s3y0yvftgi2cph5e.myfritz.net:8317', get_public_ip()+":8317"],
# }
new_nodes = {
    'nodes': ['http://s3y0yvftgi2cph5e.myfritz.net:8317', 'https://bcbf-80-187-114-41.ngrok-free.app'],
}


# Send the transaction to the server
#response = requests.get('http://localhost:8317/nodes/register_with_network')
#print(response.json())
#response = requests.post('http://localhost:8317/transactions/new', json=new_transaction)
#response = requests.get('http://localhost:8317/mine')
#response = requests.get('http://localhost:8317/chain')
#print(response.json())
#response = requests.get('http://localhost:8317/nodes')
#response = requests.get('http://s3y0yvftgi2cph5e.myfritz.net:8317/nodes')
#response = requests.get('https://bcbf-80-187-114-41.ngrok-free.app/nodes')
response = requests.get('http://localhost:8317/nodes/resolve')
#response = requests.post('http://localhost:8317/nodes/register', json=new_nodes)
#response = requests.get('http://localhost:8317/nodes/synchronize')
print(response.json())


# data = response.json()
# nodes = data['total_nodes']
# print(get_public_ip())
# print(nodes)


# The 'chain' key contains a JSON string, so parse it again
#chain = data['chain']

# Deserialize the JSON string to a Python object
#chain = json.loads(chain_str)

# Replace the string with the parsed list
#data['chain'] = chain

# Pretty-print the entire data
#print(json.dumps(data, indent=4))