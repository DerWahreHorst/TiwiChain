import requests
import json

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
    'nodes': ['http://s3y0yvftgi2cph5e.myfritz.net:8317', 'https://b557-2a01-599-619-1f20-4815-e62d-30af-64ad.ngrok-free.app'],
}


# Send the transaction to the server
response = requests.post('http://localhost:8317/transactions/new', json=new_transaction)
response = requests.get('http://localhost:8317/mine')
#response = requests.get('http://localhost:8317/chain')


response = requests.post('http://localhost:8317/nodes/register', json=new_nodes)
data = response.json()
nodes = data['total_nodes']
print(get_public_ip())
print(nodes)

response = requests.get('http://localhost:8317/nodes/resolve')
print(response.json())


# The 'chain' key contains a JSON string, so parse it again
#chain = data['chain']

# Deserialize the JSON string to a Python object
#chain = json.loads(chain_str)

# Replace the string with the parsed list
#data['chain'] = chain

# Pretty-print the entire data
#print(json.dumps(data, indent=4))