document.addEventListener('DOMContentLoaded', function() {
    const chainDiv = document.getElementById('chain');
    const messagesDiv = document.getElementById('messages');

    // Function to fetch and display the blockchain
    function fetchChain() {
        fetch('/chain')
            .then(response => response.json())
            .then(data => {
                chainDiv.innerHTML = '';
    
                data.chain.forEach(block => {
                    const blockDiv = document.createElement('div');
                    blockDiv.className = 'block';
    
                    const blockContent = `
                        <h3>Block ${block.index}</h3>
                        <p><strong>Timestamp:</strong> ${new Date(block.timestamp * 1000).toLocaleString()}</p>
                        <p><strong>Previous Hash:</strong> ${block.previous_hash}</p>
                        <p><strong>Proof:</strong> ${block.proof}</p>
                        <p><strong>Transactions:</strong></p>
                        <ul>
                            ${block.transactions.map(tx => `
                                <li>${tx.sender} ➡️ ${tx.recipient}: ${tx.amount}</li>
                            `).join('')}
                        </ul>
                    `;
    
                    blockDiv.innerHTML = blockContent;
                    chainDiv.appendChild(blockDiv);
                });
            })
            .catch(error => {
                console.error('Error fetching chain:', error);
                messagesDiv.textContent = 'Error fetching blockchain data.';
            });
    }
    

    // Fetch the blockchain on page load
    fetchChain();

    // Handle transaction form submission
    const transactionForm = document.getElementById('transaction-form');
    transactionForm.addEventListener('submit', function(event) {
        event.preventDefault();

        const sender = document.getElementById('sender').value.trim();
        const recipient = document.getElementById('recipient').value.trim();
        const amountValue = document.getElementById('amount').value;
        const amount = parseFloat(amountValue);

        if (!sender || !recipient || isNaN(amount) || amount <= 0) {
            messagesDiv.textContent = 'Please enter valid transaction details.';
            return;
        }

        const transactionData = {
            sender: sender,
            recipient: recipient,
            amount: amount
        };

        fetch('/transactions/new', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(transactionData)
        })
        .then(response => response.json())
        .then(data => {
            messagesDiv.textContent = data.message;
            transactionForm.reset();
        })
        .catch(error => {
            console.error('Error sending transaction:', error);
            messagesDiv.textContent = 'Error sending transaction.';
        });
    });

    // Handle mine block button click
    const mineButton = document.getElementById('mine-block');
    mineButton.addEventListener('click', function() {
        fetch('/mine')
            .then(response => response.json())
            .then(data => {
                messagesDiv.textContent = data.message;
                fetchChain(); // Refresh the blockchain display
            })
            .catch(error => {
                console.error('Error mining block:', error);
                messagesDiv.textContent = 'Error mining block.';
            });
    });
});
