# TalCash Python Wallet

This Python wallet allows you to create a wallet, check the balance, and send funds to another address.

## Prerequisites

1. **Download Python 3**:
   - **Windows**: [Download Python 3](https://www.python.org/downloads/windows/)
   - **Linux**: Install Python 3 using the command:
     ```sh
     sudo apt-get update
     sudo apt-get install python3
     ```

2. **Install pip**:
   - **Windows**: Pip is included with Python 3.4 and later.
   - **Ubuntu**: Install pip using the command:
     ```sh
     sudo apt-get install python3-pip
     ```
   - **Other Platforms**: Follow instructions from the [pip installation guide](https://pip.pypa.io/en/stable/installation/).

3. **Install Required Packages**:
   - Navigate to the project directory and run:
     ```sh
     pip install -r requirements.txt
     ```

## How to Use

### 1. Create a Wallet

Create a new wallet by running the following command:
```sh
python3 create_wallet.py
```
The wallet credentials will be shown and saved in the wallet directory.
*Note: Do not share your passphrase / seed to anyone, if anyone get this information they can steal your funds!*

### 2. Check Balance

Check the balance of your wallet by running:
```sh
python3 balance.py
```
*Note: Make sure you have created a wallet first.*

### 3. Send Funds
Send funds from your wallet to another address by running:
```sh
python3 create_payment.py -address {address} -amount {amount} -fee {fee}
```
Replace {address}, {amount}, and {fee} with the recipient address, the amount to send, and the transaction fee, respectively.
Note: make sure the fee is atleast 1% of the payment or 0.1 (the lowest).

### Directory Sturcutre
```sh
.
├── create_wallet.py
├── balance.py
├── create_payment.py
├── requirements.txt
├── ...
└── wallet
    ├── passphrase.txt
    ├── seed.txt
    └── address.txt
```

