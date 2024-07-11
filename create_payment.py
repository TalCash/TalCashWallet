import argparse
import os
import json
import asyncio
from datetime import datetime, timezone
from websocket import WebSocketClient
from wallet import Wallet, TransactionSenderData, TransactionReceiverData


# Read the seed from the file
def read_seed(path):
    if not os.path.exists(path):
        return None
    with open(path, 'r') as file:
        seed = file.read().strip()
    return seed


# Read the address from the file
def read_address(path):
    if not os.path.exists(path):
        return None
    with open(path, 'r') as file:
        address = file.read().strip()
    return address


async def create_payment(address, amount, fee):
    # Check if all parameters are provided
    if not address or not amount or not fee:
        print("You haven't provided the proper variables.")
        print("Please provide -address {address} and replace {address} with the address you'd like to send funds to.")
        print("Please provide -amount {amount} and replace {amount} with the amount of funds you'd like to send.")
        print("Please provide -fee {fee} and replace {fee} with the amount of fee you'd like to pay for the "
              "transaction (recommended 1% or 0.01).")
        return

    # Read the seed from wallet/seed.txt
    seed = read_seed('wallet/seed.txt')
    if seed is None:
        print("Wallet hasn't been created yet, please run python3 create_wallet.py to create wallet first")
        return

    # Create key pair
    pair = Wallet.create_key_pair(seed)
    private_key = pair["private"]
    public_key = pair["public"]

    # Get sender address
    sender_address = read_address('wallet/address.txt')
    if sender_address is None:
        print("Wallet hasn't been created yet, please run python3 create_wallet.py to create wallet first")
        return

    # Create the transaction
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    sender_data = TransactionSenderData(sender_address, amount, fee)
    receiver_data = TransactionReceiverData(address, amount - fee)

    sig_msg = Wallet.create_message(timestamp, sender_data, [receiver_data])
    signature = Wallet.sign_message(private_key, sig_msg)

    sender_data.key = public_key
    sender_data.signature = signature
    txid = Wallet.create_transaction_id([sender_data], [receiver_data], timestamp)

    transaction_data = {
        "txid": txid,
        "timestamp": timestamp,
        "senders": [sender_data.to_dict()],
        "receivers": [receiver_data.to_dict()],
        "fee": float(fee),
        "message": "{python transaction}"
    }

    # Connect to WebSocket
    client = WebSocketClient('ws://crypto.talcash.com:8880')
    if not await client.connect():
        return

    # Send transaction request
    await client.send({
        "name": "transaction",
        "data": transaction_data
    })

    async def on_message(data):
        if data["name"] == "response" and not data["data"]["success"]:
            print("Failed to send transaction.")
        elif data["name"] == "transaction":
            print("Transaction sent successfully.")
        await client.close()

    await client.listen(on_message)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process transaction data.")
    parser.add_argument("-address", required=True, help="Address to send funds to")
    parser.add_argument("-amount", required=True, type=float, help="Amount of funds to send")
    parser.add_argument("-fee", required=True, type=float, help="Fee for the transaction (recommended 1% or 0.01)")

    args = parser.parse_args()
    asyncio.run(create_payment(args.address, args.amount, args.fee))
