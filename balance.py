import os
import json
import asyncio
from websocket import WebSocketClient


# Read the address from the file
def read_address(path):
    if not os.path.exists(path):
        return None
    with open(path, 'r') as file:
        address = file.read().strip().replace("Address: ", "")
    return address


async def check_balance():
    # Read the address from wallet/address.txt
    address = read_address('wallet/address.txt')
    if address is None:
        print("Address hasn't been generated yet, please run python3 create_address.py to create address first")
        return

    # Connect to WebSocket
    client = WebSocketClient('ws://crypto.talcash.com:8880')
    await client.connect()

    # Send balance request
    message = {
        "name": "get",
        "data": {
            "type": "balance",
            "params": {
                "address": address
            }
        }
    }
    await client.send(message)

    async def on_message(data):
        if data["name"] == "response" and not data["data"]["success"]:
            print("Failed to get balance.")
        elif data["name"] == "balance":
            address = data["data"]["address"]
            balance = data["data"]["balance"]
            pending = data["data"]["pending"]
            print(f"Balance for address {address}:")
            print(f"Current balance: {balance}")
            print(f"Pending balance: {pending}")
        await client.close()

    await client.listen(on_message)

if __name__ == "__main__":
    asyncio.run(check_balance())
