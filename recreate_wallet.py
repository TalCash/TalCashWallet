import os
from wallet import Wallet


# Read the word list from the file
def read_mnemonic(path):
    if not os.path.exists(path):
        return None
    with open(path, 'r') as file:
        mnemonic = file.read()
    return mnemonic


def create_wallet():
    # Read the wordlist
    mnemonic = read_mnemonic('wallet/passphrase.txt')

    if mnemonic is None:
        print("Please create a text file in wallet/passphrase.txt and input there your 24 words seperated by space")
        return

    # Generate the seed from the mnemonic
    seed = Wallet.create_seed(mnemonic)
    keys = Wallet.create_key_pair(seed)
    address = Wallet.create_address(keys["public"])

    # Write the seed to the output file
    with open('wallet/seed.txt', 'w') as file:
        file.write(seed)

    with open('wallet/address.txt', 'w') as file:
        file.write(address)

    print(f"Seed exported to wallet/seed.txt")
    print(f"Address exported to wallet/address.txt")


if __name__ == "__main__":
    create_wallet()
