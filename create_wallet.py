import os
from wallet import Wallet


# Read the word list from the file
def read_wordlist(path):
    with open(path, 'r') as file:
        wordlist = file.read().splitlines()
    return wordlist


def create_wallet():
    # Ensure the output directory exists
    os.makedirs('wallet', exist_ok=True)

    # Read the wordlist
    wordlist = read_wordlist('english.txt')

    # Generate the mnemonic (24 words)
    mnemonic = Wallet.generate_mnemonic(wordlist)
    print("Your new wallet (24 words):")
    print(mnemonic)

    # Generate the seed from the mnemonic
    seed = Wallet.create_seed(mnemonic)

    keys = Wallet.create_key_pair(seed)

    address = Wallet.create_address(keys["public"])

    # Write the seed to the output file
    with open('wallet/seed.txt', 'w') as file:
        file.write(seed)

    with open('wallet/passphrase.txt', 'w') as file:
        file.write(mnemonic)

    with open('wallet/address.txt', 'w') as file:
        file.write(address)

    print(f"Seed exported to wallet/seed.txt")
    print(f"Passphrase exported to wallet/passphrase.txt")
    print(f"Address exported to wallet/address.txt")


if __name__ == "__main__":
    create_wallet()
