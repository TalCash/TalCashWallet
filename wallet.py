import random
import hashlib
import binascii
from gmpy2 import gmpy2
import nacl.signing
from nacl.exceptions import BadSignatureError


class TransactionSenderData:
    def __init__(self, address, amount, fee, signature=None, key=None):
        self.address = address
        self.amount = self.round_num(amount, 8)
        self.fee = self.round_num(fee, 8)
        self.signature = signature
        self.key = key

    @staticmethod
    def round_num(number, digits):
        result = round(number, digits)
        if result == int(result):
            return int(result)
        return result

    def to_dict(self):
        return {
            "address": self.address,
            "amount": self.amount,
            "fee": self.fee,
            "signature": self.signature,
            "key": self.key
        }


class TransactionReceiverData:
    def __init__(self, address, amount):
        self.address = address
        self.amount = self.round_num(amount, 8)

    @staticmethod
    def round_num(number, digits):
        result = round(number, digits)
        if result == int(result):
            return int(result)
        return result

    def to_dict(self):
        return {
            "address": self.address,
            "amount": self.amount
        }


class Wallet:
    ADDRESS_PREFIX = "tc"

    @staticmethod
    def hex_to_binary(hex_str):
        return binascii.unhexlify(hex_str)

    @staticmethod
    def base58_encode(data: bytes) -> str:
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        base_count = len(alphabet)
        encoded = ''
        hex_string = binascii.hexlify(data).decode('utf-8')
        dec = gmpy2.mpz(hex_string, 16)

        while dec > 0:
            dec, mod = gmpy2.f_divmod(dec, base_count)
            encoded = alphabet[int(mod)] + encoded

        return encoded

    @staticmethod
    def base58check_encode(payload: bytes) -> str:
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return Wallet.base58_encode(payload + checksum)

    @staticmethod
    def base58_decode(input_str: str) -> bytes:
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        base_count = len(alphabet)
        decoded = gmpy2.mpz(0)
        multi = gmpy2.mpz(1)

        for char in reversed(input_str):
            decoded += gmpy2.mpz(alphabet.index(char)) * multi
            multi *= base_count

        hex_string = gmpy2.digits(decoded, 16)
        if len(hex_string) % 2 != 0:
            hex_string = '0' + hex_string

        return binascii.unhexlify(hex_string)

    @staticmethod
    def public_key_to_address(public_key: str, version: int = 0) -> str:
        version_byte = bytes([version])
        hash1 = hashlib.sha256(public_key.encode('utf-8')).digest()
        ripemd = Wallet.ripemd160(hash1)

        versioned_payload = version_byte + ripemd
        checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
        return Wallet.base58check_encode(versioned_payload + checksum)

    @staticmethod
    def ripemd160(data: bytes) -> bytes:
        h = hashlib.new('ripemd160')
        h.update(data)
        return h.digest()

    @staticmethod
    def keys(data: str) -> dict:
        # Hash the data using SHA-256
        data_hash = hashlib.sha256(data.encode()).digest()

        # Generate key pair from the hashed data
        signing_key = nacl.signing.SigningKey(data_hash)

        # Extract the private and public keys
        secret_key = signing_key.encode()
        public_key = signing_key.verify_key.encode()

        return {
            "private": binascii.hexlify(secret_key).decode(),
            "public": binascii.hexlify(public_key).decode()
        }

    @staticmethod
    def create_key_pair(seed, index=0):
        return Wallet.keys(seed + str(index))

        #seed_bytes = Wallet.hex_to_binary(seed)
        #private_key = hashlib.sha256(seed_bytes + str(index).encode('utf-8')).digest()
        #signing_key = SigningKey(private_key)
        #return {"private": signing_key.encode(HexEncoder).decode('utf-8'), "public": signing_key.verify_key.encode(HexEncoder).decode('utf-8')}

    @staticmethod
    def create_address(public_key, version=1):
        return Wallet.ADDRESS_PREFIX + Wallet.public_key_to_address(public_key, version)

    @staticmethod
    def verify_address(address: str) -> bool:
        decoded = Wallet.base58_decode(address)
        version = decoded[:1]
        payload = decoded[1:-4]
        checksum = decoded[-4:]
        recomputed_checksum = hashlib.sha256(hashlib.sha256(version + payload).digest()).digest()[:4]
        return checksum == recomputed_checksum

    @staticmethod
    def generate_words(wordlist):
        entropy = random.getrandbits(256).to_bytes(32, byteorder='big')
        entropy_bits = Wallet.bytes_to_binary_string(entropy)
        checksum_bits = Wallet.bytes_to_binary_string(hashlib.sha256(entropy).digest())[:8]
        total_bits = entropy_bits + checksum_bits

        chunks = [total_bits[i:i + 11] for i in range(0, len(total_bits), 11)]
        words = [wordlist[int(chunk, 2) % 2048] for chunk in chunks]

        return words

    @staticmethod
    def bytes_to_binary_string(bytes_data):
        return ''.join(format(byte, '08b') for byte in bytes_data)

    @staticmethod
    def validate_passphrase(mnemonic, wordlist):
        bits = ''.join(format(wordlist.index(word), '011b') for word in mnemonic.split())
        entropy_bits = bits[:-8]
        checksum_bits = bits[-8:]

        entropy = int(entropy_bits, 2).to_bytes(len(entropy_bits) // 8, byteorder='big')
        computed_checksum_bits = Wallet.bytes_to_binary_string(hashlib.sha256(entropy).digest())[:8]

        return checksum_bits == computed_checksum_bits

    @staticmethod
    def generate_mnemonic(wordlist):
        return ' '.join(Wallet.generate_words(wordlist))

    @staticmethod
    def verify_owned_address(public_key, address):
        return any(Wallet.create_address(public_key, version) == address for version in range(256))

    @staticmethod
    def validate_address(address):
        if address.startswith(Wallet.ADDRESS_PREFIX):
            address = address[len(Wallet.ADDRESS_PREFIX):]
        return Wallet.verify_address(address)

    @staticmethod
    def get_address(public_key):
        return Wallet.ADDRESS_PREFIX + Wallet.public_key_to_address(public_key)

    @staticmethod
    def create_seed(seed_phrase):
        seed = hashlib.pbkdf2_hmac('sha512', seed_phrase.encode(), b'mnemonic', 2048, 64)
        s = seed.hex()
        return s[:64]

    @staticmethod
    def create_message(time, sender, receivers):
        receivers_hash = "".join(receiver.address for receiver in receivers)
        return f"{time}{sender.amount}{sender.address}{receivers_hash}"

    @staticmethod
    def sign_message(private_key: str, message: str) -> str:
        binary_private_key = binascii.unhexlify(private_key)
        signing_key = nacl.signing.SigningKey(binary_private_key)
        signature = signing_key.sign(message.encode('utf-8')).signature

        return binascii.hexlify(signature).decode('utf-8')

    @staticmethod
    def verify_signature(signature, message, public_key):
        verify_key = nacl.signing.VerifyKey(binascii.unhexlify(public_key))
        try:
            verify_key.verify(message.encode(), binascii.unhexlify(signature))
            return True
        except BadSignatureError:
            return False

    @staticmethod
    def calculate_fees(amount):
        return round(min(0.01 * amount, 0.01), 8)

    @staticmethod
    def create_transaction_id(senders, receivers, date):
        senders_hash = ""
        receivers_hash = ""
        amount = 0

        for sender in senders:
            amount += sender.amount
            senders_hash += sender.address

        for receiver in receivers:
            receivers_hash += receiver.address

        transaction_string = senders_hash + receivers_hash + str(amount) + date
        return Wallet.hash(transaction_string)

    @staticmethod
    def hash(data):
        return hashlib.sha256(data.encode()).hexdigest()
