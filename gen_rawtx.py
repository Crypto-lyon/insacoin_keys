# coding: utf-8
import sys
sys.path.append('.')
from gen_keypair import *
import opcodes
import binascii
import ecdsa
import requests
import time
import socket
import random


def serialize(prev_hash, index, in_script, value, out_script):
    """
    Creates a serialized transaction from given values.

    :param prev_hash: the hash of the previous transaction from which we take the input. (int or bytes)
    :param index: the place of the output in the 'output list'. (int or bytes)
    :param in_script: the input script (unlocking prev tx locking script), as bytes.
    :param value: the amount in satoshis to spend from the output. (int or bytes)
    :param out_script: the output script (locking coins spent)

    :return: an hex-encoded serialized tx.
    """
    # We then check every parameters in order to avoid errors when submitting the tx to the network
    if isinstance(prev_hash, int):
        prev_hash = prev_hash.to_bytes(sizeof(prev_hash), 'big')
    elif not isinstance(prev_hash, bytes):
        raise Exception('prev_hash must be specified as int or bytes, not {}'.format(type(prev_hash)))
    if isinstance(index, int):
        index = index.to_bytes(4, 'little',)
    elif not isinstance(index, bytes):
        raise Exception('index must be specified as int or bytes, not {}'.format(type(index)))
    if not isinstance(in_script, bytes):
        raise Exception('in_script must be specified as bytes')
    if isinstance(value, int):
        value = value.to_bytes(8, 'little')
    elif not isinstance(value, bytes):
        raise Exception('value must be specified as int or bytes, not {}'.format(type(value)))
    if not isinstance(out_script, bytes):
        raise Exception('out_script must be specified as bytes')

    # check out the transaction structure at the head of this file for explanations
    tx = b'\x01\x00\x00\x00' # version
    tx += b'\x01' # input count
    tx += prev_hash[::-1]
    tx += index
    script_length = len(in_script)
    tx += script_length.to_bytes(sizeof(script_length), 'big')
    tx += in_script
    tx += b'\xff\xff\xff\xff' # sequence
    tx += b'\x01' # output count
    tx += value
    script_length = len(out_script)
    tx += script_length.to_bytes(sizeof(script_length), 'big')
    tx += out_script
    tx += b'\x00\x00\x00\x00' # timelock

    return binascii.hexlify(tx)


def decode_print(tx):
    """
    Displays a deserialized tx (JSON-like).

    :param tx: A raw tx.
    """
    print('{')
    print(' version : ', binascii.hexlify(tx[:4]), ',')
    print(' input_count : ', tx[4], ',')
    print(' prev_hash : ', binascii.hexlify(tx[5:37]), ',')
    print(' index : ', binascii.hexlify(tx[37:41]), ',')
    scriptsig_len = tx[41]
    print(' scriptsig_len : ', scriptsig_len, ',')
    print(' scriptsig : ', binascii.hexlify(tx[42:42+scriptsig_len]), ',')
    print(' sequence', binascii.hexlify(tx[42+scriptsig_len:42+scriptsig_len+4]), ',')
    print(' output_count', tx[42+scriptsig_len+4], ',')
    print(' value : ', binascii.hexlify(tx[42+scriptsig_len+4:42+scriptsig_len+12]), ',') # aie aie aie
    output_length = tx[42+scriptsig_len+13]
    print(' output_length : ', output_length, ',')
    print(' output : ', binascii.hexlify(tx[42+scriptsig_len+14:42+scriptsig_len+13+output_length+1]), ',') # ouie
    print(' locktime : ', binascii.hexlify(tx[42+scriptsig_len+13+output_length+1:42+scriptsig_len+output_length+18]), ',')
    print('}')


def parse_script(script):
    """
    Parses and serializes a script.

    :param script: The script to serialize, as string.
    :return: The serialized script, as bytes.
    """
    # Parsing the string
    instructions = script.split(' ')
    serialized = b''
    for i in instructions:
        if i in opcodes.OPCODE_NAMES :
            op = opcodes.OPCODE_NAMES.index(i)
            serialized += op.to_bytes(sizeof(op), 'big')
        else:
            try:
                value = int(i, 16)
                length = sizeof(value)
                serialized += length.to_bytes(sizeof(length), 'big') + value.to_bytes(sizeof(value), 'big')
            except:
                raise Exception('Unexpected instruction in script : {}'.format(i))
    if len(serialized) > 10000:
        raise Exception('Serialized script should be less than 10,000 bytes long')
    return serialized


def der_encode(r, s):
    """
    DER-encodes a signed tx. https://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
    https://github.com/bitcoin/bitcoin/blob/ce74799a3c21355b35fed923106d13a0f8133721/src/script/interpreter.cpp#L108
    """
    r_len = sizeof(r)
    s_len = sizeof(s)
    total_len = (4 + r_len + s_len) # 5 = 02 + r_len + 02 + s_len (all 1 byte)
    return b'\x30' + total_len.to_bytes(sizeof(total_len), 'big') + b'\x02' + r_len.to_bytes(sizeof(r_len), 'big') \
            + r.to_bytes(sizeof(r), 'big') + b'\x02' + s_len.to_bytes(sizeof(s_len), 'big') + s.to_bytes(sizeof(s), 'big')


def sign_tx(tx, key):
    """
    Signs a raw transaction with the corresponding private key.

    :param tx: Serialized (INSA/Bit)coin transaction.
    :param key: (INSA/Bit)coin private key, as bytes.
    :return: Signed serialized (Bit/INSA)coin transaction.
    """
    tx_hash = double_sha256(tx, True)
    secexp = int.from_bytes(key, 'big')
    sk = ecdsa.SigningKey.from_secret_exponent(secexp, curve=ecdsa.SECP256k1)
    sig = sk.sign_digest(tx_hash, sigencode=ecdsa.util.sigencode_der_canonize) + b'\x01'
    return sig


def get_scriptpubkey(txid, index, user, password):
    """
    Fetches the scriptpubkey from the tx which has been specified the id.

    :return: The scriptpubkey as bytes
    """
    s = requests.Session()
    s.auth = (user, password)
    s.headers.update({'content-type' : 'text/plain'})
    payload = {'jsonrpc':'1.0',
               'id':'getscriptpubkey',
               'method':'getrawtransaction',
               'params':[txid, 1]}
    r = s.post('http://127.0.0.1:7332', json=payload)
    return binascii.unhexlify(r.json()['result']['vout'][index]['scriptPubKey']['hex'])

def create_raw(privkey, prev_hash, index, script_sig, value, script_pubkey):
    """
    Creates a signed raw transaction

    :param privkey: bytes
    """
    pubkey = get_pubkey(privkey + b'\x01') # Plus the compression byte
    # Before signing the transaction, the script_sig is filled with the script_pubkey from the previous tx
    tx = serialize(prev_hash, index, script_sig, value, script_pubkey)
    sig = sign_tx(binascii.unhexlify(tx) + b'\x01\x00\x00\x00', privkey) # + hash code type
    sig_len = len(sig)
    pub_len = len(pubkey)
    script_sig = sig_len.to_bytes(sizeof(sig_len), 'big') + sig + pub_len.to_bytes(sizeof(pub_len), 'big') + pubkey
    return serialize(prev_hash, index, script_sig, value, script_pubkey)

"""
privkey = wif_decode('TBTBrUVDRtKPaak6XqhxW7NUTiTQBpF2Hq9bszKiv8bg3Zc2oXUg') # To keep compression
prev_txid = 0xfa6ab480a73737f830237693ce7ba7b66b3da300219c60e126015a16a340464d
# Avant de la signer, le unlocking script (scriptsig) est rempli avec le locking script (scriptPubKey) de la precedente tx
scriptsig = parse_script('OP_DUP OP_HASH160 53451511c482ec1d3647934551d4b6dfbeefcde4 OP_EQUALVERIFY OP_CHECKSIG')
scriptpubkey = parse_script('OP_DUP OP_HASH160 53451511c482ec1d3647934551d4b6dfbeefcde4 OP_EQUALVERIFY OP_CHECKSIG')

tx = create_raw(privkey, prev_txid, 1, scriptsig, 98000000, scriptpubkey)
print(tx)
"""

class Bitcoind:
    """
    An interface to the Bitcoin daemon (or Insacoin one).
    """
    def __init__(self, url, user, password):
        self.url = url
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.session.headers.update({'content-type' : 'text/plain'})

    def send(self, call, params=[]):
        """
        Makes a RPC call to the daemon.

        :param call: The method to send, as string.
        :param params: The parameters to send with the method.
        :return: The JSON response.
        """
        payload = {'jsonrpc':'1.0',
                   'id':call,
                   'method':call,
                   'params':params}
        r = self.session.post(self.url, json=payload)
        return r.json()

class Script:
    """
    This class represents a Bitcoin script.
    """
    def __init__(self, script):
        """
        :param script: The script as a string.
        """
        self.script = script
        self.serialized = self.parse(self.script)
        self.size = len(self.serialized)

    def parse(self):
        """
        Parses and serializes a script.

        :return: The serialized script, as bytes.
        """
        # Parsing the string
        instructions = script.split(' ')
        serialized = b''
        # Filling with the corresponding OPCODEs
        for i in instructions:
            if i in opcodes.OPCODE_NAMES:
                op = opcodes.OPCODE_NAMES.index(i)
                serialized += op.to_bytes(sizeof(op), 'big')
            else:
                # There may be some hex numbers in the script which are not OPCODE
                try:
                    value = int(i, 16)
                    length = sizeof(value)
                    serialized += length.to_bytes(sizeof(length), 'big') + value.to_bytes(sizeof(value), 'big')
                except:
                    raise Exception('Unexpected instruction in script : {}'.format(i))
        if len(serialized) > 10000:
            raise Exception('Serialized script should be less than 10,000 bytes long')
        return serialized


class Transaction:
    """
    Represents a Bitcoin transaction.
    For simplicity this transaction just spends one output and creates one input.
    """
    def __init__(self, daemon, prev_hash, index, script_sig, value, script_pubkey):
        """
        :param daemon: An instance of the Bitcoind class.
        :param prev_hash: The id of the transaction which contains the output spent by this transaction.
        :param index: The index of the output spent by this transaction in the output list of the precedent one.
        :param script_sig: The unlocking script of the output of this transaction.
        :param value: The value spent from the output.
        :param script_pubkey: The locking script of the output created by this transaction.
        """
        self.network = daemon
        self.id = None
        self.serialized = None
        self.script_sig = script_sig
        self.script_pubkey = script_pubkey
        if isinstance(prev_hash, int):
            self.prev_hash = prev_hash.to_bytes(sizeof(prev_hash), 'big')
        elif isinstance(prev_hash, bytes):
            self.prev_hash = prev_hash
        else:
            raise Exception('prev_hash must be specified as int or bytes, not {}'.format(type(prev_hash)))
        if isinstance(index, int):
            self.index = index.to_bytes(4, 'little', )
        elif isinstance(index, bytes):
            self.index = index
        else:
            raise Exception('index must be specified as int or bytes, not {}'.format(type(index)))
        if isinstance(value, int):
            self.value = value.to_bytes(8, 'little')
        elif isinstance(value, bytes):
            self.value = value
        else:
            raise Exception('value must be specified as int or bytes, not {}'.format(type(value)))

    def serialize(self, script_sig=None):
        """
        Serializes the transaction.
        :return: The serialized transaction, as bytes.
        """
        if not script_sig:
            script_sig = self.script_sig
        tx = b'\x01\x00\x00\x00'  # version
        tx += b'\x01'  # input count
        tx += self.prev_hash[::-1]
        tx += self.index
        script_length = len(script_sig)
        tx += script_length.to_bytes(sizeof(script_length), 'big')
        tx += script_sig
        tx += b'\xff\xff\xff\xff'  # sequence
        tx += b'\x01'  # output count
        tx += self.value
        script_length = len(self.script_pubkey)
        tx += script_length.to_bytes(sizeof(script_length), 'big')
        tx += self.script_pubkey
        tx += b'\x00\x00\x00\x00'  # timelock
        self.serialized = tx
        return binascii.hexlify(tx)

    def print(self):
        """
        Displays the decoded transaction in a JSON-like way.
        This method is quite messy. Actually, this function IS messy.
        """
        assert self.serialized is not None
        tx = self.serialized
        print('{')
        print(' version : ', binascii.hexlify(tx[:4]), ',')
        print(' input_count : ', tx[4], ',')
        print(' prev_hash : ', binascii.hexlify(tx[5:37]), ',')
        print(' index : ', binascii.hexlify(tx[37:41]), ',')
        scriptsig_len = tx[41]
        print(' scriptsig_len : ', scriptsig_len, ',')
        print(' scriptsig : ', binascii.hexlify(tx[42:42 + scriptsig_len]), ',')
        print(' sequence', binascii.hexlify(tx[42 + scriptsig_len:42 + scriptsig_len + 4]), ',')
        print(' output_count', tx[42 + scriptsig_len + 4], ',')
        print(' value : ', binascii.hexlify(tx[42 + scriptsig_len + 4:42 + scriptsig_len + 12]), ',')  # aie aie aie
        output_length = tx[42 + scriptsig_len + 13]
        print(' output_length : ', output_length, ',')
        print(' output : ', binascii.hexlify(tx[42 + scriptsig_len + 14:42 + scriptsig_len + 13 + output_length + 1]),
              ',')  # ouie
        print(' locktime : ',
              binascii.hexlify(tx[42 + scriptsig_len + 13 + output_length + 1:42 + scriptsig_len + output_length + 18]),
              ',')
        print('}')

    def get_prev_pubkey(self):
        """
        Fetches the script_pubkey from the ouput spent by this tx.

        :return: The script as bytes.
        """
        txid = hex(int.from_bytes(self.prev_hash, 'big'))[2:]
        index = int.from_bytes(self.index, 'little')
        return binascii.unhexlify(self.network.send('getrawtransaction', [txid, 1])['result']['vout'][index]['scriptPubKey']['hex'])

    def sign(self, key):
        """
        Signs the transaction.

        :param key: The private key with which to sign the transaction.
        :return: The DER-encoded signature.
        """
        # To sign the transaction, we serialize it with the script_sig being the script_pubkey of the output spent.
        tx = binascii.unhexlify(self.serialize(script_sig=self.get_prev_pubkey()))
        # Then we hash this serialized transaction, giving us the payload to sign
        tx_hash = double_sha256(tx + b'\x01\x00\x00\x00', True) # + the hash_code byte
        secexp = int.from_bytes(key, 'big')
        sk = ecdsa.SigningKey.from_secret_exponent(secexp, curve=ecdsa.SECP256k1)
        # The byte appended is the hash_code byte, signifying we will use SIGHASH_ALL
        sig = sk.sign_digest(tx_hash, sigencode=ecdsa.util.sigencode_der_canonize) + b'\x01'
        return sig

    def create_and_sign(self, privkey, pubkey):
        """
        Creates a raw transaction and signs it.

        :param privkey: The key to sign the tx with.
        :param pubkey: The corresponding public key.
        :return: A serialized and signed Bitcoin transaction.
        """
        # self.sign creates the raw tx so we don't have to do it before
        sig = self.sign(privkey)
        # We build the final script_sig
        sig_len = len(sig)
        pub_len = len(pubkey)
        script_sig = sig_len.to_bytes(sizeof(sig_len), 'big') + sig + pub_len.to_bytes(sizeof(pub_len), 'big') + pubkey
        return self.serialize(script_sig=script_sig)

    def send(self):
        """
        Sends the transaction to the network.
        """
        # Monkey patching of hex() erasing leading 0s
        tx = '0' + hex(int.from_bytes(self.serialized, 'big'))[2:]
        return self.network.send('sendrawtransaction', params=[tx])

    def send_the_hard_way(self, ip):
        """
        Sends a transaction without using RPC, just a raw network message.
        https://en.bitcoin.it/wiki/Protocol_documentation

        :param ip: The node to which send the message. A string.
        """
        # First the version message
        # https://en.bitcoin.it/wiki/Version_Handshake
        magic = 0xddb8c2fd.to_bytes(4, 'little')
        version = int(70003).to_bytes(4, 'little')
        services = int(1).to_bytes(8, 'little')
        timestamp = int(time.time()).to_bytes(8, 'little')
        myip = socket.inet_aton(requests.get('https://api.ipify.org').text)
        nodeip = socket.inet_aton(ip)
        # 7333 -> insacoin
        addr_recv = services + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff' + myip + int(7333).to_bytes(2, 'big')
        addr_from = services + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff' + nodeip + int(7333).to_bytes(2, 'big')
        #nonce = random.getrandbits(64).to_bytes(8, 'little')
        nonce = 0x00.to_bytes(8, 'little')
        user_agent = 0x00.to_bytes(1, 'big')
        start_height = 0x00.to_bytes(4, 'little')
        payload = version + services + timestamp + addr_recv + addr_from + nonce + user_agent + start_height
        checksum = double_sha256(payload, bin=True)[:4]
        payload_length = len(payload)
        # NULL padded ascii command
        version_message = magic + 'version'.encode('ascii') + b'\x00\x00\x00\x00\x00' + payload_length.to_bytes(4, 'little') + checksum + payload
        # Now the tx message
        checksum = double_sha256(self.serialized, bin=True)[:4]
        tx_length = len(self.serialized)
        tx_message = magic + 'tx'.encode('ascii') + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + tx_length.to_bytes(4, 'little') + checksum + self.serialized
        # Now the verack message
        checksum = double_sha256(b'', bin=True)[:4]
        verack_message = magic + 'verack'.encode('ascii') + b'\x00\x00\x00\x00\x00\x00' + 0x00.to_bytes(4, 'little') + checksum
        # Now let's connect to the node and send it our messages
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, 7333))
        s.send(version_message)
        s.recv(1000) # receive version + verack
        s.send(verack_message)
        s.send(tx_message)
        #print('Error message : ')
        #print(s.recv(1000))
        

if __name__ == '__main__':
    privkey = wif_decode('T9z15bnpSN4hoyDx5JvgirFEYoyNUtcCfmSY7Vm3nUUUCwAuAYpD')
    pubkey = get_pubkey(privkey + b'\x01') # + the compression byte
    prev_txid = 0x1cb7268e3032bbba308f9031c3c97615be1a21234cd99cfb7573e7911c7805a1
    scriptpubkey = parse_script('OP_DUP OP_HASH160 a86c52f90b0e2ae853d8e9ea4403a4b68de7a7e0 OP_EQUALVERIFY OP_CHECKSIG')
    index = 0
    value = 98000000 # In Satoshis

    myCoin = Bitcoind('http://127.0.0.1:7332', 'insacoinrpc', '5CR4JLMSMVspaq8odQH543nJHQ5RX4r5h6Sw9XRp5oL6')
    myTransaction = Transaction(myCoin, prev_txid, index, script_sig=None, value=value, script_pubkey=scriptpubkey)
    myTransaction.create_and_sign(privkey, pubkey)
    #myTransaction.print()
    print(binascii.hexlify(myTransaction.serialized))
    myTransaction.send_the_hard_way('188.213.28.67')