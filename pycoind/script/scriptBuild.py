import binascii
from math import log

from . import opcodes


def sizeof(n):
    if n == 0:
        return 1
    return int(log(n, 256)) + 1


def get_pk_script(to_addr):
    # just use the P2PKH method
    pubkey_script = Script('OP_DUP OP_HASH160').parse()
    pubkey_script += len(to_addr).to_bytes(1, 'big')
    pubkey_script += to_addr
    pubkey_script += Script('OP_EQUALVERIFY OP_CHECKSIG').parse()

    return pubkey_script


def get_signature_script_without_hashtype(signature, pk):
    """
    this version is just for checking our process is good enough to get the message.
    """

    # get signature len
    sig_len = len(signature)

    # get pk_script len
    pk_len = len(pk)

    signature_script = sig_len.to_bytes(1, 'big') + signature + pk_len.to_bytes(1, 'big') + pk

    return binascii.hexlify(signature_script)


def get_signature_script(signature, pk):
    """
    if we use signature with a hash_type we need to check in our code.
    eg : hash_type = b'\x01' (SIGHASH_ALL)and the final signature is (sig + hash_type) and we need to spilt it out later.
    """
    # add hash_type
    sig = signature + b'\x01'

    return get_signature_script_without_hashtype(sig, pk)


class Script:
    """
    This class represents a Bitcoin script.
    """

    def __init__(self, script):
        """
        :param script: The script as a string.
        """
        self.script = script

    def parse(self):
        """
        Parses and serializes a script.

        :return: The serialized script, as bytes.
        """
        # we do the process parse the string here
        element = self.script.split(' ')
        serlized_data = b''
        for i in element:
            if i in opcodes.OPCODE_NAMES:
                op = opcodes.OPCODE_NAMES.index(i)
                serlized_data += op.to_bytes(sizeof(op), 'big')
            else:
                # if there is some hex numbers in the script which are not OPCODE
                try:
                    value = int(i, 16)
                    length = sizeof(value)
                    serlized_data += length.to_bytes(sizeof(length), 'big') + value.to_bytes(sizeof(value), 'big')
                except:
                    raise Exception('Unexpected instruction in script : {}'.format(i))
        return serlized_data
