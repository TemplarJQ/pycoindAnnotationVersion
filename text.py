import hashlib

from base58 import b58encode_check

from pycoind.script import script
from pycoind.script import scriptBuild

import ecdsa


def test_Tokenizer(my_addr):
    pk_script = scriptBuild.get_pk_script(my_addr)
    return pk_script


def test_de_Tokenizer(pk_script):
    return script.Tokenizer(pk_script)


def pubkey_to_address(pubkey: bytes) -> str:
    if 'ripemd160' not in hashlib.algorithms_available:
        raise RuntimeError('missing ripemd160 hash algorithm')

    sha = hashlib.sha256(pubkey).digest()
    ripe = hashlib.new('ripemd160', sha).digest()

    address = b58encode_check(b'\x00' + ripe)
    address = address if isinstance(address, str) else str(address, encoding="utf-8")
    return address


# begin test
signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
verifying_key = signing_key.get_verifying_key()

my_address = verifying_key.to_string()

pk_script = test_Tokenizer(my_address)
print(pk_script)

test_script = 'v\xa9\x14\xd6Kqr\x9aPM#\xd9H\x88\xd3\xf7\x12\xd5WS\xd5\xd6"\x88\xac'
# de_script = test_de_Tokenizer(test_script)
print(script.Tokenizer(test_script))