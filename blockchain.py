from __future__ import annotations
from dataclasses import dataclass
import json
import dataclasses as dc
import math
from functools import reduce
from Crypto.Util import number
import binascii
from typing import Tuple, Sequence
import hashlib
from time import time

class Paillier:
    def xgcd(self, a: int, b: int) -> tuple:
        x0, y0, x1, y1 = 1, 0, 0, 1
        while b != 0:
            q, a, b = a // b, b, a % b
            x0, x1 = x1, x0 - q * x1
            y0, y1 = y1, y0 - q * y1
        return a, x0, y0
    
    def modinv(self, a: int, m: int) -> int:
        g, x, y = self.xgcd(a, m)
        if g != 1:
            raise Exception('modular inverse does not exist')
        else:
            return x % m
    
    def L(self, x: int, n: int) -> int:
        return (x - 1) // n
    
    def paillier_keygen(self, bits: int) -> tuple:
        # prime number p, q
        p = number.getPrime(bits // 2)
        while True:
            q = number.getPrime(bits // 2)
            if p != q:
                break
        n = p * q
        lamda = math.lcm(p - 1, q - 1)
        
        while True:
            g = number.getRandomRange(2, n*n)
            mu = self.modinv(self.L(pow(g, lamda, n*n), n), n)
            if mu is not None:
                break
            
        return (n, g), (lamda, mu)
    
    def paillier_encrypt(self, m: int, pk: int) -> int:
        n, g = pk
        nn = n * n
        # assert (0 <= m and m < n)
        while True:
            r = number.getRandomRange(1, n)
            if math.gcd(r, n) == 1:
                break
        return (pow(g, m, nn) * pow(r, n, nn)) % nn
    
    def paillier_decrypt(self, c: int, pk: int, sk: int) -> int:
        n, g = pk
        lamda, mu = sk
        # assert(0 <= c < n*n)
        return (self.L(pow(c, lamda, n*n), n) * mu) % n
    
@dataclass
class Transaction:
    sender_address: str
    receiver_address: str
    value: float
    sign: str = None
    
    def str_data(self) -> str:
        d = dc.asdict(self)
        del d['sign']
        return json.dumps(d, sort_keys=True)
    
    def json_dumps(self) -> str:
        return json.dumps(dc.asdict(self), sort_keys=True)
    
    @classmethod
    def json_loads(cls, json_str: str) -> Transaction:
        return cls(**json.loads(json_str))
    
@dataclass
class Wallet:
    def __init__(self):
        pk, sk = Paillier().paillier_keygen(bits=40)
        self.private_key = sk
        self.address = pk
        
    def sign_transaction(self, transaction: Transaction) -> Transaction:
        # generate signer from self private key
        signer = Paillier()
        h = int(binascii.hexlify(transaction.str_data().encode()), 16)
        return Transaction(transaction.sender_address, transaction.receiver_address, transaction.value, signer.paillier_encrypt(h, self.private_key))
    
    def send(self, receiver_address: str, value: float) -> Transaction:
        return self.sign_transaction(Transaction(self.address, receiver_address, value))
    
    
@dataclass
class Block:
    time: float
    transactions: Tuple[Transaction]
    previous_hash: str
    sign: str = None

    def json_dumps(self) -> str:
        dct=dc.asdict(self)
        dct["transactions"]=[t.json_dumps() for t in self.transactions]
        return json.dumps(dct)
    @classmethod
    def json_loads(cls, string) -> Block:
        dct=json.loads(string)
        dct["transactions"]=tuple([Transaction.json_loads(t) for t in dct["transactions"]])
        return cls(**dct)

    def hash(self) -> str:
        block_bytes=self.json_dumps().encode()
        return hashlib.sha256(block_bytes).hexdigest()

class TimestampServer:
    def __init__(self):
        pk, sk = Paillier().paillier_keygen(bits=40)
        self.public_key = pk
        self.signer = Paillier()
        genesis = Block(time(), (), "0")
        self.block_chain = [genesis]
    
    def genete_block(self, transactions: Sequence[Transaction]) -> Block:
        # generate block
        block = Block(time(), tuple(transactions), self.block_chain[-1].hash())
        
        # sign the block
        dct = dc.asdict(block)
        del dct['sign']
        block.sign = self.signer.paillier_encrypt(int(binascii.hexlify(json.dumps(dct, sort_keys=True).encode()), 16), self.public_key)
        
        self.block_chain.append(block)
        
Ledger=list

alice = Wallet()
bob = Wallet()
ledger = Ledger()

transaction = alice.send(bob.address, 100)
ledger.append(transaction)

timestampserver = TimestampServer()
transactions=[]
transactions.append(alice.send(bob.address, 5))
transactions.append(bob.send(alice.address, 7))
timestampserver.genete_block(transactions)
print(timestampserver.block_chain[-1].json_dumps())