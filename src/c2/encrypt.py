from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome import Random
from os import path
import base64

class cRSA:
    def __init__(self):
        self.publicKey = None
        self.privateKey = None

        #Check if RSA keypair exists
        if path.exists("./keys/publicKey.pem") and path.exists("./keys/privateKey.pem"):
            print("[INFO] - RSA keypair already exists, skipping...")
            with open("./keys/publicKey.pem", "rb") as f:
                self.publicKey = RSA.import_key(f.read())
            with open("./keys/privateKey.pem", "rb") as f:
                self.privateKey = RSA.import_key(f.read())
        else:
            print("[INFO] - Creating a RSA keypair...")
            self.generateKeypair()


    def generateKeypair(self):
        key = RSA.generate(2048)
        with open("./keys/publicKey.pem", "wb") as f:
            f.write(key.publickey().export_key())
        with open("./keys/privateKey.pem", "wb") as f:
            f.write(key.export_key())
        self.publicKey = key.publickey().export_key()
        self.privateKey = key.export_key()

    def signMsg(self, msg):
        hash = SHA256.new(msg)
        signature = pss.new(self.privateKey).sign(hash)
        signature = base64.b64encode(signature)

        return signature

    def verify(self, msg, signature):
        signature = base64.b64decode(signature)
        hash = SHA256.new(msg)
        verifier = pss.new(self.publicKey)
        try:
            verifier.verify(hash, signature)
            print("Authentic")
        except (ValueError, TypeError):
            print("Not authentic")
