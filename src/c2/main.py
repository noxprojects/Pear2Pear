import encrypt

def main():
    rsaHandle = encrypt.cRSA()
    message = b"test"
    signature = rsaHandle.signMsg(message)
    print("Message: {}\nSignature: {}".format(message.decode("utf-8"), signature.decode("utf-8")))

    rsaHandle.verify(message, signature)

if __name__ == "__main__": #If ran as main file
    main()
