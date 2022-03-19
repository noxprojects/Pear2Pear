import encrypt

def main():
    rsaHandle = encrypt.cRSA()
    message = b"test"
    signature = rsaHandle.signMsg(message)
    print("Message: {}\nSignature: {}".format(message.decode("utf-8"), signature.decode("utf-8")))

if __name__ == "__main__": #If ran as main file
    main()
