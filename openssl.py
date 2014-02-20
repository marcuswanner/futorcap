##
# OpenSSL key generation module for futorcap.
# This file serves as a reference for additional keygen modules.
# The functions in this file need not guard against malicious args.

README = """
You can use the .pub keys to encrypt and .priv keys to decrypt. The .priv key
for each .pub key will NOT be available before the timestamp listed in the
filename.

The .priv files in this directory are openssl "key files" and the .pub files
are openssl "cert files" in PEM format. You can encrypt like this:

openssl smime -encrypt -binary -aes-25r-cbc -in plainfilename \\
        -out cipherfilename -outform DER 2014-02-20_05-13-33_UTC.pub

And decrypt like this:

openssl smime -decrypt -binary -in cipherfilename -inform DER \\
        -out plainfilename -inkey 2014-02-20_05-13-33_UTC.priv

The .pub files are all signed by root.pub. You should receive root.pub over
a secure channel and verify normal timestamped .pub files using:




    Powered by futorcap.futord ~ GPL2 Copyright 2014 Marcus Wanner
"""

import subprocess, os

##
# Do any root key setup. This will certainly be run before generate() and may
# be run often, so don't overwrite existing keys. You will get a keydir keyword
# arg which provides a location for your keys, along with a str-format keyword
# arg for each entry in your plugin's section of the config.
def init(keydir=".", bits="2048"):

    privroot = os.path.join(keydir, "root.priv")
    pubroot = os.path.join(keydir, "root.pub")

    makepubkey = False
    makeprivkey = False
    if not os.path.exists(privroot):
        makeprivkey = True
        makepubkey = True
    elif not os.path.exists(pubroot):
        makeprivkey = True
        makepubkey = True

    if makeprivkey:
        c = subprocess.call(["openssl", "genrsa", "-out", privroot, bits])
        assert c == 0, "Root privkey generation failed"
    if makepubkey:
        c = subprocess.call(["openssl", "req", "-batch", "-x509", "-new",
                            "-nodes", "-key", privroot, "-out", pubroot])
        assert c == 0, "Root pubkey generation failed"

    open(os.path.join(keydir, "README.txt"), "w").write(README)

##
# Generate a privkey/pubkey pair. You will get a str-format keyword arg for
# each entry in your plugin's section of the config, along with a keydir where
# your keys will reside, in addition to the pubfname and privfname keyword
# args which specify the names of the files this function will write relative
# to the keydir.
def generate(pubfname=None, privfname=None, keydir=".", bits="2048"):

    assert pubfname is not None and privfname is not None, \
        "Both pubfname and privfname are required!"
    pubfname = os.path.join(keydir, pubfname)
    privfname = os.path.join(keydir, privfname)

    c = subprocess.call(["openssl", "genrsa", "-out", privfname, bits])
    assert c == 0, "Privkey generation failed"

    privroot = os.path.join(keydir, "root.priv")
    pubroot = os.path.join(keydir, "root.pub")
    c = subprocess.call("openssl req -batch -new -key {} | "
            "openssl x509 -req -CA {} -CAkey {} -CAcreateserial -out {}"
            "".format(privfname, pubroot, privroot, pubfname), shell=True)
    assert c == 0, "Pubkey generation failed"
