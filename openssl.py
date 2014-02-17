##
# OpenSSL key generation module for futorcap.

import subprocess

def generate(pubfname=None, privfname=None, bits="2048"):
    assert pubfname is not None and privfname is not None, \
        "Both pubfname and privfname are required!"
    c = subprocess.call(["openssl", "genrsa", "-out", privfname, bits])
    assert c == 0, "Privkey generation failed"
    c = subprocess.call(["openssl", "rsa", "-in", privfname,
        "-out", pubfname, "-outform", "PEM", "-pubout"])
    assert c == 0, "Pubkey generation failed"
