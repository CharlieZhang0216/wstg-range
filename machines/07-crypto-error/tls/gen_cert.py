"""Generate the deliberately bad certificate for WSTG-CRYP-01.

Self-signed, RSA-1024, SHA1 signature, hostname mismatch (CN=legacy.acme.test
while clients connect to 127.0.0.1), and already expired.
"""
import random

from OpenSSL import crypto

key = crypto.PKey()
key.generate_key(crypto.TYPE_RSA, 1024)          # weak key size

cert = crypto.X509()
cert.get_subject().CN = "legacy.acme.test"       # hostname mismatch
cert.get_subject().O = "Acme Legacy Systems"
cert.set_issuer(cert.get_subject())              # self-signed
cert.set_pubkey(key)
cert.set_serial_number(random.getrandbits(64))
cert.gmtime_adj_notBefore(-400 * 86400)
cert.gmtime_adj_notAfter(-30 * 86400)            # expired 30 days ago
cert.sign(key, "sha1")                           # weak signature hash

with open("/app/cert.pem", "wb") as f:
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
with open("/app/key.pem", "wb") as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
print("wrote expired RSA-1024/SHA1 self-signed cert for legacy.acme.test")