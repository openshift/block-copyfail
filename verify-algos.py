#!/usr/bin/env python3
"""Verify that only authencesn is blocked while other AF_ALG algorithms work."""
import socket

tests = [
    ("aead",     "gcm(aes)"),
    ("aead",     "ccm(aes)"),
    ("aead",     "rfc4106(gcm(aes))"),
    ("hash",     "sha256"),
    ("skcipher", "cbc(aes)"),
    ("aead",     "authencesn(hmac(sha256),cbc(aes))"),
]

for salg_type, salg_name in tests:
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    try:
        s.bind((salg_type, salg_name))
        print(f"  ALLOWED  {salg_type}/{salg_name}")
    except OSError as e:
        print(f"  BLOCKED  {salg_type}/{salg_name} — {e}")
    finally:
        s.close()
