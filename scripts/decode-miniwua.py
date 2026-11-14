#!/usr/bin/env python3
"""Decode the verified a/i MiniWUA container offline; do not infer bit meanings.

Algorithm reference: https://iosre.com/t/26281 (byte_archaeologist).
Android header constants and field semantics differ from that iOS analysis.
Input and key are local files; decoded private data is never printed.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zlib


def des(data, key, decrypt):
    command = ["openssl", "enc", "-des-ecb", "-nopad", "-K", key.hex(),
               "-provider", "default", "-provider", "legacy"]
    if decrypt:
        command.append("-d")
    result = subprocess.run(command, input=data, capture_output=True)
    if result.returncode:
        raise ValueError("OpenSSL DES operation failed; check provider support")
    if len(result.stdout) != len(data):
        raise ValueError("DES length mismatch")
    return result.stdout


def outer(data, key, decrypt):
    if len(data) < 10 or (len(data) - 2) % 8:
        raise ValueError("invalid block framing")
    result = bytearray(data[:2] + des(data[2:], key, decrypt))
    position = 2 + 8 * (data[0] % ((len(data) - 2) // 8))
    result[position:position + 8] = bytes(x ^ data[0] for x in data[position:position + 8])
    return bytes(result)


def xor_body(data):
    result = bytearray(data)
    for index in range(5, len(result)):
        result[index] ^= data[3:5][(~index) & 1]
    return bytes(result)


def decode(token, key):
    if len(key) != 8 or not token or token[0] not in "ai":
        raise ValueError("expected 8-byte DES material and a/i token")
    cipher = base64.b64decode(token[1:], validate=True)
    padded = outer(cipher, key, True)
    candidate = xor_body(padded)
    position, parts = 14, []
    for _ in range(5):
        if position >= len(candidate):
            raise ValueError("component length missing")
        length = candidate[position]
        position += 1
        if position + length > len(candidate):
            raise ValueError("truncated component")
        parts.append(candidate[position:position + length])
        position += length
    if [len(x) for x in parts[1:4]] != [7, 11, 32]:
        raise ValueError("unsupported component layout")
    padding = (-(position - 2)) % 8
    if padded[position:] != bytes([padding]) * padding:
        raise ValueError("invalid padding or trailing data")
    body = candidate[:position]
    checksum = zlib.crc32(body[9:]) & 0xffffffff
    for byte in body[3:5]:
        checksum ^= byte
        for _ in range(8):
            checksum = (checksum >> 1) ^ (0xedb88320 if checksum & 1 else 0)
    if body[5:9] != checksum.to_bytes(4, "big"):
        raise ValueError("CRC mismatch")
    reconstructed = outer(xor_body(body) + bytes([padding]) * padding, key, False)
    if reconstructed != cipher:
        raise ValueError("exact re-encoding mismatch")
    return body, parts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="local one-token text file")
    parser.add_argument("--key-file", type=Path, required=True, help="exactly 8 raw bytes")
    parser.add_argument("--output", type=Path, required=True, help="new private JSON file")
    args = parser.parse_args()
    body, parts = decode(args.input.read_text().strip(), args.key_file.read_bytes())
    data = {"crc_verified": True, "exact_reencoding": True,
            "component_lengths": [len(p) for p in parts],
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_hex_private": body.hex(),
            "component_hex_private": [p.hex() for p in parts],
            "candidate_state_hex_private": (parts[1] + parts[2]).hex(),
            "bit_semantics_verified": False}
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as destination:
        json.dump(data, destination, indent=2)
        destination.write("\n")
    print(json.dumps({"crc_verified": True, "exact_reencoding": True,
                      "component_lengths": data["component_lengths"]}))
