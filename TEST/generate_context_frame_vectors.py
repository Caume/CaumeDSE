#!/usr/bin/env python3
"""Generate synthetic draft vectors using the pinned upstream Python port.

Input: git show ad42138af14a40eb3b47127872f39509723c789f:'Herradura cryptographic suite.py'
Output is independent of the C acceptance harness; no runtime key material.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import herradura_context_contract as contract

REVISION = 'ad42138af14a40eb3b47127872f39509723c789f'
SOURCE_SHA256 = 'dd365a0d883de673535f2f1e63b863b04056a83270c4f8a27b75236dd362e59f'


def generate(path):
    if hashlib.sha256(Path(path).read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError('reference source does not match the pinned Python port')
    spec = importlib.util.spec_from_file_location('cdse_vector_reference', path)
    upstream = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = upstream
    spec.loader.exec_module(upstream)
    context = dict(zip(contract.UUID_FIELDS, (bytes([i])*16 for i in range(1, 6))))
    context.update(role='ColumnFile', table='data', field='value')
    password, salt = b'fixture-v2-password', bytes(range(16))
    cases = []
    for index, size in enumerate((0, 1, 33, 97)):
        nonce = bytes((i+index*7) % 256 for i in range(32))
        plain = bytes((i*17+3) % 256 for i in range(size))
        key = hashlib.pbkdf2_hmac('sha256', password, salt, 10000, 32)
        _, ciphertext, tag = upstream.hske_nl_aead_encrypt(
            upstream.BitArray(256, int.from_bytes(key, 'big')), plain,
            contract.aad(context, salt, nonce, size),
            upstream.BitArray(256, int.from_bytes(nonce, 'big')))
        assert upstream.hske_nl_aead_decrypt(
            upstream.BitArray(256, int.from_bytes(key, 'big')),
            upstream.BitArray(256, int.from_bytes(nonce, 'big')), ciphertext, tag,
            contract.aad(context, salt, nonce, size)) == plain
        frame = contract.metadata(1, 1, 1, size, nonce) + tag + ciphertext
        cases.append(dict(plaintext=plain.hex(), nonce=nonce.hex(), frame=frame.hex()))
    return dict(reference_revision=REVISION, reference_sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                context={k: (v.hex() if isinstance(v, bytes) else v) for k, v in context.items()},
                password=password.hex(), salt=salt.hex(), cases=cases)


if __name__ == '__main__':
    print(json.dumps(generate(sys.argv[1]), indent=2, sort_keys=True))
