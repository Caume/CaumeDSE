"""Draft #147 wire-contract reference. Not runtime crypto or an approved format."""
import re
import struct

MAGIC = b'CDSEHKX2'
DOMAIN = b'CDSE-HKX-AAD-v2\x00'
HEADER = struct.Struct('>8sBBBBI32s32s')
ROLES = {'ResourcesDB': 1, 'RolesDB': 2, 'LogsDB': 3, 'ColumnFile': 4, 'RawPart': 5}
UUID_FIELDS = ('deployment', 'organization', 'storage', 'resource', 'record')
ZERO = bytes(16)


def metadata(profile, kdf, schema, size, nonce, flags=0):
    if profile != 1 or kdf != 1 or schema != 1 or flags != 0:
        raise ValueError('unsupported draft profile, KDF, schema or flags')
    if type(size) is not int or not 0 <= size <= 0x7fffffff - HEADER.size:
        raise ValueError('invalid ciphertext length')
    if type(nonce) is not bytes or len(nonce) != 32:
        raise ValueError('nonce must contain 32 bytes')
    return struct.pack('>8sBBBBI32s', MAGIC, profile, flags, kdf, schema, size, nonce)


def context_bytes(context):
    if set(context) != set(UUID_FIELDS) | {'role', 'table', 'field'}:
        raise ValueError('context fields must be complete and exact')
    role = ROLES.get(context['role'])
    if role is None:
        raise ValueError('unknown database role')
    output = bytes([role])
    for name in UUID_FIELDS:
        value = context[name]
        if type(value) is not bytes or len(value) != 16:
            raise ValueError('identifiers must contain 16 bytes')
        if value == ZERO and (name != 'storage' or role in (4, 5)):
            raise ValueError('required identifier is missing')
        if name == 'storage' and role in (1, 2, 3) and value != ZERO:
            raise ValueError('internal DB storage identifier must be zero')
        output += value
    for name in ('table', 'field'):
        value = context[name]
        if type(value) is not str or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', value):
            raise ValueError('noncanonical table or field name')
        encoded = value.encode('ascii')
        output += bytes([len(encoded)]) + encoded
    if role == 5 and (context['table'], context['field']) != ('payload', 'bytes'):
        raise ValueError('raw parts use payload/bytes')
    return output


def aad(context, salt, nonce, size, profile=1, kdf=1, schema=1, flags=0):
    if type(salt) is not bytes or len(salt) != 16:
        raise ValueError('salt must contain 16 bytes')
    return DOMAIN + metadata(profile, kdf, schema, size, nonce, flags) + salt + context_bytes(context)


def parse_frame(frame):
    if type(frame) is not bytes or len(frame) < HEADER.size:
        raise ValueError('truncated draft frame')
    magic, profile, flags, kdf, schema, size, nonce, tag = HEADER.unpack_from(frame)
    if magic != MAGIC:
        raise ValueError('not a draft V2 frame')
    metadata(profile, kdf, schema, size, nonce, flags)
    if len(frame) != HEADER.size + size:
        raise ValueError('ciphertext length mismatch')
    return {'profile': profile, 'flags': flags, 'kdf': kdf, 'schema': schema,
            'size': size, 'nonce': nonce, 'tag': tag, 'ciphertext': frame[HEADER.size:]}


def read_kind(frame, minimum_version=1):
    """Proposed dispatch policy only; does not authenticate or decrypt anything."""
    if minimum_version not in (1, 2):
        raise ValueError('unknown trusted format floor')
    if frame.startswith(MAGIC):
        parse_frame(frame)
        return 'draft-v2'
    if frame.startswith(b'CDSEHKX1'):
        if minimum_version == 2 or len(frame) < 74 or frame[8] not in (1, 2):
            raise ValueError('legacy frame unavailable under expected policy')
        return 'legacy-v1'
    if frame.startswith(b'CDSEHKX'):
        raise ValueError('unknown Herradura frame; no AES fallback')
    if minimum_version == 2:
        raise ValueError('unframed value unavailable under expected policy')
    return 'legacy-aes'


def legacy_aad(algorithm, salt):
    # V1 authenticates literal salt spelling, unlike the proposed binary V2 salt.
    return f'CDSE-HKX-AAD-v1|{algorithm}|{salt}'.encode('ascii')
