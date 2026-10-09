"""Executable #147 registry reference; no production registry or key handling."""
from dataclasses import dataclass
import hashlib
import hmac
import json
import re

from herradura_context_contract import UUID_FIELDS, context_bytes

DOMAIN = b'CDSE-HKX-REGISTRY-v1\x00'
MAX_BYTES = 1024 * 1024
MAX_ENTRIES = 4096


def identifier(value):
    if type(value) is not str or not re.fullmatch('[0-9a-f]{32}', value):
        raise ValueError('noncanonical registry identifier')
    return bytes.fromhex(value)


def decode_context(context):
    if type(context) is not dict or set(context) != set(UUID_FIELDS) | {'role', 'table', 'field'}:
        raise ValueError('incomplete registry context')
    if any(type(context[name]) is not str for name in ('role', 'table', 'field')):
        raise ValueError('noncanonical context names')
    decoded = dict(context)
    for name in UUID_FIELDS:
        decoded[name] = identifier(context[name])
    context_bytes(decoded)
    return decoded


def canonical(snapshot):
    if type(snapshot) is not dict or set(snapshot) != {
            'schema', 'deployment', 'organization', 'generation', 'minimumFormat', 'entries'}:
        raise ValueError('invalid registry schema')
    if type(snapshot['schema']) is not int or snapshot['schema'] != 1:
        raise ValueError('unsupported registry schema')
    if type(snapshot['generation']) is not int or not 1 <= snapshot['generation'] <= 0xffffffffffffffff:
        raise ValueError('invalid registry generation')
    if type(snapshot['minimumFormat']) is not int or snapshot['minimumFormat'] not in (1, 2):
        raise ValueError('invalid registry format floor')
    deployment = identifier(snapshot['deployment'])
    organization = identifier(snapshot['organization'])
    if not any(deployment) or not any(organization):
        raise ValueError('missing namespace identifier')
    entries = snapshot['entries']
    if type(entries) is not list or len(entries) > MAX_ENTRIES:
        raise ValueError('registry entry limit exceeded')
    lookups, contexts = set(), set()
    for entry in entries:
        if type(entry) is not dict or set(entry) != {'lookup', 'state', 'context'}:
            raise ValueError('invalid registry entry')
        lookup = entry['lookup']
        if type(lookup) is not str or not re.fullmatch(r'[A-Za-z0-9/_:-]{1,128}', lookup) or lookup in lookups:
            raise ValueError('invalid or duplicate registry lookup')
        if entry['state'] not in ('active', 'revoked'):
            raise ValueError('unknown registry state')
        context = decode_context(entry['context'])
        if context['deployment'] != deployment or context['organization'] != organization:
            raise ValueError('cross-namespace registration')
        encoded = context_bytes(context)
        if encoded in contexts:
            raise ValueError('duplicate context registration')
        lookups.add(lookup)
        contexts.add(encoded)
    normalized = dict(snapshot, entries=sorted(entries, key=lambda entry: entry['lookup']))
    body = json.dumps(normalized, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    if len(body) > MAX_BYTES:
        raise ValueError('registry size limit exceeded')
    return body


@dataclass(frozen=True)
class Anchor:
    deployment: str
    organization: str
    generation: int
    minimum_format: int
    digest: bytes

    def __post_init__(self):
        if not any(identifier(self.deployment)) or not any(identifier(self.organization)):
            raise ValueError('missing anchor namespace')
        if type(self.generation) is not int or not 1 <= self.generation <= 0xffffffffffffffff:
            raise ValueError('invalid anchor generation')
        if type(self.minimum_format) is not int or self.minimum_format not in (1, 2):
            raise ValueError('invalid anchor floor')
        if type(self.digest) is not bytes or len(self.digest) != 32:
            raise ValueError('invalid snapshot pin')


@dataclass(frozen=True)
class Registry:
    body: bytes
    anchor: Anchor

    def expected_context(self, lookup):
        for entry in json.loads(self.body)['entries']:
            if entry['lookup'] == lookup:
                if entry['state'] != 'active':
                    raise ValueError('registration revoked')
                return decode_context(entry['context'])
        raise ValueError('registration unavailable')

    def read_kind(self, lookup, frame):
        from herradura_context_contract import read_kind
        self.expected_context(lookup)
        return read_kind(frame, self.anchor.minimum_format)


def authenticate(body, key):
    if type(key) is not bytes or len(key) != 32:
        raise ValueError('registry authentication requires a separate 32-byte key')
    return hmac.digest(key, DOMAIN + body, 'sha256')


def issue(snapshot, key, previous=None):
    body = canonical(snapshot)
    current = json.loads(body)
    if previous is not None:
        old = json.loads(previous.body)
        if (current['deployment'], current['organization']) != (old['deployment'], old['organization']):
            raise ValueError('namespace migration requires separate provisioning')
        if current['generation'] != old['generation'] + 1 or current['minimumFormat'] < old['minimumFormat']:
            raise ValueError('generation or format-floor rollback')
        entries = {entry['lookup']: entry for entry in current['entries']}
        for before in old['entries']:
            after = entries.get(before['lookup'])
            if after is None or after['context'] != before['context']:
                raise ValueError('registrations must retain immutable context and tombstones')
            if before['state'] == 'revoked' and after['state'] != 'revoked':
                raise ValueError('revoked registrations cannot be revived')
    anchor = Anchor(current['deployment'], current['organization'], current['generation'],
                    current['minimumFormat'], hashlib.sha256(body).digest())
    return body, authenticate(body, key), anchor


def verify(body, tag, key, expected):
    """Expected anchor comes from the external manager, never the candidate file."""
    if type(body) is not bytes or len(body) > MAX_BYTES or type(tag) is not bytes or len(tag) != 32:
        raise ValueError('invalid registry envelope')
    if not hmac.compare_digest(authenticate(body, key), tag):
        raise ValueError('registry authentication failed')
    if not hmac.compare_digest(hashlib.sha256(body).digest(), expected.digest):
        raise ValueError('registry differs from trusted snapshot')
    snapshot = json.loads(body)
    if canonical(snapshot) != body:
        raise ValueError('noncanonical registry payload')
    actual = Anchor(snapshot['deployment'], snapshot['organization'], snapshot['generation'],
                    snapshot['minimumFormat'], hashlib.sha256(body).digest())
    if actual != expected:
        raise ValueError('registry trust anchor mismatch')
    return Registry(body, actual)
