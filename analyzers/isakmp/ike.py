import copy
import re

from .. import AbstractParser
from . import SERVICE_SCHEMA

class Parser(AbstractParser):
  '''
  parse results of the `ike` scanner.

  $ ike ${address}
  '''

  def __init__(self):
    super().__init__()

    self.name = 'ike'
    self.file_type = 'log'

  def parse_file(self, path):
    super().parse_file(path)

    '''
    # ike-scan --sport=0 --trans='5,2,64221,14' 192.168.42.116
    192.168.42.116	Main Mode Handshake returned HDR=(CKY-R=268db1329ed4fd5f) SA=(Enc=3DES Hash=SHA1 Group=14:modp2048 Auth=Hybrid LifeType=Seconds LifeDuration=28800) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

    # ike-scan --sport 0 --trans='7/256,2,4,14' 192.168.42.116
    192.168.42.116	Main Mode Handshake returned HDR=(CKY-R=2232fde4d285ceb8) SA=(Enc=AES KeyLength=256 Hash=SHA1 Group=14:modp2048 Auth=PSK LifeType=Seconds LifeDuration=28800) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

    # ike-scan -s 0 -2 192.168.42.116
    192.168.42.116	IKEv2 SA_INIT Handshake returned HDR=(CKY-R=fb1f618ae71783a5, IKEv2) SA=(Encr=AES_CBC,KeyLength=256 Integ=HMAC_SHA1_96 Prf=HMAC_SHA1 DH_Group=2:modp1024) KeyExchange(132 bytes) Nonce(32 bytes) Notification(4 bytes) Notification(4 bytes)
    '''

    # regular expression of a IKE (version 1 and 2) handshake
    handshake = re.compile(r'^(?P<host>[0-9.]+)\s(?P<mode>.+?) Handshake returned .+? SA=\((?P<security_association>[^)]+)\)')

    # regular expression of a Security Association (SA) for IKEv1
    security_association_1 = re.compile(r'Enc=(?P<encryption_algorithm>[^\s]+)(?:\s+KeyLength=(?P<key_length>[^\s]+))?\s+Hash=(?P<hash_algorithm>[^\s]+)\s+Group=(?P<group>[^\s]+)\s+Auth=(?P<authentication_method>[^\s]+)')

    # regular expression of a Security Association (SA) for IKEv2
    security_association_2 = re.compile(r'Encr=(?P<encryption_algorithm>[^\s,]+)(?:,KeyLength=(?P<key_length>[^\s]+))?\s+Integ=(?P<integrity_algorithm>[^\s]+)\s+Prf=(?P<pseudorandom_function>[^\s]+)\s+DH_Group=(?P<key_exchange_method>[^\s]+)')

    with open(path) as f:
      results = f.read()

    for line in results.splitlines():
      m = handshake.search(line)
      if not m:
        continue

      host = m.group('host')

      identifier = host

      if identifier not in self.services:
        self.services[identifier] = copy.deepcopy(SERVICE_SCHEMA)

      service = self.services[identifier]

      mode = m.group('mode')

      sa = m.group('security_association')

      m = security_association_1.search(sa)
      if m:
        self._parse_SAv1(m, mode, service)
        continue

      m = security_association_2.search(sa)
      if m:
        self._parse_SAv2(m, service)
        continue

  def _parse_SAv1(self, sa, mode, service):
    version = 'IKEv1'
    if version not in service['versions']:
      service['versions'].append(version)

    s = service[version]

    if mode == 'Aggressive Mode':
      s['aggressive'] = True

    encryption_algorithm = sa.group('encryption_algorithm')

    if encryption_algorithm not in s['encryption_algorithms']:
      s['encryption_algorithms'].append(encryption_algorithm)

    if sa.group('key_length'):
      key_lengths = s['key_lengths']
      key_length = int(sa.group('key_length'))

      if encryption_algorithm not in key_lengths:
        key_lengths[encryption_algorithm] = [ key_length ]
      elif key_length not in key_lengths[encryption_algorithm]:
        key_lengths[encryption_algorithm].append(key_length)

    hash_algorithm = sa.group('hash_algorithm')
    if hash_algorithm not in s['hash_algorithms']:
      s['hash_algorithms'].append(hash_algorithm)

    authentication_method = sa.group('authentication_method')
    if authentication_method not in s['authentication_methods']:
      s['authentication_methods'].append(authentication_method)

    group = sa.group('group')
    if group not in s['groups']:
      s['groups'].append(group)

  def _parse_SAv2(self, sa, service):
    version = 'IKEv2'
    if version not in service['versions']:
      service['versions'].append(version)

    s = service[version]

    encryption_algorithm = sa.group('encryption_algorithm')

    if encryption_algorithm not in s['encryption_algorithms']:
      s['encryption_algorithms'].append(encryption_algorithm)

    if sa.group('key_length'):
      key_lengths = s['key_lengths']
      key_length = int(sa.group('key_length'))

      if encryption_algorithm not in key_lengths:
        key_lengths[encryption_algorithm] = [ key_length ]

      elif key_length not in key_lengths[encryption_algorithm]:
        key_lengths[encryption_algorithm].append(key_length)

    pseudorandom_function = sa.group('pseudorandom_function')
    if pseudorandom_function not in s['pseudorandom_functions']:
      s['pseudorandom_functions'].append(pseudorandom_function)

    integrity_algorithm = sa.group('integrity_algorithm')
    if integrity_algorithm not in s['integrity_algorithms']:
      s['integrity_algorithms'].append(integrity_algorithm)

    key_exchange_method = sa.group('key_exchange_method')
    if key_exchange_method not in s['key_exchange_methods']:
      s['key_exchange_methods'].append(key_exchange_method)

