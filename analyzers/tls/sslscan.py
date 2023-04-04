import copy
import datetime
import re
import sys

try:
  # https://github.com/tiran/defusedxml
  import defusedxml.ElementTree
except:
  sys.exit("this script requires the 'defusedxml' module.\nplease install it via 'pip3 install defusedxml'.")

from .. import AbstractParser
from . import CERTIFICATE_SCHEMA, SERVICE_SCHEMA

class Parser(AbstractParser):
  '''
  parse results of the "sslscan" tool.

  $ sslscan --show-certificate --ocsp --show-sigs --xml="{result_file}.xml" {hostname}:{port}
  '''

  def __init__(self):
    super().__init__()

    self.name = 'sslscan'
    self.file_type = 'xml'
    self.cipher_suites_specifications = {}

  def parse_file(self, path):
    super().parse_file(path)

    '''
    <document>
      <ssltest host="{host}" port="{port}">
        <protocol type="ssl" version="2" enabled="0" />
        <protocol type="ssl" version="3" enabled="0" />
        <protocol type="tls" version="1.0" enabled="0" />
        <protocol type="tls" version="1.1" enabled="0" />
        <protocol type="tls" version="1.2" enabled="1" />
        <protocol type="tls" version="1.3" enabled="1" />
        <fallback supported="1" />
        <renegotiation supported="0" secure="0" />
        <compression supported="0" />
        <heartbleed sslversion="TLSv1.3" vulnerable="0" />
        <heartbleed sslversion="TLSv1.2" vulnerable="0" />
        <cipher cipher="{OpenSSL/IANA name}" [curve="{elliptic_curve}"] ecdhebits="{bits}"] [dhebits="{bits}"]> [multiple]
        <group name="{group}(\s.+)?" />

        <group sslversion="TLSv1.3" bits="128" name="secp256r1 (NIST P-256)" id="0x0017" />
        <group sslversion="TLSv1.3" bits="128" name="x25519" id="0x001d" />
        <group sslversion="TLSv1.2" bits="128" name="secp256r1 (NIST P-256)" id="0x0017" />
        <group sslversion="TLSv1.2" bits="128" name="x25519" id="0x001d" />
        <connection-signature-algorithm sslversion="TLSv1.3" name="ecdsa_secp256r1_sha256" id="0x0403" />
        <certificates>

    '''

    document_node = defusedxml.ElementTree.parse(path).getroot()

    for ssltest_node in document_node.iter('ssltest'):
      host = ssltest_node.get('host')
      port = ssltest_node.get('port')

      identifier = f"{host}:{port}"

      if identifier in self.services:
        continue

      service = copy.deepcopy(SERVICE_SCHEMA)
      self.services[identifier] = service

      service['host'] = host
      service['port'] = port

      for protocol_node in ssltest_node.iter('protocol'):
        if protocol_node.get('enabled') == '1':
          protocol = f"{protocol_node.get('type').upper()} {protocol_node.get('version')}"
          service['protocol_versions'].append(protocol)

      fallback_node = ssltest_node.find('fallback')
      if fallback_node and fallback_node.get('supported') == '1':
        if 'misc' not in service:
          service['misc'] = {}
        service['misc']['fallback_SCSV'] = 'supported'

      # vulnerabilities

      renegotiation_node = ssltest_node.find('renegotiation')
      if renegotiation_node and renegotiation_node.get('supported') == '1' and renegotiation_node.get('secure') == '0':
        service['vulnerabilities'].append('client_initiated_renegotiation_DoS')

      compression_node = ssltest_node.find('compression')
      if compression_node and compression_node.get('supported') == '1':
        service['vulnerabilities'].append('CRIME')

      for heartbleed_node in ssltest_node.iter('heartbleed'):
        if heartbleed_node.get('vulnerable') == '1':
          service['vulnerabilities'].append('Heartbleed')
          break

      # cipher suites

      for cipher_node in ssltest_node.iter('cipher'):
        self._parse_cipher_node(
          cipher_node,
          service['cipher_suites'],
          service['key_exchange']
        )

      for group_node in ssltest_node.iter('group'):
        self._parse_group_node(
          group_node,
          service['key_exchange']
        )

      for connection_signature_algorithm_node in ssltest_node.iter('connection-signature-algorithm'):
        self._parse_connection_signature_algorithm_node(
          connection_signature_algorithm_node,
          service['signature_algorithms']
        )

      for certificate_node in ssltest_node.iter('certificate'):
        if certificate_node.get('type') == 'short':
          self._parse_certificate_node(
            certificate_node,
            service
          )

      for certificate in service['certificates']:
        if not self._evaluate_certificate_trust(certificate, host):
          service['issues'].append("certificate not trusted: certificate does not match supplied URI")
          break

  def _parse_cipher_node(self, node, cipher_suites, key_exchange):
    cipher_suite = node.get('cipher') # most often OpenSSL name

    cipher_suite_ID = node.get('id')[2:]
    hex_byte_1 = f'0x{cipher_suite_ID[:2]}'
    hex_byte_2 = f'0x{cipher_suite_ID[2:]}'

    for name, cs in self.cipher_suites_specifications.items():
      if cs['hex_byte_1'] == hex_byte_1 and cs['hex_byte_2'] == hex_byte_2:
        cipher_suite = name
        break

    if cipher_suite not in cipher_suites:
      cipher_suites.append(cipher_suite)

    if node.get('dhebits'):
      kex = ( 'DH', int(node.get('dhebits')) )
    elif node.get('ecdhebits'):
      kex = ( 'ECDH', int(node.get('ecdhebits')) )
    else:
      kex = ( 'RSA', None )

    kex_methods = key_exchange['methods']
    if kex[0] not in kex_methods:
      kex_methods[kex[0]] = kex[1]
    elif kex[1] and kex_methods[kex[0]] and kex[1] < kex_methods[kex[0]]:
      kex_methods[kex[0]] = kex[1]

  def _parse_group_node(self, node, key_exchange):
    name = node.get('name').split(' ')[0]
    if name not in key_exchange['groups']:
      key_exchange['groups'].append(name)

  def _parse_connection_signature_algorithm_node(self, node, signature_algorithms):
    name = node.get('name')
    if name == 'ANY':
      name = '*'

    if name not in signature_algorithms:
      signature_algorithms.append(name)

  def _parse_certificate_pk_node(self, node, public_key):
    public_key['bits'] = int(node.get('bits'))

    pk_type = node.get('type')
    if pk_type == 'EC':
      pk_type = 'ECDSA'
      public_key['curve'] = node.get('curve_name')
      public_key['bits'] = None # TODO: currently, the value reported by sslscan is NOT correct for ECDSA

    public_key['type'] = pk_type

  def _parse_certificate_subject_node(self, node, subjects):
    subjects.append(node.text)

  def parse_certificate_altnames_node(self, node, subjects):
    for altname in node.text.split(', '):
      subject = altname.split(':')[1]
      if subject not in subjects:
        subjects.append(subject)

  def _parse_certificate_self_signed_node(self, node, issues):
    if node.text == 'true':
      issues.append("certificte not trusted: self signed")

  def _parse_certificate_validity(self, node):
    # Feb  2 23:00:24 2023 GMT

    date_time = datetime.datetime.strptime(
      node.text.replace('  ', ' 0'),
      '%b %d %H:%M:%S %Y GMT'
    )

    return date_time.isoformat(sep=' ')

  def _parse_certificate_expired_node(self, node, issues):
    if node.text == 'true':
      issues.append("certificate not trusted: expired")

  def _parse_certificate_node(self, node, service):
    certificate = copy.deepcopy(CERTIFICATE_SCHEMA)
    service['certificates'].append(certificate)

    certificate['signature_algorithm'] = node.find('signature-algorithm').text

    self._parse_certificate_pk_node(
      node.find('pk'),
      certificate['public_key']
    )

    self._parse_certificate_subject_node(
      node.find('subject'),
      certificate['subjects']
    )

    self.parse_certificate_altnames_node(
      node.find('altnames'),
      certificate['subjects']
    )

    self._parse_certificate_self_signed_node(
      node.find('self-signed'),
      service['issues']
    )

    certificate['validity']['not_before'] = self._parse_certificate_validity(node.find('not-valid-before'))
    certificate['validity']['not_after'] = self._parse_certificate_validity(node.find('not-valid-after'))

    self._parse_certificate_expired_node(
      node.find('expired'),
      service['issues']
    )

  def _evaluate_certificate_trust(self, certificate, host):
    for subject in certificate['subjects']:
      #  wildcard certificate
      #                               cheap trick to test whether the host is a DNS hostname (or at least an IPv4 address)
      #                                               test parent domain of host and subject
      if subject.startswith('*.') and '.' in host and host.split('.')[1:] == subject.split('.')[1:]:
        return True
      if host == subject:
        return True

    return False




