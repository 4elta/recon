import copy
import json
import re
import sys

from .. import Issue, AbstractParser
from . import CERTIFICATE_SCHEMA, SERVICE_SCHEMA

PROTOCOL_VERSIONS = {
  'SSLv2': 'SSL 2.0',
  'SSLv3': 'SSL 3.0',
  'TLS1': 'TLS 1.0',
  'TLS1_1': 'TLS 1.1',
  'TLS1_2': 'TLS 1.2',
  'TLS1_3': 'TLS 1.3'
}

class Parser(AbstractParser):
  '''
  parse results of the "testssl.sh" tool.

  testssl
    --ip one
    --mapping no-openssl
    --warnings off
    --connect-timeout 60
    --openssl-timeout 60
    --json
    {hostname}:{port}
  '''

  def __init__(self):
    super().__init__()

    self.name = 'testssl'
    self.file_type = 'json'

  def parse_file(self, path):
    super().parse_file(path)

    with open(path, 'r') as f:
      try:
        results = json.load(f)
      except Exception as e:
        sys.exit(f"error parsing file '{path}'\n\n{e}")

    for f in filter(lambda x: x['id'] == 'optimal_proto', results):
      if "doesn't seem to be a TLS/SSL enabled server" in f['finding']:
        return

    for s in filter(lambda x: x['id'] == 'service', results):
      host = s['ip'].split('/')[0]
      '''
      we instruct testssl to only test the first IP address (`--ip one`).
      therefore, we can be sure, that the hostname (or, if only the IP address was used) plus the port number is enough
      to uniquely identify a service
      '''

      port = s['port']

      application_protocol = None

      if s['severity'] == 'INFO':
        application_protocol = s['finding']

      identifier = f"{host}:{port} ({self.transport_protocol})"

      if identifier in self.services:
        continue

      service = copy.deepcopy(SERVICE_SCHEMA)
      self.services[identifier] = service

      service['host'] = host
      service['port'] = port
      service['application_protocol'] = application_protocol

      findings = list(
        filter(
          lambda x: x['ip'].startswith(host) and x['port'] == port,
          results
        )
      )

      certificate = copy.deepcopy(CERTIFICATE_SCHEMA)
      service['certificates'].append(certificate)

      for f in findings:

        # protocol versions
        if f['id'] in PROTOCOL_VERSIONS and f['finding'].startswith('offered'):
          service['protocol_versions'].append(PROTOCOL_VERSIONS[f['id']])
          continue

        # certificate public key
        if f['id'] == 'cert_keySize':
          self._parse_public_key(
            f['finding'],
            certificate['public_key']
          )
          continue

        # certificate signature algorithms
        if f['id'] == 'cert_signatureAlgorithm':
          self._parse_signature_algorithm(
            f['finding'],
            certificate['signature_algorithm']
          )
          continue

        # certificate subjects

        if f['id'] == 'cert_commonName':
          self._parse_common_name(
            f['finding'],
            certificate['subjects']
          )
          continue

        if f['id'] == 'cert_subjectAltName':
          self._parse_subject_alt_names(
            f['finding'],
            certificate['subjects']
          )
          continue

        # certificate validity

        if f['id'] == 'cert_notBefore':
          certificate['validity']['not_before'] = self._parse_validity(f['finding'])
          continue

        if f['id'] == 'cert_notAfter':
          certificate['validity']['not_after'] = self._parse_validity(f['finding'])
          continue

        # groups (elliptic curve groups, finite field DH groups)
        if f['id'] == 'PFS_ECDHE_curves':
          self._parse_groups(
            f['finding'],
            service['key_exchange']['groups']
          )
          continue

        # preference

        # 1. client sends a list of cipher suites it supports
        # 2. server has two strategies to choose a cipher suite:
        #   a. use the client's preference of ciphers
        #   b. use its own preference
        if f['id'] == 'cipher_order':
          service['preference'] = self._parse_preference(f['finding'])
          continue

        if f['id'].startswith('cipher_x'):
          self._parse_cipher_suite(
            f['finding'],
            service['cipher_suites'],
            service['key_exchange']
          )
          continue

        # TLS extensions
        # https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
        if f['id'] == 'TLS_extensions':
          self._parse_extensions(
            f['finding'],
            service['extensions']
          )
          continue

        # misc. information about the server/certificate/etc
        service['misc'] = {}

        if f['id'] == 'fallback_SCSV' and f['severity'] not in ('OK', 'INFO'):
          service['misc']['fallback_SCSV'] = f['finding']
          continue

        if f['id'] == 'HSTS_time':
          service['misc']['HSTS'] = self._parse_HSTS_time(f['finding'])
          continue

        # vulnerabilities

        if f['id'] == 'secure_client_renego' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append(Issue("vuln: client-initiated renegotiation DoS"))
          continue

        if f['id'] == 'BEAST' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append(Issue("vuln: BEAST"))
          continue

        if f['id'] == 'CRIME_TLS' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append(Issue("vuln: CRIME"))
          continue

        if f['id'] == 'BREACH' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append(Issue("vuln: BREACH"))
          continue

        if f['id'] == 'LUCKY13' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append(Issue("vuln: Lucky Thirteen"))
          continue

        if f['id'] == 'heartbleed' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append(Issue("vuln: Heartbleed"))
          continue

        if f['id'] == 'POODLE_SSL' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append(Issue("vuln: POODLE"))
          continue

        if f['id'] == 'CCS' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append(Issue("vuln: OpenSSL CCS injection"))
          continue

        if f['id'] == 'FREAK' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append(Issue("vuln: FREAK"))
          continue

        if f['id'] == 'LOGJAM' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append(Issue("vuln: Logjam"))
          continue

        if f['id'] == 'DROWN' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append(Issue("vuln: DROWN"))
          continue

        # https://sweet32.info/
        # support of DES/3DES
        if f['id'] == 'SWEET32' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append(Issue("vuln: Sweet32"))
          continue

        if f['id'] == 'ticketbleed' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append(Issue("vuln: Ticketbleed"))
          continue

        # https://www.robotattack.org/
        # use of RSA for key exchange
        if f['id'] == 'ROBOT' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append(Issue("vuln: ROBOT"))
          continue

        # (other) issues

        if f['id'] == 'cert_trust':
          if f['severity'] not in ('OK', 'INFO'):
            service['issues'].append(
              Issue(
                "certificate: not trusted",
                info = f['finding']
              )
            )
          continue

        if f['id'] == 'cert_chain_of_trust':
          if f['severity'] not in ('OK', 'INFO'):
            service['issues'].append(
              Issue(
                "certificate: not trusted",
                info = self._parse_chain_of_trust(f['finding'])
              )
            )
          continue

  def _parse_public_key(self, description, public_key):
    # example description: 'RSA 4096 bits (exponent is 65537)'
    key_type, key_bits, *_ = description.split(' ')

    if key_type == 'EC':
      key_type = 'ECDSA'

    key_bits = int(key_bits)

    public_key['type'] = key_type
    public_key['bits'] = key_bits

  def _parse_signature_algorithm(self, description, signature_algorithm):
    # SHA256 with RSA
    # SHA256 with ECDSA
    sig = description.split(' ')

    if 'RSA' in sig:
      # https://www.rfc-editor.org/rfc/rfc3447.html#appendix-A.2
      signature_algorithm = f'{sig[0].lower()}WithRSAEncryption'
    elif 'EC' in sig:
      # https://www.rfc-editor.org/rfc/rfc5480.html#appendix-A
      signature_algorithm = f'{sig[2].lower()}-with-{sig[0].upper()}'

  def _parse_common_name(self, description, subjects):
    subject = description.strip()
    if subject not in subjects:
      subjects.append(subject)

  def _parse_subject_alt_names(self, description, subjects):
    for subject in description.split(' '):
      subject = subject.strip()
      if subject not in subjects:
        subjects.append(subject)

  def _parse_validity(self, description):
    return f"{description}:00"

  def _parse_groups(self, description, groups):
    for group in description.split(' '):
      if group == 'X25519':
        group = 'x25519'

      groups.append(group)

  def _parse_preference(self, description):
    if description.startswith('server'):
      return 'server'
    elif description.startswith('client'):
      return 'client'

  def _parse_cipher_suite(self, description, cipher_suites, key_exchange):
    #         cipher suite                                      kex
    # xc02c   TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384           ECDH 253   AESGCM      256
    # x9f     TLS_DHE_RSA_WITH_AES_256_GCM_SHA384               DH 512     AESGCM      256
    session_info = re.split('   +', description)

    #print(description)

    cipher_suite = session_info[1]
    cipher_suites.append(cipher_suite)

    kex = session_info[2]

    if ' ' in kex:
      parts = kex.split(' ')
      kex = (parts[0], int(parts[1]))
    else:
      kex = (kex, None)

    kex_methods = key_exchange['methods']
    if kex[0] not in kex_methods:
      kex_methods[kex[0]] = kex[1]
    elif kex[1] and kex_methods[kex[0]] and kex[1] < kex_methods[kex[0]]:
      kex_methods[kex[0]] = kex[1]

  def _parse_extensions(self, description, extensions):
    m = re.findall(
      r"'([^/]+)/#\d+'",
      description
    )

    for ext in m:
      extension = ext.lower().replace(' ', '_')
      if extension not in extensions:
        extensions.append(extension)

  def _parse_HSTS_time(self, description):
    m = re.search(
      r'\(=(?P<time>\d+) seconds\)',
      description
    )

    if m:
      return int(m.group('time'))

    return None

  def _parse_chain_of_trust(self, description):
    m = re.search(
      r'\((?P<reason>[^)]+)\)',
      description
    )

    if m:
      return m.group('reason')

    return description
