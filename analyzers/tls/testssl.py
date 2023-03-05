import copy
import json
import pathlib
import re

from . import SERVICE_SCHEMA

PROTOCOL_VERSIONS = {
  'SSLv2': 'SSL 2',
  'SSLv3': 'SSL 3',
  'TLS1': 'TLS 1',
  'TLS1_1': 'TLS 1.1',
  'TLS1_2': 'TLS 1.2',
  'TLS1_3': 'TLS 1.3'
}

class Parser:
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

  name = 'testssl'
  file_type = 'json'

  def __init__(self, cipher_suites_specifications):
    self.services = {}
    self.cipher_suites_specifications = cipher_suites_specifications

  def parse_files(self, files):
    for path in files[self.file_type]:
      self.parse_file(path)

    return self.services

  def parse_file(self, path):

    with open(path, 'r') as f:
      results = json.load(f)

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

      identifier = f"{host}:{port}"

      if identifier in self.services:
        continue

      service = copy.deepcopy(SERVICE_SCHEMA)
      self.services[identifier] = service

      service['application_protocol'] = application_protocol

      findings = list(
        filter(
          lambda x: x['ip'].startswith(host) and x['port'] == port,
          results
        )
      )

      for f in findings:
        if f['id'] in PROTOCOL_VERSIONS and f['finding'].startswith('offered'):
          service['protocol_versions'].append(PROTOCOL_VERSIONS[f['id']])
          continue

        if f['id'] == 'cert_keySize':
          service['certificate']['public_key'] = self.parse_key_size(f['finding'])
          continue

        if f['id'] == 'cert_signatureAlgorithm':
          service['certificate']['signature_algorithm'] = self.parse_signature_algorithm(f['finding'])
          continue

        if f['id'] == 'cert_commonName':
          subject = f['finding'].strip()
          if subject not in service['certificate']['subjects']:
            service['certificate']['subjects'].append(subject)
          continue

        if f['id'] == 'cert_subjectAltName':
          for subject in f['finding'].split(' '):
            if subject not in service['certificate']['subjects']:
              service['certificate']['subjects'].append(subject)
          continue

        if f['id'] == 'cert_notBefore':
          service['certificate']['validity']['not_before'] = f"{f['finding']}:00"
          continue

        if f['id'] == 'cert_notAfter':
          service['certificate']['validity']['not_after'] = f"{f['finding']}:00"
          continue

        if f['id'] == 'PFS_ECDHE_curves':
          service['cipher_suites']['elliptic_curves'] = f['finding'].split(' ')
          continue

        # 1. client sends a list of cipher suites it supports
        # 2. server has two strategies to choose a cipher suite:
        #   a. use the client's preference of ciphers
        #   b. use its own preference
        if f['id'] == 'cipher_order':
          if f['finding'].startswith('server'):
            service['cipher_suites']['preference'] = 'server'
          if f['finding'].startswith('client'):
            service['cipher_suites']['preference'] = 'client'
          continue

        if f['id'].startswith('cipher_x'):
          service['cipher_suites']['list'].append(self.parse_cipher_suite(f['finding']))
          continue

        # TLS extensions
        # https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml

        if f['id'] == 'TLS_extensions':
          service['extensions'] = self.parse_TLS_extensions(f['finding'])
          continue

        # misc. information about the server/certificate/etc

        if f['id'] == 'fallback_SCSV' and f['severity'] not in ('OK', 'INFO'):
          service['misc']['fallback_SCSV'] = f['finding']
          continue

        if f['id'] == 'HSTS_time':
          service['misc']['HSTS'] = self.parse_HSTS_time(f['finding'])
          continue

        # vulnerabilities

        # https://www.rfc-editor.org/rfc/rfc5746.html#section-4.4
        # legacy (insecure) renegotiation
        if f['id'] == 'secure_client_renego' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append('vulnerable to client-initiated renegotiation DoS (CVE-2011-1473)')
          continue

        # https://en.wikipedia.org/wiki/Transport_Layer_Security#BEAST_attack
        # CBC vulnerability in TLS1
        if f['id'] == 'BEAST' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append('potentially vulnerable to BEAST (Browser Exploit Against SSL/TLS): ciphers in CBC mode with TLS 1')
          continue

        # https://en.wikipedia.org/wiki/CRIME
        # server accepts TLS compression, or uses SPDY header compression
        if f['id'] == 'CRIME_TLS' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append('vulnerable to CRIME (Compression Ratio Info-leak Made Easy): TLS compression or SPDY header compression')
          continue

        # https://www.breachattack.com/
        # HTTP compression
        if f['id'] == 'BREACH' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append('potentially vulnerable to BREACH: HTTP compression detected')
          continue

        # https://en.wikipedia.org/wiki/Lucky_Thirteen_attack
        # certain implementations of the TLS protocol that use the CBC mode of operation are vulnerable
        if f['id'] == 'LUCKY13' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append('potentially vulnerable to Lucky Thirteen (CVE-2013-0169): ciphers in CBC mode')
          continue

        # https://heartbleed.com/
        # vulnerable version of heartbeat TLS extension
        if f['id'] == 'heartbleed' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append('vulnerable to Heartbleed (CVE-2014-0160): vulnerable version of the heartbeat TLS extension (OpenSSL 1.0.1 through 1.0.1f)')
          continue

        # https://en.wikipedia.org/wiki/POODLE
        # legacy protocols (SSL 3)
        if f['id'] == 'POODLE_SSL' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append('vulnerable to POODLE (Padding Oracle On Downgraded Legacy Encryption; CVE-2014-3566): SSL 3')
          continue

        # https://www.imperialviolet.org/2014/06/05/earlyccs.html
        # this is an attack against implementations of the ChangeCipherSpec (CCS) in outdated versions of OpenSSL
        if f['id'] == 'CCS' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append('vulnerable to CCS (ChangeCipherSpec) injection (CVE-2014-0224): outdated version of OpenSSL')
          continue

        # https://en.wikipedia.org/wiki/FREAK
        # server supports RSA with moduli of 512 bits or less,
        if f['id'] == 'FREAK' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append('vulnerable to FREAK (Factoring RSA Export Keys; CVE-2015-0204): RSA with moduli of 512 bits or less')
          continue

        # https://weakdh.org/
        # Logjam (CVE-2015-4000), weak DH keys
        if f['id'] == 'LOGJAM' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append('vulnerable to Logjam (CVE-2015-4000): weak DH keys')
          continue

        # https://drownattack.com/
        # server supports SSL 2
        if f['id'] == 'DROWN' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append('vulnerable to DROWN (Decrypting RSA with Obsolete and Weakened eNcryption; CVE-2016-0800): SSL 2')
          continue

        # https://sweet32.info/
        # support of DES/3DES
        if f['id'] == 'SWEET32' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append('vulnerable to Sweet32 (CVE-2016-2183, CVE-2016-6329): DES/3DES')
          continue

        # https://filippo.io/Ticketbleed/
        # vulnerable implementation of Session Tickets
        if f['id'] == 'ticketbleed' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append('vulnerable to Ticketbleed (CVE-2016-9244): insecure implementation for handling Session Tickets')
          continue

        # https://www.robotattack.org/
        # use of RSA for key exchange
        if f['id'] == 'ROBOT' and f['severity'] not in ('OK', 'INFO'):
          service['issues'].append("vulnerable to ROBOT (Return Of Bleichenbacher's Oracle Threat; CVE-2017-13099): RSA for key exchange")
          continue

        # other issues

        if f['id'] == 'cert_trust':
          if f['severity'] not in ('OK', 'INFO'):
            issue = f"certificate not trusted: {f['finding']}"
            service['issues'].append(issue)
          continue

        if f['id'] == 'cert_chain_of_trust':
          if f['severity'] not in ('OK', 'INFO'):
            issue = f"certificate not trusted: {self.parse_chain_of_trust(f['finding'])}"
            service['issues'].append(issue)
          continue

  def parse_key_size(self, description):
    key_type, key_size, _ = description.split(' ')

    if key_type == 'EC':
      key_type = 'ECDSA'

    return {
      'type': key_type,
      'size': int(key_size)
    }

  def parse_signature_algorithm(self, description):
    sig = description.split(' ')

    if 'RSA' in sig:
      # https://www.rfc-editor.org/rfc/rfc3447.html#appendix-A.2
      return f'{sig[0].lower()}WithRSAEncryption'
    elif 'EC' in sig:
      # https://www.rfc-editor.org/rfc/rfc5480.html#appendix-A
      return f'{sig[2].lower()}-with-{sig[0].upper()}'

  def parse_cipher_suite(self, description):
    parts = re.split('   +', description)

    name = parts[1]
    cipher_suite = self.cipher_suites_specifications[name]

    # CIPHER_SUITE_SCHEMA
    return {
      'name': name,
      'key_exchange_algorithm': parts[2],
      'authentication_algorithm': cipher_suite['auth_algorithm'],
      'encryption_algorithm': cipher_suite['enc_algorithm'],
      'hash_algorithm': name.split('_')[-1],
    }

  def parse_TLS_extensions(self, description):
    m = re.findall(
      r"'([^/]+)/#\d+'",
      description
    )

    extensions = []
    for ext in m:
      extension = ext.lower().replace(' ', '_')
      if extension not in extensions:
        extensions.append(extension)

    return extensions

  def parse_HSTS_time(self, description):
    m = re.search(
      r'\(=(?P<time>\d+) seconds\)',
      description
    )

    if m:
      return int(m.group('time'))

    return None

  def parse_chain_of_trust(self, description):
    m = re.search(
      r'\((?P<reason>[^)]+)\)',
      description
    )

    if m:
      return m.group('reason')

    return description
