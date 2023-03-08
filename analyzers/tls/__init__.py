import csv
import datetime
import json
import pathlib
import sys

CERTIFICATE_SCHEMA = {
  'subjects': [],
  # common name, subject alternative names

  'public_key': {
    'type': None, # e.g. "RSA" or "ECDSA"
    'bits': None, # e.g. 2048 or 256
    'curve': None, # e.g. "prime256v1"
  },

  'signature_algorithm': None,
  # e.g. "sha256WithRSAEncryption", "ecdsa-with-SHA256"
  # RSA: https://www.rfc-editor.org/rfc/rfc3279#section-2.2.1
  # ECDSA: https://www.rfc-editor.org/rfc/rfc3279#section-2.2.3
  # RSA: https://www.rfc-editor.org/rfc/rfc4055#section-5
  # ECDSA: https://www.rfc-editor.org/rfc/rfc5758#section-3.2

  'validity': {
    'not_before': None, # "YYYY-MM-DD hh:mm:ss" UTC
    'not_after': None,
  },
}


VULNERABILITIES = {

  # legacy (insecure) renegotiation
  'client-initiated renegotiation DoS': {
    'description': 'vulnerable to client-initiated renegotiation DoS',
    'CVE': [ 'CVE-2011-1473' ],
    'references': [ 'https://www.rfc-editor.org/rfc/rfc5746.html#section-4.4' ]
  },

  # CBC vulnerability in SSL 3.0 and TLS 1.0
  'BEAST': {
    'description': 'potentially vulnerable to BEAST (Browser Exploit Against SSL/TLS): ciphers in CBC mode with SSL 3.0 or TLS 1.0',
    'CVE': [ 'CVE-2011-3389' ],
    'references': [ 'https://web.archive.org/web/20140603102506/https://bug665814.bugzilla.mozilla.org/attachment.cgi?id=540839' ]
  },

  # server accepts TLS compression, or uses SPDY header compression
  'CRIME': {
    'description': 'vulnerable to CRIME (Compression Ratio Info-leak Made Easy): TLS compression or SPDY header compression',
    'CVE': [ 'CVE-2012-4929' ],
    'references': [ 'https://en.wikipedia.org/wiki/CRIME' ]
  },

  # HTTP compression
  'BREACH': {
    'description': 'potentially vulnerable to BREACH: HTTP compression detected',
    'CVE': [ 'CVE-2013-3587' ],
    'references': [ 'https://www.breachattack.com/' ]
  },

  # certain implementations of the TLS protocol that use the CBC mode of operation are vulnerable
  'Lucky Thirteen': {
    'description': 'potentially vulnerable to Lucky Thirteen: ciphers in CBC mode',
    'CVE': [ 'CVE-2013-0169' ],
    'references': [ 'https://en.wikipedia.org/wiki/Lucky_Thirteen_attack' ]
  },

  # vulnerable version of heartbeat TLS extension
  'Heartbleed': {
    'description': 'vulnerable to Heartbleed: vulnerable version of the heartbeat TLS extension (OpenSSL 1.0.1 through 1.0.1f)',
    'CVE': [ 'CVE-2014-0160' ],
    'references': [ 'https://heartbleed.com/' ]
  },

  # legacy protocols (SSL 3)
  'POODLE': {
    'description': 'vulnerable to POODLE (Padding Oracle On Downgraded Legacy Encryption): SSL 3.0',
    'CVE': [ 'CVE-2014-3566' ],
    'references': [ 'https://en.wikipedia.org/wiki/POODLE' ]
  },

  # this is an attack against implementations of the ChangeCipherSpec (CCS) in outdated versions of OpenSSL
  'OpenSSL CCS injection': {
    'description': 'vulnerable to CCS (ChangeCipherSpec) injection: outdated version of OpenSSL',
    'CVE': [ 'CVE-2014-0224' ],
    'references': [ 'https://www.imperialviolet.org/2014/06/05/earlyccs.html' ]
  },

  # server supports RSA with moduli of 512 bits or less
  'FREAK': {
    'description': 'vulnerable to FREAK (Factoring RSA Export Keys): RSA with moduli of 512 bits or less',
    'CVE': [ 'CVE-2015-0204' ],
    'references': [ 'https://en.wikipedia.org/wiki/FREAK' ]
  },

  # weak DH keys
  'Logjam': {
    'description': 'vulnerable to Logjam: weak DH keys',
    'CVE': [ 'CVE-2015-4000' ],
    'references': [ 'https://weakdh.org/' ]
  },

  # server supports SSL 2
  'DROWN': {
    'description': 'vulnerable to DROWN (Decrypting RSA with Obsolete and Weakened eNcryption): SSL 2.0',
    'CVE': [ 'CVE-2016-0800' ],
    'references': [ 'https://drownattack.com/' ]
  },

  # support of DES/3DES
  'Sweet32': {
    'description': 'vulnerable to Sweet32: DES/3DES',
    'CVE': [ 'CVE-2016-2183', 'CVE-2016-6329' ],
    'references': [ 'https://sweet32.info/' ]
  },

  # vulnerable implementation of Session Tickets
  'Ticketbleed': {
    'description': 'vulnerable to Ticketbleed: insecure implementation for handling Session Tickets',
    'CVE': [ 'CVE-2016-9244' ],
    'references': [ 'https://filippo.io/Ticketbleed/' ]
  },

  # use of RSA for key exchange
  'ROBOT': {
    'description': "vulnerable to ROBOT (Return Of Bleichenbacher's Oracle Threat): RSA for key exchange",
    'CVE': [ 'CVE-2017-13099' ],
    'references': [ 'https://www.robotattack.org/' ]
  },

  'VULNERABILITY': {
    'description': '',
    'CVE': [],
    'references': [ '' ]
  },

}

SERVICE_SCHEMA = {
  'application_protocol': None,
  # e.g. "HTTP", "FTP"

  'protocol_versions': [],
  # e.g. "SSL 2", "SSL 3", "TLS 1", "TLS 1.1", "TLS 1.3"

  'certificates': [], # a host can hold multiple (different) certificates

  'preference': None, # e.g. "server" or "client"

  'cipher_suites': [], # e.g. "TLS_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"

  'key_exchange': {
    'methods': {}, # e.g. "DH": 2048, "ECDH": 253, "RSA": None
    'groups': [],
    # e.g. "x25519", "prime256v1", "secp384r1", "ffdhe2048"
    # EC groups, finite field DH groups
    # https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
    # "prime256v1": https://www.rfc-editor.org/rfc/rfc3279#section-3
  },

  'signature_algorithms': [],
  # e.g. "ecdsa_secp256r1_sha256", "rsa_pkcs1_sha1"
  # https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme

  'extensions': [], # e.g. "status_request"
  # https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1

  'issues': [],

  'vulnerabilities': [],
}

class Analyzer:

  # downloaded from https://ciphersuite.info/api/cs/
  cipher_suites_specifications_document = pathlib.Path(
    pathlib.Path(__file__).resolve().parent,
    "cipher_suites.json"
  )

  def __init__(self, tool, recommendations):
    self.tool = tool
    self.recommendations = recommendations

    self.services = []

    if self.tool == 'testssl':
      from .testssl import Parser
    elif self.tool == 'sslscan':
      from .sslscan import Parser
    elif self.tool == 'sslyze':
      from .sslyze import Parser
    else:
      sys.exit(f"unknown tool '{self.tool}'")

    # load cipher suites specifications
    cipher_suites_specifications = {}
    with open(Analyzer.cipher_suites_specifications_document, 'r') as f:
      for cs in json.load(f)['ciphersuites']:
        for name in cs:
          cipher_suites_specifications[name] = cs[name]

    self.parser = Parser(cipher_suites_specifications)

  def analyze(self, files):
    # parse result files
    services = self.parser.parse_files(files[self.tool])
    self.services = services

    #print(json.dumps(services, indent=2))

    # analyze services based on recommendations
    for identifier, service in services.items():
      issues = service['issues']

      # protocol versions
      if 'protocol_versions' in self.recommendations:
        self.analyze_protocol_versions(
          service['protocol_versions'],
          self.recommendations['protocol_versions'],
          issues
        )

      # certificates
      if 'certificate' in self.recommendations:
        for certificate in service['certificates']:
          self.analyze_certificate(
            certificate,
            self.recommendations['certificate'],
            issues
          )

      # preference
      if 'preference' in self.recommendations:
        self.analyze_preference(
          service['preference'],
          self.recommendations['preference'],
          issues
        )

      # cipher suites
      if 'cipher_suites' in self.recommendations:
        self.analyze_cipher_suites(
          service['cipher_suites'],
          self.recommendations['cipher_suites'],
          issues
        )

      # key exchange
      if 'key_exchange' in self.recommendations:
        self.analyze_key_exchange(
          service['key_exchange'],
          self.recommendations['key_exchange'],
          issues
        )

      # signature algorithms
      if 'signature_algorithms' in self.recommendations:
        self.analyze_signature_algorithms(
          service['signature_algorithms'],
          self.recommendations['signature_algorithms'],
          issues
        )

      # extensions
      if 'extensions' in self.recommendations:
        self.analyze_extensions(
          service['extensions'],
          self.recommendations['extensions'],
          issues
        )

      # analyze vulnerabilities
      for vulnerability_ID in service['vulnerabilities']:
        vulnerability = VULNERABILITIES[vulnerability_ID]
        # TODO: add CVE, references?
        issues.append(vulnerability['description'])

    return services

  def analyze_protocol_versions(self, protocol_versions, recommendation, issues):
    for deviation in list(set(protocol_versions).difference(recommendation)):
      issues.append(f"protocol supported: {deviation}")

    for deviation in list(set(recommendation).difference(protocol_versions)):
      issues.append(f"protocol not supported: {deviation}")

  def analyze_certificate(self, certificate, recommendation, issues):
    validity = certificate['validity']

    not_before = datetime.datetime.fromisoformat(validity['not_before'])
    not_after = datetime.datetime.fromisoformat(validity['not_after'])
    livespan = not_after - not_before
    livespan_in_days = int(livespan.total_seconds() / (24 * 60 * 60))

    if livespan_in_days > recommendation['lifespan']:
      issues.append(f"certificate lifespan: {livespan_in_days} days")

    pub_key = certificate['public_key']

    if pub_key['type'] not in recommendation['public_key']['types']:
      if pub_key['bits']:
        issues.append(f"server's public key: {pub_key['type']} {pub_key['bits']} bits")
      else:
        issues.append(f"server's public key: {pub_key['type']}")
    else:
      if pub_key['bits'] and pub_key['bits'] < recommendation['public_key']['types'][pub_key['type']]:
        issues.append(f"server's public key: {pub_key['type']} {pub_key['bits']} bits")

    if pub_key['curve'] and pub_key['curve'] not in recommendation['public_key']['curves']:
      issues.append(f"server's public key: curve `{pub_key['curve']}`")

    sig_alg = certificate['signature_algorithm']

    if sig_alg and sig_alg not in recommendation['signature_algorithms']:
      issues.append(f"server's certificate: signature algorithm `{sig_alg}`")

  def analyze_preference(self, preference, recommendation, issues):
    if not preference == recommendation:
      issues.append(f"cipher preference: {preference}")

  def analyze_cipher_suites(self, cipher_suites, recommendation, issues):
    for deviation in list(set(cipher_suites).difference(recommendation)):
      issues.append(f"cipher suite supported: `{deviation}`")

  def analyze_key_exchange(self, key_exchange, recommendation, issues):
    for kex_method, kex_bits in key_exchange['methods'].items():
      if kex_method not in recommendation['methods']:
        issue = f"key exchange: {kex_method}"
        if kex_bits:
          issue += f" {kex_bits} bits"

        issues.append(issue)
        continue

      if kex_bits and kex_bits < recommendation['methods'][kex_method]:
        issues.append(f"key exchange: {kex_method} {kex_bits} bits")

    for deviation in list(set(key_exchange['groups']).difference(recommendation['groups'])):
      issues.append(f"key exchange: group `{deviation}`")

  def analyze_signature_algorithms(self, signature_algorithms, recommendation, issues):
    for deviation in list(set(signature_algorithms).difference(recommendation)):
      if deviation == '*':
        issues.append("server accepts any signature algorithm")
      else:
        issues.append(f"signature algorithm: `{deviation}`")

  def analyze_extensions(self, extensions, recommendation, issues):
    if 'yes' in recommendation:
      for deviation in list(set(recommendation['yes']).difference(extensions)):
        issues.append(f"extension not supported: `{deviation}`")

    if 'no' in extensions:
      for deviation in list(set(extensions).intersection(recommendation['no'])):
        issues.append(f"extension supported: `{deviation}`")

  def save_CSV(self, path, tool):
    delimiter = ','
    header = ['tool', 'asset', 'issues']

    with open(path, 'w') as f:
      csv.writer(f, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL).writerow(header)

      for identifier, service in self.services.items():
        for issue in service['issues']:
          row = [tool, identifier, issue]
          csv.writer(f, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL).writerow(row)
