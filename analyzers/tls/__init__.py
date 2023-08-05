import datetime
import ipaddress
import json
import pathlib
import sys

try:
  # https://github.com/uiri/toml
  import toml
except:
  sys.exit("this script requires the 'toml' module.\nplease install it via 'pip3 install toml'.")

vulnerabilities_specification_document = pathlib.Path(
  pathlib.Path(__file__).resolve().parent,
  "vulnerabilities.toml"
  )

with open(vulnerabilities_specification_document, 'r') as f:
  VULNERABILITIES = toml.load(f)

from .. import Issue, AbstractAnalyzer

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

SERVICE_SCHEMA = {
  'host': None, # hostname or IP address
  'port': None, # port number

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
}

# path to the cipher suites specification document; downloaded from https://ciphersuite.info/api/cs/
cipher_suites_specifications_document = pathlib.Path(
  pathlib.Path(__file__).resolve().parent,
  "cipher_suites.json"
)

# load cipher suites specifications
CIPHER_SUITES_SPECIFICATIONS = {}
with open(cipher_suites_specifications_document) as f:
  for cs in json.load(f)['ciphersuites']:
    for name in cs:
      CIPHER_SUITES_SPECIFICATIONS[name] = cs[name]

class Analyzer(AbstractAnalyzer):

  def __init__(self, name, recommendations):
    super().__init__(name, recommendations)

    self.set_parser('testssl')

  def set_parser(self, tool):
    super().set_parser(tool)
    self.parser.cipher_suites_specifications = CIPHER_SUITES_SPECIFICATIONS

  def analyze(self, files):
    super().analyze(files)

    # parse result files
    services = self.parser.parse_files(files[self.parser_name])
    self.services = services

    # analyze services based on recommendations
    for identifier, service in services.items():
      issues = service['issues']

      # protocol versions
      if 'protocol_versions' in self.recommendations:
        self._analyze_protocol_versions(
          service['protocol_versions'],
          self.recommendations['protocol_versions'],
          issues
        )

      # certificates
      if 'certificate' in self.recommendations:
        try:
          is_private_host = ipaddress.ip_address(service['host']).is_private
        except ValueError:
          # host is NOT a valid IP address
          is_private_host = False

        for certificate in service['certificates']:
          self._analyze_certificate(
            is_private_host,
            certificate,
            self.recommendations['certificate'],
            issues
          )

      # preference
      if 'preference' in self.recommendations:
        self._analyze_preference(
          service['preference'],
          self.recommendations['preference'],
          issues
        )

      # cipher suites
      if 'cipher_suites' in self.recommendations:
        self._analyze_cipher_suites(
          service['cipher_suites'],
          self.recommendations['cipher_suites'],
          issues
        )

      # key exchange
      if 'key_exchange' in self.recommendations:
        self._analyze_key_exchange(
          service['key_exchange'],
          self.recommendations['key_exchange'],
          issues
        )

      # signature algorithms
      if 'signature_algorithms' in self.recommendations:
        self._analyze_signature_algorithms(
          service['signature_algorithms'],
          self.recommendations['signature_algorithms'],
          issues
        )

      # extensions
      if 'extensions' in self.recommendations:
        self._analyze_extensions(
          service['extensions'],
          self.recommendations['extensions'],
          issues
        )

    return services

  def _analyze_protocol_versions(self, protocol_versions, recommendation, issues):
    for deviation in list(set(protocol_versions).difference(recommendation)):
      issues.append(
        Issue(
          "protocol: supported",
          protocol = deviation
        )
      )

    for deviation in list(set(recommendation).difference(protocol_versions)):
      issues.append(
        Issue(
          "protocol: not supported",
          protocol = deviation
        )
      )

  def _analyze_certificate(self, is_private_host, certificate, recommendation, issues):
    if certificate == CERTIFICATE_SCHEMA:
      issues.append(Issue("certificate: none"))
      return

    if not is_private_host:
      # analyze certificate subjects for private IP addresses
      for subject in certificate['subjects']:
        try:
          if ipaddress.ip_address(subject).is_private:
            issues.append(
              Issue(
                "certificate: private IP address",
                address = subject
              )
            )
        except ValueError:
          # subject is NOT a valid IP address
          continue

    validity = certificate['validity']

    not_before = datetime.datetime.fromisoformat(validity['not_before'])
    not_after = datetime.datetime.fromisoformat(validity['not_after'])
    livespan = not_after - not_before
    livespan_in_days = int(livespan.total_seconds() / (24 * 60 * 60))

    if livespan_in_days > recommendation['lifespan']:
      issues.append(
        Issue(
          "certificate: lifespan",
          lifespan = livespan_in_days
        )
      )

    pub_key = certificate['public_key']

    if pub_key['type'] not in recommendation['public_key']['types']:
      issues.append(
        Issue(
          "certificate: public key",
          key_info = pub_key['type']
        )
      )
    else:
      if pub_key['bits'] and pub_key['bits'] < recommendation['public_key']['types'][pub_key['type']]:
        issues.append(
          Issue(
            "certificate: public key",
            key_info = f"{pub_key['type']} {pub_key['bits']} bits"
          )
        )

    if pub_key['curve'] and pub_key['curve'] not in recommendation['public_key']['curves']:
      issues.append(
        Issue(
          "certificate: public key: curve",
          curve = pub_key['curve']
        )
      )

    sig_alg = certificate['signature_algorithm']

    if sig_alg and sig_alg not in recommendation['signature_algorithms']:
      issues.append(
        Issue(
          "certificate: signature algorithm",
          algorithm = sig_alg
        )
      )

  def _analyze_preference(self, preference, recommendation, issues):
    if not preference == recommendation:
      issues.append(
        Issue(
          "cipher preference",
          preference = preference
        )
      )

  def _analyze_cipher_suites(self, cipher_suites, recommendation, issues):
    if len(cipher_suites) == 0:
      issues.append(
        Issue(
          "cipher suites: none"
        )
      )
      return

    for deviation in list(set(cipher_suites).difference(recommendation)):
      issues.append(
        Issue(
          "cipher suites: supported",
          cipher_suite = deviation
        )
      )

  def _analyze_key_exchange(self, key_exchange, recommendation, issues):
    for kex_method, kex_bits in key_exchange['methods'].items():
      if kex_method not in recommendation['methods']:
        issues.append(
          Issue(
            "key exchange",
            info = kex_method
          )
        )
        continue

      if kex_bits and kex_bits < recommendation['methods'][kex_method]:
        issues.append(
          Issue(
            "key exchange",
            info = f"{kex_method} {kex_bits} bits"
          )
        )

    for deviation in list(set(key_exchange['groups']).difference(recommendation['groups'])):
      issues.append(
        Issue(
          "key exchange: group",
          group = deviation
        )
      )

  def _analyze_signature_algorithms(self, signature_algorithms, recommendation, issues):
    for deviation in list(set(signature_algorithms).difference(recommendation)):
      if deviation == '*':
        issues.append(
          Issue(
            "signature algorithm",
            info = "server accepts any signature algorithm"
          )
        )
      else:
        issues.append(
          Issue(
            "signature algorithm",
            info = f"`{deviation}`"
          )
        )

  def _analyze_extensions(self, extensions, recommendation, issues):
    if 'yes' in recommendation:
      for deviation in list(set(recommendation['yes']).difference(extensions)):
        issues.append(
          Issue(
            "extensions: not supported",
            extension = deviation
          )
        )

    if 'no' in extensions:
      for deviation in list(set(extensions).intersection(recommendation['no'])):
        issues.append(
          Issue(
            "extensions: supported",
            extension = deviation
          )
        )
