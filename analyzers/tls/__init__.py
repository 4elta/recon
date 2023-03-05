import csv
import datetime
import json
import pathlib
import sys

SERVICE_SCHEMA = {
  'application_protocol': None,
  'protocol_versions': [], # "SSL 2", "SSL 3", "TLS 1", "TLS 1.1", "TLS 1.3"
  'certificate': {
    'public_key': None,
    'elliptic_curve': None,
    'signature_algorithm': None,
    'subjects': [], # common name, subject alternative names
    'validity': {
      'not_before': None, # YYYY-MM-DD hh:mm:ss UTC
      'not_after': None,
    },
  },
  'cipher_suites': {
    'elliptic_curves': [],
    'preference': None, # server or client
    'list': [], # cipher suites
  },
  'extensions': [],
  'misc': {},
  'issues': [],
}

PUBLIC_KEY_SCHEMA = {
  'type': None,
  'size': None
}

CIPHER_SUITE_SCHEMA = {
  'name': None, # IANA name
  'key_exchange_algorithm': None,
  'authentication_algorithm': None,
  'encryption_algorithm': None,
  'hash_algorithm': None,
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

      for protocol_version in service['protocol_versions']:
        if protocol_version not in self.recommendations['protocol_versions']:
          issues.append(f"protocol supported: {protocol_version}")

      for protocol_version in self.recommendations['protocol_versions']:
        if protocol_version not in service['protocol_versions']:
          issues.append(f"protocol not supported: {protocol_version}")

      cert = service['certificate']
      reco = self.recommendations['certificate']

      validity = cert['validity']
      not_before = datetime.datetime.fromisoformat(validity['not_before'])
      not_after = datetime.datetime.fromisoformat(validity['not_after'])
      livespan = not_after - not_before
      livespan_in_days = int(livespan.total_seconds() / (24 * 60 * 60))

      if livespan_in_days > reco['lifespan']:
        issues.append(f"certificate lifespan: {livespan_in_days} days")

      pub_key = cert['public_key']
      if pub_key and (pub_key['type'] not in reco['minimum_key_length'] or pub_key['size'] < reco['minimum_key_length'][pub_key['type']]):
        issues.append(f"server's public key: {pub_key['type']} {pub_key['size']} bits")

      ec = cert['elliptic_curve']
      if ec and ec not in reco['elliptic_curves']:
        issues.append(f"server's public key: elliptic curve `{ec}`")

      sig_alg = cert['signature_algorithm']
      if sig_alg and sig_alg not in reco['signature_algorithms']:
        issues.append(f"server's certificate: signature algorithm `{sig_alg}`")

      cs = service['cipher_suites']
      reco = self.recommendations['cipher_suite']

      for deviation in list(set(cs['elliptic_curves']).difference(reco['elliptic_curves'])):
        issues.append(f"ECDH curve: {deviation}")

      if 'preference' in reco and not reco['preference'] == cs['preference']:
        issues.append(f"cipher preference: {cs['preference']}")

      # (weak) key exchange

      flagged_kex = []
      for cipher_suite in cs['list']:
        if cipher_suite['name'] not in reco['names']:
          issues.append(f"cipher suite supported: `{cipher_suite['name']}`")
          #continue

        kex = cipher_suite['key_exchange_algorithm']
        if kex:
          key_info = kex.split(' ')

          if kex not in flagged_kex and key_info[0] not in reco['minimum_key_length']:
            flagged_kex.append(kex)

          if kex not in flagged_kex and len(key_info) > 1 and int(key_info[1]) < reco['minimum_key_length'][key_info[0]]:
            flagged_kex.append(kex)

      for kex in flagged_kex:
        issues.append(f"key exchange: {kex}")

      # TLS extensions

      if 'extensions' in self.recommendations:
        extensions = self.recommendations['extensions']
        if 'yes' in extensions:
          for deviation in list(set(extensions['yes']).difference(service['extensions'])):
            issues.append(f"extension not supported: {deviation}")
        if 'no' in extensions:
          for deviation in list(set(service['extensions']).intersection(extensions['no'])):
            issues.append(f"extension supported: {deviation}")

    return services

  def save_CSV(self, path, tool):
    delimiter = ','
    header = ['tool', 'asset', 'issues']

    with open(path, 'w') as f:
      csv.writer(f, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL).writerow(header)

      for identifier, service in self.services.items():
        for issue in service['issues']:
          row = [tool, identifier, issue]
          csv.writer(f, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL).writerow(row)
