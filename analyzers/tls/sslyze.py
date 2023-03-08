import copy
import json
import pathlib
import re

from . import CERTIFICATE_SCHEMA, SERVICE_SCHEMA

PROTOCOL_VERSIONS = {
  'SSL_2_0': 'SSL 2.0',
  'SSL_3_0': 'SSL 3.0',
  'TLS_1_0': 'TLS 1.0',
  'TLS_1_1': 'TLS 1.1',
  'TLS_1_2': 'TLS 1.2',
  'TLS_1_3': 'TLS 1.3'
}

class Parser:
  '''
  parse results of the "sslyze" tool.

  $  sslyze --json_out "{result_file}.json" {hostname}:{port}
  '''

  name = 'sslyze'
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

    for server_scan_result in results['server_scan_results']:

      server_location = server_scan_result['server_location']
      host = server_location['hostname'] # TODO: or is it 'ip_address'?
      port = server_location['port']

      identifier = f"{host}:{port}"

      if identifier in self.services:
        continue

      #print(identifier)

      status = server_scan_result['scan_status']
      if not status == 'COMPLETED':
        print(status)
        continue

      service = copy.deepcopy(SERVICE_SCHEMA)
      self.services[identifier] = service

      if server_scan_result['connectivity_status'] == 'ERROR':
        service['issues'].append("could not connect to target")
        continue

      if 'scan_result' in server_scan_result and server_scan_result['scan_result']:
        self.parse_scan_result(
          server_scan_result['scan_result'],
          service
        )


  def parse_scan_result(self, scan_result, service):

    self.parse_certificate_info(
      scan_result['certificate_info'],
      service
    )

    for protocol in ('ssl_2_0', 'ssl_3_0', 'tls_1_0', 'tls_1_1', 'tls_1_2', 'tls_1_3'):
      self.parse_protocol(
        scan_result[f'{protocol}_cipher_suites'],
        service
      )

    if 'misc' not in service:
      service['misc'] = {}

    # TLS 1.3 Early Data
    # https://www.rfc-editor.org/rfc/rfc8446#section-2.3
    if self.parse_generic_scan_result(scan_result['tls_1_3_early_data'], 'supports_early_data'):
      service['misc']['0_RTT'] = 'supported'

    if self.parse_generic_scan_result(scan_result['tls_fallback_scsv'], 'supports_fallback_scsv'):
      service['misc']['fallback_SCSV'] = 'supported'

    if self.parse_generic_scan_result(scan_result['tls_compression'], 'supports_compression'):
      service['vulnerabilities'].append('CRIME')

    if self.parse_generic_scan_result(scan_result['openssl_ccs_injection'], 'is_vulnerable_to_ccs_injection'):
      service['vulnerabilities'].append('OpenSSL CCS injection')

    if self.parse_generic_scan_result(scan_result['heartbleed'], 'is_vulnerable_to_heartbleed'):
      service['vulnerabilities'].append('Heartbleed')

    if not self.parse_generic_scan_result(scan_result['robot'], 'robot_result').startswith('NOT_VULNERABLE'):
      service['vulnerabilities'].append('ROBOT')

    self.parse_session_renegotiation_result(
      scan_result['session_renegotiation'],
      service
    )

    self.parse_elliptic_curves(
      scan_result['elliptic_curves'],
      service
    )

  def parse_certificate_info(self, certificate_info, service):
    if not certificate_info['status'] == 'COMPLETED' or 'result' not in certificate_info:
      service['issues'].append('could not parse certificate information')
      return

    result = certificate_info['result']
    for certificate_deployment in result['certificate_deployments']:
      certificate = copy.deepcopy(CERTIFICATE_SCHEMA)
      service['certificates'].append(certificate)

      leaf_certificate = certificate_deployment['received_certificate_chain'][0]

      validity = certificate['validity']
      validity['not_before'] = leaf_certificate['not_valid_before']
      validity['not_after'] = leaf_certificate['not_valid_after']

      subject_alt_names = certificate_deployment['subject_alternative_name']

      for subject_alt_name in subject_alt_names['dns']:
        if subject_alt_name not in certificate['subjects']:
          certificate['subjects'].append(subject_alt_name)

      if 'ip_addresses' in subject_alt_names:
        for subject_alt_name in subject_alt_names['ip_addresses']:
          if subject_alt_name not in certificate['subjects']:
            certificate['subjects'].append(subject_alt_name)

      if 'subject' in leaf_certificate:
        subject = leaf_certificate['subject']['rfc4514_string']
        if subject not in certificate['subjects']:
          certificate['subjects'].append(subject)

      certificate['signature_algorithm'] = leaf_certificate['signature_hash_algorithm']['name']

      pub_key = leaf_certificate['public_key']
      public_key = certificate['public_key']

      public_key['type'] = pub_key['algorithm']

      if 'key_size' in pub_key:
        public_key['bits'] = pub_key['key_size']

      if 'ec_curve_name' in pub_key:
        public_key['curve'] = pub_key['ec_curve_name']

      if not certificate_deployment['leaf_certificate_subject_matches_hostname']:
        service['issues'].append(f"certificate not trusted: hostname mismatch")

      if not certificate_deployment['received_chain_has_valid_order']:
        service['issues'].append(f"certificate not trusted: invalid certificate chain order")

      if not certificate_deployment['path_validation_results']['was_validation_successful']:
        # TODO: add certificate_deployment['path_validation_results']['openssl_error_string']?
        service['issues'].append(f"certificate not trusted: path validation failed")

      if not certificate_deployment['verified_chain_has_sha1_signature']:
        service['issues'].append(f"signature based on SHA-1 found within the certificate chain")

      # https://blog.mozilla.org/security/2018/03/12/distrust-symantec-tls-certificates/
      if not certificate_deployment['verified_chain_has_legacy_symantec_anchor']:
        service['issues'].append(f"certificate chain contains a legacy Symantec certificate")

  def parse_protocol(self, cipher_suites, service):
    if not cipher_suites['status'] == 'COMPLETED' or 'result' not in cipher_suites:
      return

    result = cipher_suites['result']

    if not result['is_tls_version_supported']:
      return

    protocol_version = PROTOCOL_VERSIONS[result['tls_version_used']]
    service['protocol_versions'].append(protocol_version)

    for accepted_cipher_suite in result['accepted_cipher_suites']:
      name = accepted_cipher_suite['cipher_suite']['name']
      if name not in service['cipher_suites']:
        service['cipher_suites'].append(name)

      if 'ephemeral_key' not in accepted_cipher_suite or not accepted_cipher_suite['ephemeral_key']:
        continue

      ephemeral_key = accepted_cipher_suite['ephemeral_key']
      kex_method = ephemeral_key['type_name']
      kex_bits = ephemeral_key['size']

      kex_methods = service['key_exchange']['methods']
      if kex_method not in kex_methods:
        kex_methods[kex_method] = kex_bits
      elif kex_bits and kex_methods[kex_method] and kex_bits < kex_methods[kex_method]:
        kex_methods[kex_method] = kex_bits

      if 'curve_name' in accepted_cipher_suite:
        group = accepted_cipher_suite['curve_name']

        if group == 'X25519':
          group = 'x25519'

        if group not in service['key_exchange']['groups']:
          service['key_exchange']['groups'].append(group)

  def parse_generic_scan_result(self, result, result_key):
    if not result['status'] == 'COMPLETED' or 'result' not in result:
      return None

    return result['result'][result_key]

  def parse_session_renegotiation_result(self, result, service):
    if not result['status'] == 'COMPLETED' or 'result' not in result:
      return

    result = result['result']

    if result['is_vulnerable_to_client_renegotiation_dos']:
      service['vulnerabilities'].append('client-initiated renegotiation DoS')

  def parse_elliptic_curves(self, result, service):
    if not result['status'] == 'COMPLETED' or 'result' not in result:
      return

    result = result['result']

    if not 'supports_ecdh_key_exchange' in result or not result['supported_curves']:
      return

    for group in result['supported_curves']:
      name = group['name']

      if name == 'X25519':
        name = 'x25519'

      if name not in service['key_exchange']['groups']:
        service['key_exchange']['groups'].append(name)
