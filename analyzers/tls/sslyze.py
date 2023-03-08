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
    '''
    # https://github.com/nabla-c0d3/sslyze/blob/release/json_output_schema.json

    certificate_info_schema = {
      "status": "(COMPLETED|ERROR|NOT_SCHEDULED)",
      "result": { # optional
        "certificate_deployments": [
          {
            "received_certificate_chain": [ # received_certificate_chain: The certificate chain sent by the server; index 0 is the leaf certificate.
              {
                "not_valid_before": "YYYY-MM-DD hh:mm:ss",
                "not_valid_after": "YYYY-MM-DD hh:mm:ss",
                "subject": { "rfc4514_string": "example.com" }, # optional
                "subject_alternative_name": {
                  "dns": [ "example.com", "*.example.com" ],
                  "ip_addresses": [ "IPv4 address", "IPv6 address" ], # optional
                },
                "signature_hash_algorithm": {
                  "name": "ecdsa-with-SHA256",
                  "digest_size": 256
                },
                "public_key": {
                  "algorithm": "RSA|ECDSA",
                  "key_size": 256, # optional
                  "ec_curve_name" = "prime256v1" # optional
                }
              }
            ],
            "leaf_certificate_subject_matches_hostname": True,
            "received_chain_has_valid_order": True, # optional
            "path_validation_results": {
              "was_validation_successful": True,
              "openssl_error_string": "OpenSSL error message" # optional
            },
            "verified_chain_has_sha1_signature": False, # optional
            "verified_chain_has_legacy_symantec_anchor": False, # optional
          },
        ]
      },
    }

    cipher_suites_schema = {
      "status": "(COMPLETED|ERROR|NOT_SCHEDULED)",
      "result": { # optional
        "tls_version_used": "SSL_2_0|SSL_3_0|TLS_1_0|TLS_1_1|TLS_1_2|TLS_1_3",
        "is_tls_version_supported": True,
        "accepted_cipher_suites": [
          "cipher_suite": { "name": "TLS_CHACHA20_POLY1305_SHA256" },
          "ephemeral_key": { # optional
            "type_name": "ECDH",
            "size": 253,
            "curve_name": "X25519" # optional
          }
        ]
      }
    }

    scan_result_schema = {
      "server_scan_results": [
        {
          "scan_status": "(COMPLETED|ERROR_NO_CONNECTIVITY)",
          "server_location": {
            "hostname": "example.com",
            "ip_address": "10.11.12.13",
            "port": 443,
          },
          "scan_result": { # optional
            "certificate_info": certificate_info_schema,
            "ssl_2_0_cipher_suites": cipher_suites_schema,
            "ssl_3_0_cipher_suites": cipher_suites_schema,
            "tls_1_0_cipher_suites": cipher_suites_schema,
            "tls_1_1_cipher_suites": cipher_suites_schema,
            "tls_1_2_cipher_suites": cipher_suites_schema,
            "tls_1_3_cipher_suites": cipher_suites_schema,
            "tls_compression": {
              "status" = "(COMPLETED|ERROR|NOT_SCHEDULED)",
              "result" = { "supports_compression": False } # optional
            },
            "tls_1_3_early_data": { # https://www.rfc-editor.org/rfc/rfc8446#section-2.3
              "status" = "(COMPLETED|ERROR|NOT_SCHEDULED)",
              "result": { "supports_early_data": False } # optional
            },
            "openssl_ccs_injection": {
              "status" = "(COMPLETED|ERROR|NOT_SCHEDULED)",
              "result": { "is_vulnerable_to_ccs_injection": False } # optional
            },
            "tls_fallback_scsv": {
              "status" = "(COMPLETED|ERROR|NOT_SCHEDULED)",
              "result": { "supports_fallback_scsv": False } # optional
            },
            "heartbleed": {
              "status" = "(COMPLETED|ERROR|NOT_SCHEDULED)",
              "result": { "is_vulnerable_to_heartbleed": False } # optional
            },
            "robot": {
              "status" = "(COMPLETED|ERROR|NOT_SCHEDULED)",
              "result": { "robot_result": "VULNERABLE_WEAK_ORACLE|VULNERABLE_STRONG_ORACLE|NOT_VULNERABLE_NO_ORACLE|NOT_VULNERABLE_RSA_NOT_SUPPORTED|UNKNOWN_INCONSISTENT_RESULTS" } # optional
            },
            "session_renegotiation": {
              "status" = "(COMPLETED|ERROR|NOT_SCHEDULED)",
              "result": { # optional
                "supports_secure_renegotiation": True,
                "is_vulnerable_to_client_renegotiation_dos": False
              }
            },
            "session_resumption": { # only TLS 1.2 supports session resumption (via Session ID and TLS Ticket)
              "status" = "(COMPLETED|ERROR|NOT_SCHEDULED)",
              "result": { # optional
                "session_id_resumption_result": "FULLY_SUPPORTED|PARTIALLY_SUPPORTED|NOT_SUPPORTED|SERVER_IS_TLS_1_3_ONLY",
                "tls_ticket_resumption_result": "FULLY_SUPPORTED|PARTIALLY_SUPPORTED|NOT_SUPPORTED|SERVER_IS_TLS_1_3_ONLY"
              }
            },
            "elliptic_curves": {
              "status" = "(COMPLETED|ERROR|NOT_SCHEDULED)",
              "result": { # optional
                "supports_ecdh_key_exchange": True,
                "supported_curves": [ {"name": "X25519"}, {"name": "prime256v1"} ] # optional
              }
            },
          },
        },
      ]
    }
    '''

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
      service['vulnerabilities'].append('OpenSSL_CCS_injection')

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
      service['vulnerabilities'].append('client_initiated_renegotiation_DoS')

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
