import json
import re

from .. import AbstractAnalyzer

SERVICE_SCHEMA = {
  'versions': [],
  'IKEv1': {
    'encryption_algorithms': [], # https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-4
    'key_lengths': {},
    'hash_algorithms': [], # https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-6
    'authentication_methods': [], # https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-8
    'groups': [], # https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-12
    'aggressive': None
  },
  'IKEv2': {
    'encryption_algorithms': [], # https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-5
    'key_lengths': {},
    'pseudorandom_functions': [], # https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-6
    'integrity_algorithms': [], # https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-7
    'key_exchange_methods': [], # https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-8
    'authentication_methods': [], # https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-12
  },
  'issues': [],
}

class Analyzer(AbstractAnalyzer):

  def __init__(self, name, recommendations):
    super().__init__(name, recommendations)

    self.set_tool('ike')

  def analyze(self, files):
    super().analyze(files)

    # parse result files
    services = self.parser.parse_files(files[self.tool])
    self.services = services

    # analyze services based on recommendations

    for identifier, service in services.items():
      issues = service['issues']

      if 'versions' in self.recommendations:
        self._analyze_list(
          service['versions'],
          self.recommendations['versions'],
          issues,
          'version',
          True
        )

      if 'IKEv1' in self.recommendations:
        self._analyze_IKEv1(
          service['IKEv1'],
          self.recommendations['IKEv1'],
          issues
        )

      if 'IKEv2' in self.recommendations:
        self._analyze_IKEv2(
          service['IKEv2'],
          self.recommendations['IKEv2'],
          issues
        )

    return services

  def _analyze_IKEv1(self, service, recommendation, issues):
    if 'encryption_algorithms' in recommendation:
      self._analyze_list(
        service['encryption_algorithms'],
        recommendation['encryption_algorithms'],
        issues,
        'IKEv1 encryption algorithm'
      )

    if 'hash_algorithms' in recommendation:
      self._analyze_list(
        service['hash_algorithms'],
        recommendation['hash_algorithms'],
        issues,
        'IKEv1 hash algorithm'
      )

    if 'authentication_methods' in recommendation:
      self._analyze_list(
        service['authentication_methods'],
        recommendation['authentication_methods'],
        issues,
        'IKEv1 authentication method'
      )

    if 'groups' in recommendation:
      self._analyze_list(
        service['groups'],
        recommendation['groups'],
        issues,
        'IKEv1 group'
      )

    if 'aggressive' in recommendation and not service['aggressive'] == recommendation['aggressive']:
      if service['aggressive']:
        issues.append(f"IKEv1 Aggressive Mode supported")
      else:
        issues.append(f"IKEv1 Aggressive Mode not supported")

  def _analyze_IKEv2(self, service, recommendation, issues):
    if 'encryption_algorithms' in recommendation:
      self._analyze_list(
        service['encryption_algorithms'],
        recommendation['encryption_algorithms'],
        issues,
        'IKEv2 encryption algorithm'
      )

    if 'pseudorandom_functions' in recommendation:
      self._analyze_list(
        service['pseudorandom_functions'],
        recommendation['pseudorandom_functions'],
        issues,
        'IKEv2 pseudorandom function'
      )

    if 'integrity_algorithms' in recommendation:
      self._analyze_list(
        service['integrity_algorithms'],
        recommendation['integrity_algorithms'],
        issues,
        'IKEv2 integrity algorithm'
      )

    if 'key_exchange_methods' in recommendation:
      self._analyze_list(
        service['key_exchange_methods'],
        recommendation['key_exchange_methods'],
        issues,
        'IKEv2 key exchange method'
      )

    if 'authentication_methods' in recommendation:
      self._analyze_list(
        service['authentication_methods'],
        recommendation['authentication_methods'],
        issues,
        'IKEv2 authentication method'
      )

  def _analyze_list(self, supported, recommendation, issues, name, must_support=False):

    for deviation in list(set(supported).difference(recommendation)):
      issues.append(f"{name} supported: `{deviation}`")

    if must_support:
      for deviation in list(set(recommendation).difference(supported)):
        issues.append(f"{name} not supported: `{deviation}`")
