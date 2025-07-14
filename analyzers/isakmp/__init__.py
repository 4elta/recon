import json
import re

from .. import Issue, AbstractAnalyzer

SERVICE_SCHEMA = {
  'versions': [],
  'IKEv1': {
    'encryption_algorithms': [], # https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-4
    'key_lengths': {},
    'hash_algorithms': [], # https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-6
    'authentication_methods': [], # https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-8
    'groups': [], # https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-12
    'aggressive': False
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

  def analyze(self, files):
    super().analyze(files)

    # parse result files
    services = self.parser.parse_files(files)
    self.services = services

    # analyze services based on recommendations

    for identifier, service in services.items():
      issues = service['issues']

      if 'versions' in self.recommendations:
        self._analyze_list(
          'protocol',
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
        'IKE Attributes',
        service['encryption_algorithms'],
        recommendation['encryption_algorithms'],
        issues,
        'IKEv1 encryption algorithm'
      )

    if 'hash_algorithms' in recommendation:
      self._analyze_list(
        'IKE Attributes',
        service['hash_algorithms'],
        recommendation['hash_algorithms'],
        issues,
        'IKEv1 hash algorithm'
      )

    if 'authentication_methods' in recommendation:
      self._analyze_list(
        'IKE Attributes',
        service['authentication_methods'],
        recommendation['authentication_methods'],
        issues,
        'IKEv1 authentication method'
      )

    if 'groups' in recommendation:
      self._analyze_list(
        'IKE Attributes',
        service['groups'],
        recommendation['groups'],
        issues,
        'IKEv1 group'
      )

    if 'aggressive' in recommendation and service['aggressive'] != recommendation['aggressive']:
      if recommendation['aggressive']:
        issues.append(Issue("IKEv1: Aggressive Mode not supported"))
      else:
        issues.append(Issue("IKEv1: Aggressive Mode supported"))

  def _analyze_IKEv2(self, service, recommendation, issues):
    if 'encryption_algorithms' in recommendation:
      self._analyze_list(
        'IKEv2 Parameters',
        service['encryption_algorithms'],
        recommendation['encryption_algorithms'],
        issues,
        'IKEv2 encryption algorithm'
      )

    if 'pseudorandom_functions' in recommendation:
      self._analyze_list(
        'IKEv2 Parameters',
        service['pseudorandom_functions'],
        recommendation['pseudorandom_functions'],
        issues,
        'IKEv2 pseudorandom function'
      )

    if 'integrity_algorithms' in recommendation:
      self._analyze_list(
        'IKEv2 Parameters',
        service['integrity_algorithms'],
        recommendation['integrity_algorithms'],
        issues,
        'IKEv2 integrity algorithm'
      )

    if 'key_exchange_methods' in recommendation:
      self._analyze_list(
        'IKEv2 Parameters',
        service['key_exchange_methods'],
        recommendation['key_exchange_methods'],
        issues,
        'IKEv2 key exchange method'
      )

    if 'authentication_methods' in recommendation:
      self._analyze_list(
        'IKEv2 Parameters',
        service['authentication_methods'],
        recommendation['authentication_methods'],
        issues,
        'IKEv2 authentication method'
      )

  def _analyze_list(self, id, supported, recommendation, issues, name, must_support=False):

    for deviation in list(set(supported).difference(recommendation)):
      issues.append(
        Issue(
          f"{id}: supported",
          name = name,
          deviation = deviation
        )
      )

    if must_support:
      for deviation in list(set(recommendation).difference(supported)):
        issues.append(
          Issue(
            f"{id}: not supported",
            name = name,
            deviation = deviation
          )
        )
