import datetime
import re
import sys

from .. import Issue, AbstractAnalyzer

SERVICE_SCHEMA = {
  'address': None,
  'dialects': {}, # for each protocol (CIFS, SMB2) hold a list of supported dialects
  'signing': {}, # for each protocol (CIFS, SMB2) hold information about 'enabled' and 'required'
  'authentication_methods': {}, # Kerberos: [], NTLM: [guest, anonymous]
  # https://sensepost.com/blog/2024/guest-vs-null-session-on-windows/
  'AD': {
    'password_policy': {},
    'account_lockout_policy': {},
  },
  'issues': [],
  'misc': [], # misc information (NetBIOS, etc); shown with the host, after all issues
  'info': [], # additional (debug) information; shown at the end of the analysis
}

PROTOCOL_NICE = {
  'CIFS': "SMB1/CIFS",
  'SMB2': "SMB2"
}

class Analyzer(AbstractAnalyzer):

  def analyze(self, files):
    super().analyze(files)

    # parse result files
    services = self.parser.parse_files(files)
    self.services = services

    for identifier, service in services.items():
      issues = service['issues']

      if service['dialects']:
        self._analyze_dialects(service['dialects'], self.recommendations, issues)
   
      if service['signing']:
        self._analyze_signing(service['signing'], self.recommendations, issues)

      if service['authentication_methods']:
        self._analyze_authentication_methods(service['authentication_methods'], self.recommendations, issues)

      if service['AD']['password_policy']:
        self._analyze_AD_password_policy(service['AD']['password_policy'], self.recommendations, issues)

      if service['AD']['account_lockout_policy']:
        self._analyze_AD_account_lockout_policy(
          service['AD']['account_lockout_policy'],
          self.recommendations,
          issues
        )

      for info in service['misc']:
        issues.append(
          Issue(
            "additional info",
            info = info
          )
        )

    return services

  def _analyze_dialects(self, dialects, recommendations, issues):
    # look for missing protocols/dialects support
    for protocol, dialect in recommendations['dialect'].items():
      if protocol not in dialects:
        issues.append(
          Issue(
            "protocol not supported",
            protocol = PROTOCOL_NICE[protocol]
          )
        )
        continue

      if dialect not in dialects[protocol]:
        issues.append(
          Issue(
            "dialect not supported",
            protocol = PROTOCOL_NICE[protocol],
            dialect = dialect
          )
        )

    # look for protocols/dialects that should not be supported
    for protocol, dialect_list in dialects.items():
      if protocol not in recommendations['dialect']:
        issues.append(
          Issue(
            "protocol supported",
            protocol = PROTOCOL_NICE[protocol]
          )
        )

      for dialect in dialect_list:
        if (
          protocol not in recommendations['dialect']
          or dialect < recommendations['dialect'][protocol]
        ):
          issues.append(
            Issue(
              "dialect supported",
              protocol = PROTOCOL_NICE[protocol],
              dialect = dialect
            )
          )

  def _analyze_signing(self, signing, recommendations, issues):
    for protocol, signing_info in signing.items():
      if (
        protocol not in recommendations['signing']
        or signing_info['required'] != recommendations['signing'][protocol]['required']
      ):
        issues.append(
          Issue(
            f"signing r:{signing_info['required']}",
            protocol = PROTOCOL_NICE[protocol]
          )
        )

  def _analyze_authentication_methods(self, authentication_methods, recommendations, issues):
    for method, variations in authentication_methods.items():
      if method not in recommendations['authentication_methods']:
        if method == 'NTLM':
          issues.append(Issue('authentication: NTLM'))
        else:
          issues.append(
            Issue(
              'authentication',
              method = method
            )
          )

        for variation in variations:
          issues.append(Issue(f'authentication: {method}: {variation}'))

  def _analyze_AD_password_policy(self, policy, recommendations, issues):
    section = 'password_policy'

    if 'AD' not in recommendations or section not in recommendations['AD']:
      return

    for policy_name, policy_value in policy.items():
      if policy_name not in recommendations['AD'][section]:
        continue

      match policy_name:
        case 'history_count':
          if policy_value < recommendations['AD'][section][policy_name]:
            issues.append(Issue(f'{section}: {policy_name}', value=policy_value))
        case 'max_age':
          if (
            (policy_value == 0 and recommendations['AD'][section][policy_name] != 0)
            or policy_value > recommendations['AD'][section][policy_name]
          ):
            duration = datetime.timedelta(seconds=policy_value)
            issues.append(
              Issue(
                f'{section}: {policy_name}',
                value = str(duration).replace(', 0:00:00', '')
              )
            )
        case 'min_age':
          if policy_value < recommendations['AD'][section][policy_name]:
            duration = datetime.timedelta(seconds=policy_value)
            issues.append(
              Issue(
                f'{section}: {policy_name}',
                value = str(duration).replace(', 0:00:00', '')
              )
            )
        case 'min_length':
          if policy_value < recommendations['AD'][section][policy_name]:
            issues.append(Issue(f'{section}: {policy_name}', value=policy_value))
        case _:
          if policy_value != recommendations['AD'][section][policy_name]:
            issues.append(Issue(f'{section}: {policy_name}', value=policy_value))

  def _analyze_AD_account_lockout_policy(self, policy, recommendations, issues):
    section = 'account_lockout_policy'

    if 'AD' not in recommendations or section not in recommendations['AD']:
      return

    for policy_name, policy_value in policy.items():
      if policy_name not in recommendations['AD'][section]:
        continue

      match policy_name:
        case 'threshold':
          if (
            (policy_value == 0 and recommendations['AD'][section][policy_name] != 0)
            or (policy_value > recommendations['AD'][section][policy_name])
          ):
            issues.append(Issue(f'{section}: {policy_name}', value=policy_value))
        case _:
          if policy_value < recommendations['AD'][section][policy_name]:
            issues.append(Issue(f'{section}: {policy_name}', value=policy_value))
