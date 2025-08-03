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
    'domain': {},
    'users': {},
  },
  'issues': [],
  'misc': [], # misc information (NetBIOS, etc); shown with the host, after all issues
  'info': [], # additional (debug) information; shown at the end of the analysis
}

USER_SCHEMA = {
  'name': None,
  'full_name': None, # can be null
  # account control bits
  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b10cfda1-f24f-441b-8f43-80cb93e786ec
  'AC': None, # can be null
  'description': None # can be null
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
        self._analyze_dialects(
          service['dialects'],
          self.recommendations,
          issues
        )
   
      if service['signing']:
        self._analyze_signing(
          service['signing'],
          self.recommendations,
          issues
        )

      if service['authentication_methods']:
        self._analyze_authentication_methods(
          service['authentication_methods'],
          self.recommendations,
          issues
        )

      if service['AD']['domain']:
        self._analyze_domain_info(
          service['AD']['domain'],
          self.recommendations,
          issues
        )

      if service['AD']['users']:
        self._analyze_domain_users(
          service['AD']['users'],
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

  def _analyze_domain_info(self, domain_info, recommendations, issues):
    if 'AD' not in recommendations:
      return

    if 'domain' not in recommendations['AD']:
      return

    issue_group = 'AD: domain'

    for field_name, field_value in domain_info.items():
      if field_name not in recommendations['AD']['domain']:
        continue

      recommendation = recommendations['AD']['domain'][field_name]

      match field_name:

        # duration; disabled with '0'; value must be equal or larger than recommendation
        case 'force_logoff':
          if (
            (field_value == 0 and recommendation != 0)
            or field_value < recommendation
          ):
            issues.append(
              Issue(
                f'{issue_group}: {field_name}',
                value = self._format_duration(field_value)
              )
            )

        # duration; disabled with '0'; value must be equal or larger than recommendation
        case 'lockout_duration' | 'lockout_observation_window' | 'min_password_age':
          if field_value < recommendation:
            issues.append(
              Issue(
                f'{issue_group}: {field_name}',
                value = self._format_duration(field_value)
              )
            )

        # duration; disabled with '0'; value must be equal or less than recommendation
        case 'max_password_age':
          if (
            (field_value == 0 and recommendation != 0)
            or field_value > recommendation
          ):
            issues.append(
              Issue(
                f'{issue_group}: {field_name}',
                value = self._format_duration(field_value)
              )
            )

        # integer; disabled with '0'; value must be equal or less than recommendation
        case 'lockout_threshold':
          if (
            (field_value == 0 and recommendation != 0)
            or field_value > recommendation
          ):
            issues.append(
              Issue(
                f'{issue_group}: {field_name}',
                value = field_value
              )
            )

        # integer; value must be equal or larger than recommendation
        case 'min_password_length' | 'password_history_length':
          if field_value < recommendation:
            issues.append(
              Issue(
                f'{issue_group}: {field_name}',
                value = field_value
              )
            )

        # password properties (boolean flags)
        case 'password_properties':
          for password_property_name, password_property in field_value.items():
            if password_property_name not in recommendation:
              continue

            if password_property != recommendation[password_property_name]:
              issues.append(
                Issue(
                  f'{issue_group}: {field_name}: {password_property_name}: {password_property}'
                )
              )

        case _:
          if field_value != recommendation[password_property_name]:
            issues.append(
              Issue(
                f'{issue_group}: {field_name}',
                value = field_value
              )
            )

  def _format_duration(self, seconds):
    duration = datetime.timedelta(seconds=seconds)

    seconds = duration.seconds
    hours = int(seconds / (60*60))
    seconds -= hours * 60*60

    minutes = int(seconds / 60)
    seconds -= minutes * 60

    return f'{duration.days}:{hours}:{minutes}:{seconds}.{duration.microseconds}'

  def _analyze_domain_users(self, domain_users, recommendations, issues):
    if 'AD' not in recommendations:
      return

    if 'users' not in recommendations['AD']:
      return

    issue_group = 'AD: users'

    secrets_pattern = None
    if 'secrets' in recommendations['AD']['users']:
      secrets_pattern = recommendations['AD']['users']['secrets']

    AC_bits_neg = None
    if 'AC_bits_neg' in recommendations['AD']['users']:
      AC_bits_neg = recommendations['AD']['users']['AC_bits_neg']

    AC_bits_pos = None
    if 'AC_bits_pos' in recommendations['AD']['users']:
      AC_bits_pos = recommendations['AD']['users']['AC_bits_pos']

    AC_neg = {}
    AC_pos = {}
    sensitive_info = []

    for RID, user in domain_users.items():
      if secrets_pattern:
        if user['full_name'] and re.search(secrets_pattern, user['full_name']):
          if user['name'] not in sensitive_info:
            sensitive_info.append(user['name'])

        if user['description'] and re.search(secrets_pattern, user['description']):
          if user['name'] not in sensitive_info:
            sensitive_info.append(user['name'])

      if user['AC']:
        if AC_bits_neg:
          for bit_string, name in AC_bits_neg.items():
            bit = int(bit_string, 16)
            if user['AC'] & bit != 0:
              if name not in AC_neg:
                AC_neg[name] = []
              AC_neg[name].append(user['name'])

        if AC_bits_pos:
          for bit_string, name in AC_bits_pos.items():
            bit = int(bit_string, 16)
            if user['AC'] & bit == 0:
              if name not in AC_pos:
                AC_pos[name] = []
              AC_pos[name].append(user['name'])

    for AC_name, users in AC_neg.items():
      issues.append(
        Issue(
          f'{issue_group}: AC: neg',
          name = AC_name,
          users = ', '.join([f'`{user}`' for user in users])
        )
      )

    for AC_name, users in AC_pos.items():
      issues.append(
        Issue(
          f'{issue_group}: AC: pos',
          name = AC_name,
          users = ', '.join([f'`{user}`' for user in users])
        )
      )

    if sensitive_info:
      issues.append(
        Issue(
          f'{issue_group}: sensitive information',
          users = ', '.join([f'`{user}`' for user in sensitive_info])
        )
      )
