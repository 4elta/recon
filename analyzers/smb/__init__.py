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
    'users': {},
    'domain': {},
  },
  'issues': [],
  'misc': [], # misc information (NetBIOS, etc); shown with the host, after all issues
  'info': [], # additional (debug) information; shown at the end of the analysis
}

USER_SCHEMA = {
  'name': None,
  'full_name': None, # can be null
  # account control bit field
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

    self.__class__.logger.debug("parsing done")

    for identifier, service in services.items():
      self.__class__.logger.info(f"analyzing {identifier} ...")

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

      if service['AD']['users']:
        self._analyze_domain_users(
          service['AD']['users'],
          self.recommendations,
          issues
        )

      if service['AD']['domain']:
        self._analyze_domain_info(
          service['AD']['domain'],
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
    self.__class__.logger.debug("analyzing dialects ...")

    # look for missing protocols/dialects support
    for protocol, dialect in recommendations['dialect'].items():
      if protocol not in dialects:
        self.__class__.logger.info(f"protocol not supported: {protocol}")
        issues.append(
          Issue(
            "protocol not supported",
            protocol = PROTOCOL_NICE[protocol]
          )
        )
        continue

      if dialect not in dialects[protocol]:
        self.__class__.logger.info(f"dialect not supported: {dialect}")
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
        self.__class__.logger.info(f"protocol supported: {protocol}")
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
          self.__class__.logger.info(f"dialect supported: {dialect}")
          issues.append(
            Issue(
              "dialect supported",
              protocol = PROTOCOL_NICE[protocol],
              dialect = dialect
            )
          )

  def _analyze_signing(self, signing, recommendations, issues):
    self.__class__.logger.debug("analyzing SMB signing ...")

    for protocol, signing_info in signing.items():
      # ignore protocol version that don't have a recommendation:
      # these are flagged as "not recommended" anyway
      if protocol not in recommendations['signing']:
        continue

      if signing_info['required'] != recommendations['signing'][protocol]['required']:
        self.__class__.logger.info(f"{protocol}: signing required: {signing_info['required']}")
        issues.append(
          Issue(
            f"signing r:{signing_info['required']}",
            protocol = PROTOCOL_NICE[protocol]
          )
        )

  def _analyze_authentication_methods(self, authentication_methods, recommendations, issues):
    self.__class__.logger.debug("analyzing authentication methods ...")

    for method, variations in authentication_methods.items():
      if method not in recommendations['authentication_methods']:
        if method == 'NTLM':
          self.__class__.logger.info("authentication: NTLM")
          issues.append(Issue('authentication: NTLM'))
        else:
          self.__class__.logger.info(f"authentication: {method}")
          issues.append(
            Issue(
              'authentication',
              method = method
            )
          )

        for variation in variations:
          self.__class__.logger.info(f"authentication: {method}: {variation}")
          issues.append(Issue(f'authentication: {method}: {variation}'))

  def _analyze_domain_users(self, domain_users, recommendations, issues):
    self.__class__.logger.info("analyzing domain users ...")

    if 'AD' not in recommendations:
      return

    if 'users' not in recommendations['AD']:
      return

    issue_group = 'AD: users'

    secrets_pattern = None
    if 'secrets' in recommendations['AD']['users']:
      secrets_pattern = recommendations['AD']['users']['secrets']

    AC_discouraged = None
    AC_recommended = None

    if 'AC' in recommendations['AD']['users']:
      if 'discouraged' in recommendations['AD']['users']['AC']:
        AC_discouraged = recommendations['AD']['users']['AC']['discouraged']

      if 'recommended' in recommendations['AD']['users']['AC']:
        AC_recommended = recommendations['AD']['users']['AC']['recommended']

    AC_present = {}
    AC_missing = {}
    users_with_sensitive_info = []

    for RID, user in domain_users.items():
      if secrets_pattern:
        if user['full_name'] and re.search(secrets_pattern, user['full_name']):
          if user['name'] not in users_with_sensitive_info:
            users_with_sensitive_info.append(user['name'])

        if user['description'] and re.search(secrets_pattern, user['description']):
          if user['name'] not in users_with_sensitive_info:
            users_with_sensitive_info.append(user['name'])

      if user['AC']:
        if AC_discouraged:
          for hex_string, name in AC_discouraged.items():
            value = int(hex_string, 16)
            if user['AC'] & value != 0:
              if name not in AC_present:
                AC_present[name] = []
              AC_present[name].append(user['name'])

        if AC_recommended:
          for hex_string, name in AC_recommended.items():
            value = int(hex_string, 16)
            if user['AC'] & value == 0:
              if name not in AC_missing:
                AC_missing[name] = []
              AC_missing[name].append(user['name'])

    for AC_name, users in AC_present.items():
      self.__class__.logger.info(f"{issue_group}: AC: {AC_name}: {users}")
      issues.append(
        Issue(
          f'{issue_group}: AC',
          name = AC_name,
          users = ', '.join([f'`{user}`' for user in users])
        )
      )

    for AC_name, users in AC_missing.items():
      self.__class__.logger.info(f"{issue_group}: AC missing: {AC_name}: {users}")
      issues.append(
        Issue(
          f'{issue_group}: AC: missing',
          name = AC_name,
          users = ', '.join([f'`{user}`' for user in users])
        )
      )

    if users_with_sensitive_info:
      self.__class__.logger.info(f"{issue_group}: sensitive information: {users_with_sensitive_info}")
      issues.append(
        Issue(
          f'{issue_group}: sensitive information',
          users = ', '.join([f'`{user}`' for user in users_with_sensitive_info])
        )
      )

  def _analyze_domain_info(self, domain_info, recommendations, issues):
    self.__class__.logger.info("analyzing domain info ...")

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
            duration = self._format_duration(field_value)
            self.__class__.logger.info(f"{issue_group}: {field_name}: {duration}")
            issues.append(
              Issue(
                f'{issue_group}: {field_name}',
                value = duration
              )
            )

        # duration; disabled with '0'; value must be equal or larger than recommendation
        case 'lockout_duration' | 'lockout_observation_window' | 'min_password_age':
          if field_value < recommendation:
            duration = self._format_duration(field_value)
            self.__class__.logger.info(f"{issue_group}: {field_name}: {duration}")
            issues.append(
              Issue(
                f'{issue_group}: {field_name}',
                value = duration
              )
            )

        # duration; disabled with '0'; value must be equal or less than recommendation
        case 'max_password_age':
          if (
            (field_value == 0 and recommendation != 0)
            or field_value > recommendation
          ):
            duration = self._format_duration(field_value)
            self.__class__.logger.info(f"{issue_group}: {field_name}: {duration}")
            issues.append(
              Issue(
                f'{issue_group}: {field_name}',
                value = duration
              )
            )

        # integer; disabled with '0'; value must be equal or less than recommendation
        case 'lockout_threshold':
          if (
            (field_value == 0 and recommendation != 0)
            or field_value > recommendation
          ):
            self.__class__.logger.info(f"{issue_group}: {field_name}: {field_value}")
            issues.append(
              Issue(
                f'{issue_group}: {field_name}',
                value = field_value
              )
            )

        # integer; value must be equal or larger than recommendation
        case 'min_password_length' | 'password_history_length':
          if field_value < recommendation:
            self.__class__.logger.info(f"{issue_group}: {field_name}: {field_value}")
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
              self.__class__.logger.info(f"{issue_group}: {field_name}: {password_property_name}: {password_property}")
              issues.append(
                Issue(
                  f'{issue_group}: {field_name}: {password_property_name}: {password_property}'
                )
              )

        case _:
          if field_value != recommendation[password_property_name]:
            self.__class__.logger.info(f"{issue_group}: {field_name}: {field_value}")
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

