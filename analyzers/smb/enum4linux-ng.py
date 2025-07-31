import copy
import datetime
import json
import re

from .. import Issue, AbstractParser
from . import SERVICE_SCHEMA

SMB_DIALECT_PATTERN = re.compile(r'SMB (?P<major>\d+)\.(?P<minor>\d+)(\.(?P<patch>\d+))?')
SECRETS_PATTERN = re.compile(r'password|secret', re.IGNORECASE)

# see https://github.com/cddmp/enum4linux-ng/pull/56
DURATION_PATTERN = re.compile(r'(?:(?P<days>\d+) day(?:s ))?(?:\(\d+ years?\) )?(?:(?P<hours>\d+) hours? )?(?:(?P<minutes>\d+) minutes?)?')
DURATION_PATTERN_NEW = re.compile(r'(?:(?P<days>\d+) days?, )?(?P<hours>\d+):(?P<minutes>\d+):(?P<seconds>\d+)(?:.(?P<microseconds>\d+))? \(hours:minutes:seconds\)')
DURATION_PATTERN_SECONDS = re.compile(r'(?P<seconds>\d+) seconds')

class Parser(AbstractParser):
  '''
  parse results of the "enum4linux-ng" tool.

  $ enum4linux-ng -As -oJ "{result_file}" {address}
  '''

  def __init__(self):
    super().__init__()

    self.name = 'enum4linux-ng'
    self.file_type = 'json'

  def parse_file(self, path):
    super().parse_file(path)

    with open(path, 'r') as f:
      results = json.load(f)

    if not 'target' in results:
      return

    host = self._parse_target(results['target'])
    if not host or host in self.services:
      return

    identifier = host

    service = copy.deepcopy(SERVICE_SCHEMA)
    self.services[identifier] = service

    service['address'] = host

    if 'listeners' in results:
      self._parse_listeners(results['listeners'], service)

    if 'smb_dialects' in results:
      self._parse_smb_dialects(results['smb_dialects'], service)

    if 'smb_domain_info' in results:
      self._parse_smb_domain_info(results['smb_domain_info'], service)

    if 'sessions' in results:
      self._parse_sessions(results['sessions'], service)

    if 'users' in results:
      self._parse_users(results['users'], service)

    if 'shares' in results:
      self._parse_shares(results['shares'], service)

    if 'policy' in results:
      self._parse_policy(results['policy'], service)

    if 'printers' in results:
      self._parse_printers(results['printers'], service)

  def _parse_target(self, target):
    if 'host' not in target:
      return

    return target['host']

  def _parse_listeners(self, listeners, service):
    ports = []
    for listener in listeners.values():
      if listener['accessible'] and listener['port'] not in ports:
        ports.append(str(listener['port']))

    if ports:
      service['misc'].append(f"ports: {', '.join(sorted(ports))}")

  def _parse_smb_dialects(self, smb_dialects, service):
    if 'Supported dialects' in smb_dialects:
      self._parse_supported_dialects(smb_dialects['Supported dialects'], service)

    preferred_protocol = 'unknown'

    if 'Preferred dialect' in smb_dialects:
      dialect = smb_dialects['Preferred dialect']
      m = SMB_DIALECT_PATTERN.fullmatch(dialect)
      if m:
        if m.group('major') == '1':
          preferred_protocol = 'CIFS'
        elif m.group('major') in ['2', '3']:
          preferred_protocol = 'SMB2'
      else:
        self.__class__.logger.error(f"could not parse preferred SMB dialect: '{dialect}'")

    '''
    enum4linux-ng checks the security (i.e. signing required) only for the preferred dialect
    https://github.com/cddmp/enum4linux-ng/blob/276de601a7cec25469eeb0b74c2273e7e49e864a/enum4linux-ng.py#L1114

    enum4linux-ng uses impacket's `smbconnection`,
    which only provides methods to test for "signature required".
    https://github.com/fortra/impacket/blob/master/impacket/smbconnection.py
    '''

    if 'SMB signing required' in smb_dialects:
      service['signing'][preferred_protocol] = {
        'required': smb_dialects['SMB signing required']
      }
    else:
      service['signing'][preferred_protocol] = {
        'required': False
      }

  def _parse_supported_dialects(self, supported_dialects, service):
    for dialect, supported in supported_dialects.items():
      if not supported:
        continue

      # older versions of enum4linux-ng used '2.02' instead of '2.0.2'
      # https://github.com/cddmp/enum4linux-ng/issues/51
      if '2.02' in dialect:
        dialect = dialect.replace('2.02', '2.0.2')

      m = SMB_DIALECT_PATTERN.fullmatch(dialect)

      if not m:
        self.__class__.logger.error(f"could not parse supported SMB dialect: '{dialect}'")
        continue

      if m.group('major') == '1':
        if 'CIFS' not in service['dialects']:
          service['dialects']['CIFS'] = []

        service['dialects']['CIFS'].append("NT LM 0.12")
        continue

      if m.group('major') in ['2', '3']:
        protocol = 'SMB2'
      else:
        protocol = 'unknown'

      if protocol not in service['dialects']:
        service['dialects'][protocol] = []

      dialect = f"{m.group('major')}.{m.group('minor')}"
      if m.group('patch'):
        dialect += f".{m.group('patch')}"

      service['dialects'][protocol].append(dialect)

  def _parse_smb_domain_info(self, smb_domain_info, service):
    for k, v in smb_domain_info.items():
      service['misc'].append(f"{k}: `{v}`")

  def _parse_sessions(self, sessions, service):
    if not sessions.pop('sessions_possible'):
      return

    for session, possible in sessions.items():
      if not possible:
        continue

      match session:
        case 'kerberos' | 'Kerberos':
          if 'Kerberos' not in service['authentication_methods']:
            service['authentication_methods']['Kerberos'] = []
        case 'password' | 'nthash' | 'NTLM':
          self._add_NTLM_authentication(service['authentication_methods'])
        case 'random_user' | 'guest':
          self._add_NTLM_authentication(service['authentication_methods'], 'guest')
        case 'null':
          self._add_NTLM_authentication(service['authentication_methods'], 'anonymous')

  def _add_NTLM_authentication(self, authentication_methods, variation=None):
    if 'NTLM' not in authentication_methods:
      authentication_methods['NTLM'] = []

    if variation and variation not in authentication_methods['NTLM']:
      authentication_methods['NTLM'].append(variation)

  def _parse_users(self, users, service):
    for user_ID, user in users.items():
      description = user['description']
      if SECRETS_PATTERN.search(description):
        service['issues'].append(
          Issue(
            'info leak',
            info = description
          )
        )

      service['misc'].append(f"user account: `{user['username']}` ({user_ID})")

  def _parse_shares(self, shares, service):
    for k, share in shares.items():
      if (
        'access' not in share
        or 'mapping' not in share['access']
        or share['access']['mapping'] != 'ok'
      ):
        continue

      info = f"SMB share: `{k}`"
      if share['comment']:
        info += f" ({share['comment']})"

      service['misc'].append(info)

  def _parse_policy(self, policy, service):
    if 'Domain password information' in policy:
      self._parse_domain_password_information(policy['Domain password information'], service)

    if 'Domain lockout information' in policy:
      self._parse_domain_lockout_information(policy['Domain lockout information'], service)

    if 'Domain logoff information' in policy:
      self._parse_domain_logoff_information(policy['Domain logoff information'], service)

  def _set_AD_password_policy(self, service, policy_name, policy_value):
    if policy_name in service['AD']['password_policy']:
      return

    service['AD']['password_policy'][policy_name] = policy_value

  def _get_seconds(self, duration):
    seconds = 0

    m = DURATION_PATTERN.fullmatch(duration)
    if m:
      if m.group('days'):
        seconds += int(m.group('days')) * 24*60*60
      if m.group('hours'):
        seconds += int(m.group('hours')) * 60*60
      if m.group('minutes'):
        seconds += int(m.group('minutes')) * 60

      return seconds

    m = DURATION_PATTERN_NEW.fullmatch(duration)
    if m:
      if m.group('days'):
        seconds += int(m.group('days')) * 24*60*60
      if m.group('hours'):
        seconds += int(m.group('hours')) * 60*60
      if m.group('minutes'):
        seconds += int(m.group('minutes')) * 60
      if m.group('seconds'):
        seconds += int(m.group('seconds'))
      if m.group('microseconds'):
        seconds += float(m.group('microseconds')) * 10e-6

      return seconds

    m = DURATION_PATTERN_SECONDS.fullmatch(duration)
    if m:
      return float(m.group('seconds'))

    self.__class__.logger.error(f"could not parse duration: '{duration}'")

  def _parse_domain_password_information(self, domain_password_information, service):
    if 'Password history length' in domain_password_information:
      self._set_AD_password_policy(
        service,
        'history_count',
        domain_password_information['Password history length']
      )

    if 'Minimum password length' in domain_password_information:
      self._set_AD_password_policy(
        service,
        'min_length',
        domain_password_information['Minimum password length']
      )

    if 'Maximum password age' in domain_password_information:
      self._set_AD_password_policy(
        service,
        'max_age',
        self._get_seconds(domain_password_information['Maximum password age'])
      )

    if 'Minimum password age' in domain_password_information:
      self._set_AD_password_policy(
        service,
        'min_age',
        self._get_seconds(domain_password_information['Minimum password age'])
      )

    if 'Password properties' in domain_password_information:
      self._parse_password_properties(
        domain_password_information['Password properties'],
        service
      )

  def _parse_password_properties(self, password_properties, service):
    for pwd_property in password_properties:
      for k, v in pwd_property.items():
        match k:
          case 'DOMAIN_PASSWORD_COMPLEX':
            self._set_AD_password_policy(
              service,
              'complexity_required',
              v
            )
          case 'DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT':
            self._set_AD_password_policy(
              service,
              'reversible_encryption',
              v
            )

  def _parse_domain_lockout_information(self, domain_lockout_information, service):
    pass

  def _parse_domain_logoff_information(self, domain_logoff_information, service):
    pass

  def _parse_printers(self, printers, service):
    pass
