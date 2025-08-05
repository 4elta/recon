import copy
import datetime
import json
import re

from .. import Issue, AbstractParser
from . import SERVICE_SCHEMA, USER_SCHEMA

SMB_DIALECT_PATTERN = re.compile(r'SMB (?P<major>\d+)\.(?P<minor>\d+)(\.(?P<patch>\d+))?')

# see https://github.com/cddmp/enum4linux-ng/pull/56
DURATION_PATTERN = re.compile(r'(?:(?P<days>\d+) days?)?(?: \(\d+ years?\))? ?(?:(?P<hours>\d+) hours?)? ?(?:(?P<minutes>\d+) minutes?)?')
DURATION_PATTERN_NEW = re.compile(r'(?:(?P<days>\d+) days?, )?(?P<hours>\d+):(?P<minutes>\d+):(?P<seconds>\d+)(?:.(?P<microseconds>\d+))? \(hours:minutes:seconds\)')
DURATION_PATTERN_SECONDS = re.compile(r'(?P<seconds>[\d.,]+) seconds')

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
    self.__class__.logger.debug("parsing listeners ...")
    ports = []
    for key, listener in listeners.items():
      if listener['accessible'] and listener['port'] not in ports:
        port = listener['port']
        ports.append(str(port))
        self.__class__.logger.debug(f"{key} ({port})")

    if ports:
      service['misc'].append(f"ports: {', '.join(sorted(ports))}")

  def _parse_smb_dialects(self, smb_dialects, service):
    if 'Supported dialects' in smb_dialects:
      self._parse_supported_dialects(smb_dialects['Supported dialects'], service)

    preferred_protocol = 'unknown'

    if 'Preferred dialect' in smb_dialects:
      dialect = smb_dialects['Preferred dialect']
      self.__class__.logger.debug(f"parsing preferred protocol: '{dialect}'")
      m = SMB_DIALECT_PATTERN.fullmatch(dialect)
      if not m:
        self.__class__.logger.error("could not parse protocol")
        return

      if m.group('major') == '1':
        preferred_protocol = 'CIFS'
      elif m.group('major') in ['2', '3']:
        preferred_protocol = 'SMB2'
      else:
        self.__class__.logger.error("could not parse protocol")
        return

    self.__class__.logger.debug(f"preferred protocol: {preferred_protocol}")

    '''
    enum4linux-ng checks the security (i.e. signing required) only for the preferred dialect
    https://github.com/cddmp/enum4linux-ng/blob/276de601a7cec25469eeb0b74c2273e7e49e864a/enum4linux-ng.py#L1114

    enum4linux-ng uses impacket's `smbconnection`,
    which only provides methods to test for "signature required".
    https://github.com/fortra/impacket/blob/master/impacket/smbconnection.py
    '''

    if 'SMB signing required' in smb_dialects:
      self.__class__.logger.debug("signing required")
      service['signing'][preferred_protocol] = {
        'required': smb_dialects['SMB signing required']
      }
    else:
      self.__class__.logger.debug("signing not required")
      service['signing'][preferred_protocol] = {
        'required': False
      }

  def _parse_supported_dialects(self, supported_dialects, service):
    self.__class__.logger.debug("parsing supported dialects ...")

    for dialect, supported in supported_dialects.items():
      if not supported:
        continue

      self.__class__.logger.debug(dialect)

      # older versions of enum4linux-ng used '2.02' instead of '2.0.2'
      # https://github.com/cddmp/enum4linux-ng/issues/51
      if '2.02' in dialect:
        self.__class__.logger.debug("replacing '2.02' with '2.0.2'")
        dialect = dialect.replace('2.02', '2.0.2')

      m = SMB_DIALECT_PATTERN.fullmatch(dialect)

      if not m:
        self.__class__.logger.error(f"could not parse supported SMB dialect: '{dialect}'")
        continue

      if m.group('major') == '1':
        if 'CIFS' not in service['dialects']:
          service['dialects']['CIFS'] = []

        service['dialects']['CIFS'].append("NT LM 0.12")
        self.__class__.logger.debug("adding 'NT LM 0.12' to the list of supported CIFS dialects")
        continue

      if m.group('major') in ['2', '3']:
        protocol = 'SMB2'
      else:
        self.__class__.logger.error("unknown protocol")
        protocol = 'unknown'

      if protocol not in service['dialects']:
        service['dialects'][protocol] = []

      dialect = f"{m.group('major')}.{m.group('minor')}"
      if m.group('patch'):
        dialect += f".{m.group('patch')}"

      self.__class__.logger.debug(f"adding '{dialect}' to the list of supported {protocol} dialects")
      service['dialects'][protocol].append(dialect)

  def _parse_smb_domain_info(self, smb_domain_info, service):
    self.__class__.logger.debug("parsing SMB domain info ...")
    for k, v in smb_domain_info.items():
      self.__class__.logger.debug(f"{k}: `{v}`")
      service['misc'].append(f"{k}: `{v}`")

  def _parse_sessions(self, sessions, service):
    self.__class__.logger.debug("parsing session ...")

    if not sessions.pop('sessions_possible'):
      return

    for session, possible in sessions.items():
      if not possible:
        continue

      self.__class__.logger.debug(session)

      match session:
        case 'kerberos' | 'Kerberos':
          self.__class__.logger.debug("Kerberos authentication")
          if 'Kerberos' not in service['authentication_methods']:
            service['authentication_methods']['Kerberos'] = []
        case 'password' | 'nthash' | 'NTLM':
          self.__class__.logger.debug("NTLM authentication")
          self._add_NTLM_authentication(service['authentication_methods'])
        case 'random_user' | 'guest':
          self.__class__.logger.debug("NTLM authentication")
          self._add_NTLM_authentication(service['authentication_methods'], 'guest')
        case 'null':
          self.__class__.logger.debug("NTLM authentication")
          self._add_NTLM_authentication(service['authentication_methods'], 'anonymous')

  def _add_NTLM_authentication(self, authentication_methods, variation=None):
    if 'NTLM' not in authentication_methods:
      authentication_methods['NTLM'] = []

    if variation and variation not in authentication_methods['NTLM']:
      self.__class__.logger.debug(f"adding '{variation}' to NTLM variations")
      authentication_methods['NTLM'].append(variation)

  def _parse_users(self, users, service):
    for RID, user_info in users.items():
      user = copy.deepcopy(USER_SCHEMA)
      service['AD']['users'][RID] = user

      user['name'] = user_info['username']

      if 'name' in user_info and user_info['name'] != "(null)":
        user['full_name'] = user_info['name']

      if 'acb' in user_info:
        user['AC'] = int(user_info['acb'], 16)

      if 'description' in user_info:
        user['description'] = user_info['description']

  def _parse_shares(self, shares, service):
    self.__class__.logger.debug("parsing shares ...")

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

      self.__class__.logger.debug(f"additional info: '{info}'")
      service['misc'].append(info)

  def _parse_policy(self, policy, service):
    if 'Domain password information' in policy:
      self._parse_domain_password_information(policy['Domain password information'], service['AD']['domain'])

    if 'Domain lockout information' in policy:
      self._parse_domain_lockout_information(policy['Domain lockout information'], service['AD']['domain'])

    if 'Domain logoff information' in policy:
      self._parse_domain_logoff_information(policy['Domain logoff information'], service['AD']['domain'])

  def _parse_domain_password_information(self, domain_password_information, domain_info):
    if 'Password history length' in domain_password_information:
      password_history_length = domain_password_information['Password history length']
      if password_history_length is None:
        password_history_length = 0
      domain_info['password_history_length'] = password_history_length

    if 'Minimum password length' in domain_password_information:
      min_password_length = domain_password_information['Minimum password length']
      if min_password_length is None:
        min_password_length = 0
      domain_info['min_password_length'] = min_password_length

    if 'Maximum password age' in domain_password_information:
      duration = self._parse_duration(domain_password_information['Maximum password age'])
      domain_info['max_password_age'] = duration

    if 'Minimum password age' in domain_password_information:
      duration = self._parse_duration(domain_password_information['Minimum password age'])
      domain_info['min_password_age'] = duration

    if 'Password properties' in domain_password_information:
      self._parse_password_properties(
        domain_password_information['Password properties'],
        domain_info
      )

  def _parse_domain_lockout_information(self, domain_lockout_information, domain_info):
    if 'Lockout observation window' in domain_lockout_information:
      duration = self._parse_duration(domain_lockout_information['Lockout observation window'])
      domain_info['lockout_observation_window'] = duration

    if 'Lockout duration' in domain_lockout_information:
      duration = self._parse_duration(domain_lockout_information['Lockout duration'])
      domain_info['lockout_duration'] = duration

    if 'Lockout threshold' in domain_lockout_information:
      lockout_threshold = domain_lockout_information['Lockout threshold']
      if lockout_threshold is None:
        lockout_threshold = 0

      domain_info['lockout_threshold'] = lockout_threshold

  def _parse_domain_logoff_information(self, domain_logoff_information, domain_info):
    if 'Force logoff time' in domain_logoff_information:
      duration = self._parse_duration(domain_logoff_information['Force logoff time'])
      domain_info['force_logoff'] = duration

  def _parse_printers(self, printers, service):
    pass #TODO

  def _parse_password_properties(self, password_properties, domain_info):
    domain_info['password_properties'] = {}

    for pwd_property in password_properties:
      for k, v in pwd_property.items():
        match k:
          case 'DOMAIN_PASSWORD_COMPLEX':
            domain_info['password_properties']['complex'] = v
          case 'DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT':
            domain_info['password_properties']['store_cleartext'] = v

  def _parse_duration(self, duration):
    self.__class__.logger.debug(f"parsing duration '{duration}' ...")
    seconds = 0

    if duration in ['not set', 'none']:
      self.__class__.logger.debug(f"{seconds} seconds")
      return seconds

    m = DURATION_PATTERN.fullmatch(duration)
    if m:
      self.__class__.logger.debug(f"using '{DURATION_PATTERN.pattern}'")
      if m.group('days'):
        seconds += int(m.group('days')) * 24*60*60
      if m.group('hours'):
        seconds += int(m.group('hours')) * 60*60
      if m.group('minutes'):
        seconds += int(m.group('minutes')) * 60

      self.__class__.logger.debug(f"{seconds} seconds")
      return seconds

    m = DURATION_PATTERN_NEW.fullmatch(duration)
    if m:
      self.__class__.logger.debug(f"using '{DURATION_PATTERN_NEW.pattern}'")
      if m.group('days'):
        seconds += int(m.group('days')) * 24*60*60
      if m.group('hours'):
        seconds += int(m.group('hours')) * 60*60
      if m.group('minutes'):
        seconds += int(m.group('minutes')) * 60
      if m.group('seconds'):
        seconds += int(m.group('seconds'))
      if m.group('microseconds'):
        seconds += int(m.group('microseconds')) * 10e-6

      self.__class__.logger.debug(f"{seconds} seconds")
      return seconds

    m = DURATION_PATTERN_SECONDS.fullmatch(duration)
    if m:
      self.__class__.logger.debug(f"using '{DURATION_PATTERN_SECONDS.pattern}'")
      seconds = float(m.group('seconds'))
      self.__class__.logger.debug(f"{seconds} seconds")
      return seconds

    self.__class__.logger.error(f"could not parse duration")
    return 0
