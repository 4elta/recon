import copy
import re

try:
  # https://github.com/tiran/defusedxml
  import defusedxml.ElementTree
except:
  sys.exit("this script requires the 'defusedxml' module.\nplease install it via 'pip3 install defusedxml'.")

from .. import Issue, AbstractParser
from . import SERVICE_SCHEMA

class Parser(AbstractParser):
  '''
  parse results of the Nmap SMB scan.

  $ nmap $([[ "{transport_protocol}" == "udp" ]] && echo "-sU") -Pn -sV -p {port} --script="banner,(nbstat or smb*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{result_file}.log" -oX "{result_file}.xml" {address}
  '''

  def __init__(self):
    super().__init__()

    self.name = 'nmap'
    self.file_type = 'xml'

  def parse_file(self, path):
    super().parse_file(path)

    '''
    https://nmap.org/book/nmap-dtd.html

    <nmaprun ...>
      <host ...>
        <address addr="192.168.42.1" addrtype="ipv4"/>
        <address addr="aa:bb:cc:dd:ee:ff" addrtype="mac" vendor="Vendor"/>
        <hostnames>
          <hostname name="example.com" type="PTR"/>
        </hostname>
        <ports>
          <port protocol="tcp" portid="139">
            <state state="open" reason="syn-ack" reason_ttl="127"/>
            <service name="netbios-ssn" product="Microsoft Windows netbios-ssn" ostype="Windows" method="probed" conf="10">
              <cpe>cpe:/o:microsoft:windows</cpe>
            </service>
            <script id="smb-enum-services" output="ERROR: Script execution failed (use -d to debug)"/>
          </port>
        </ports>
        <hostscript>
          <script id="smb-protocols">
            <table key="dialects">
              <elem>NT LM 0.12 (SMBv1) [dangerous, but default]</elem>
              <elem>2.0.2</elem>
              <elem>2.1</elem>
              <elem>3.0</elem>
              <elem>3.0.2</elem>
              <elem>3.1.1</elem>
            </table>
          </script>
          <script id="smb2-security-mode">
            <table key="3.1.1">
              <elem>Message signing enabled but not required</elem>
            </table>
          </script>
          <script id="smb-security-mode">
            <elem key="account_used">guest</elem>
            <elem key="authentication_level">user</elem>
            <elem key="challenge_response">supported</elem>
            <elem key="message_signing">disabled</elem>
          </script>
          <script id="nbstat" output="...">
            ...
          </script>
          ...
        </hostscript>
    '''

    try:
      nmaprun_node = defusedxml.ElementTree.parse(path).getroot()
    except defusedxml.ElementTree.ParseError as e:
      sys.exit(f"error parsing file '{path}': {e}")

    for host_node in nmaprun_node.iter('host'):
      address = None

      for address_node in host_node.iter('address'):
        if address_node.get('addrtype') in ('ipv4', 'ipv6'):
          address = address_node.get('addr')
          break

      if address is None:
        continue

      for port_node in host_node.iter('port'):
        if port_node.find('state').get('state') != 'open':
          continue

        transport_protocol = port_node.get('protocol').upper() # TCP/UDP
        port = port_node.get('portid') # port number

        identifier = f"{address}:{port} ({transport_protocol})"

        if identifier in self.services:
          continue

        service = copy.deepcopy(SERVICE_SCHEMA)
        self.services[identifier] = service

        service['address'] = address
        service['transport_protocol'] = transport_protocol
        service['port'] = port
       
        for script_node in host_node.findall('./hostscript/script'):
          script_ID = script_node.get('id')

          if script_ID == 'smb-protocols':
            self._parse_smb_protocols(script_node, service)
            continue

          if script_ID == 'smb2-security-mode':
            self._parse_smb2_security_mode(script_node, service)
            continue

          if script_ID == 'smb-security-mode':
            self._parse_smb_security_mode(script_node, service)
            continue

          if script_ID == 'nbstat':
            for nbstat in script_node.get('output').replace('\n', ',').split(','):
              service['misc'].append(nbstat.strip())
            continue

          if 'smb' in script_ID:
            service['info'].append(f"Nmap script scan result not parsed: '{script_ID}'")
            #TODO: implement this

  def _parse_smb_protocols(self, script_node, service):
    '''
    with SMB/CIFS, the dialect is specified/negotiated via a string (e.g. 'NT LM 0.12'):
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/25c8c3c9-58fc-4bb8-aa8f-0272dede84c5
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/80850595-e301-4464-9745-58e4945eb99b

    with SMB2, the dialect is specified/negotiated via an integer (e.g. 0x210 for 2.1; 0x311 for 3.1.1):
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fac3655a-7eb5-4337-b0ab-244bbcd014e8
    '''

    dialect_SMB2_pattern = re.compile(r'(?P<major>\d+).(?P<minor>\d+)(.(?P<patch>\d+))?')

    for elem_node in script_node.findall('./table[@key="dialects"]/elem'):
      value = elem_node.text

      m = dialect_SMB2_pattern.fullmatch(value)

      if not m:
        if 'CIFS' not in service['dialects']:
          service['dialects']['CIFS'] = []

        service['dialects']['CIFS'].append("NT LM 0.12")
        continue

      if m.group('major') in ["2", "3"]:
        protocol = "SMB2"
      else:
        protocol = "unknown"

      if protocol not in service['dialects']:
        service['dialects'][protocol] = []

      dialect = f"{m.group('major')}.{m.group('minor')}"
      if m.group('patch'):
        dialect += f".{m.group('patch')}"

      service['dialects'][protocol].append(dialect)

  def _parse_smb2_security_mode(self, script_node, service):
    # https://nmap.org/nsedoc/scripts/smb2-security-mode.html

    elem_node = script_node.find('./table/elem')
    if elem_node is None:
      return

    value = elem_node.text

    if 'enabled and required' in value:
      signing_info = {
        "enabled": True,
        "required": True
      }

    if 'enabled but not required' in value:
      signing_info = {
        "enabled": True,
        "required": False
      }

    if 'disabled and not required!' in value:
      signing_info = {
        "enabled": False,
        "required": False
      }

    if 'disabled!' in value:
      signing_info = {
        "enabled": False,
        "required": True
      }

    service['signing']['SMB2'] = signing_info

  def _parse_smb_security_mode(self, script_node, service):
    # https://nmap.org/nsedoc/scripts/smb-security-mode.html

    for elem_node in script_node.iter('./elem'):
      key = elem_node.get('key')
      value = elem_node.text

      if key == 'message_signing':
        if 'required' in value:
          signing_info = {
            "enabled": True,
            "required": True
          }

        if 'supported' in value:
          signing_info = {
            "enabled": True,
            "required": False
          }

        if 'disabled' in value:
          signing_info = {
            "enabled": False,
            "required": False
          }

        service['signing']['CIFS'] = signing_info
