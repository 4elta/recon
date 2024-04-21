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
        port protocol="tcp" portid="139">
                <state state="open" reason="syn-ack" reason_ttl="127"/>
                <service name="netbios-ssn" product="Microsoft Windows netbios-ssn" ostype="Windows" method="probed" conf="10">
                    <cpe>cpe:/o:microsoft:windows</cpe>
                </service>
                <script id="smb-enum-services" output="ERROR: Script execution failed (use -d to debug)"/>
            </port>
        </ports>
        <hostscript>
            <script id="smb2-capabilities" output=...>
            <script id="smb-protocols" output="&#xa;  dialects: &#xa;    NT LM 0.12 (SMBv1) [dangerous, but default]&#xa;    2:0:2&#xa;    2:1:0&#xa;    3:0:0&#xa;    3:0:2&#xa;    3:1:1">
                <table key="dialects">
                    <elem>NT LM 0.12 (SMBv1) [dangerous, but default]</elem>
                    <elem>2:0:2</elem>
                    <elem>2:1:0</elem>
                    <elem>3:0:0</elem>
                    <elem>3:0:2</elem>
                    <elem>3:1:1</elem>
                </table>
            </script>
            ...
            </hostscript>
    '''
    try:
      nmaprun_node = defusedxml.ElementTree.parse(path).getroot()
    except defusedxml.ElementTree.ParseError as parse_error:
      print(f"Could not parse XML file: {parse_error}: {path}")
      exit(-1)

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

        service['info'] = []
       
        for sub_node in port_node.iter('service'):
          service_name = sub_node.get('name')
          if 'netbios-ssn' in service_name:
            service['netbios'] = True

        for hscript_node in host_node.iter('hostscript'):
          for script_node in hscript_node.iter('script'):
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
              service['netbios'] = True
              service['nbstat_info'] = script_node.get('output').replace('\n', ',')

            if 'smb' in script_ID:
              service['info'].append(f"Nmap script scan result not parsed: '{script_ID}'")
              #TODO: implement this

  def _parse_smb_protocols(self,script_node, service):
    for elem_node in script_node.iter('elem'):
      key = elem_node.get('key')
      value = elem_node.text
      dialect = value.split(':')[0]

      if 'NT LM' in dialect:
        service['smb_dialects'].append(value.replace('[dangerous, but default]', ''))
        continue
      
      service['smb_dialects'].append(re.sub('[:.]', '', value))

  def _parse_smb2_security_mode(self, script_node, service):
    for elem_node in script_node.iter('elem'):
      key = elem_node.get('key')
      value = elem_node.text

      if 'enabled and required' in value:
        service['smb2_signing']['enabled'] = True
        service['smb2_signing']['required'] = True

      if 'enabled but not required' in value:
        service['smb2_signing']['enabled'] = True
        service['smb2_signing']['required'] = False

      if 'disabled!' in value:
        service['smb2_signing']['enabled'] = False
        service['smb2_signing']['required'] = True

      if 'disabled and not required!' in value:
        service['smb2_signing']['enabled'] = False
        service['smb2_signing']['required'] = False

  def _parse_smb_security_mode(self, script_node, service):
    for elem_node in script_node.iter('elem'):
      key = elem_node.get('key')
      value = elem_node.text

      if 'message_signing' in key:
        if 'required' in value:
          service['cifs_signing']['enabled'] = True
          service['cifs_signing']['required'] = True

        if 'supported' in value:
          service['cifs_signing']['enabled'] = True
          service['cifs_signing']['required'] = False

        if 'disabled' in value:
          service['cifs_signing']['enabled'] = False
          service['cifs_signing']['required'] = False
