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
  #            self._parse_rdp_enum_encryption(script_node, service)
              continue

            if script_ID == 'smb2-security-mode':
              self._parse_smb2_security_mode(script_node, service)
  #            self._parse_rdp_ntlm_info(script_node, service)
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
      if 'LM' in dialect or '2' in dialect:
        service['smb_dialects'].append(value)

  def _parse_smb2_security_mode(self, script_node, service):
    for elem_node in script_node.iter('elem'):
      key = elem_node.get('key')
      value = elem_node.text
      if 'not' in value or 'disabled' in value:
        service['smb_signing'] = value

  def _parse_smb_security_mode(self, script_node, service):
    for elem_node in script_node.iter('elem'):
      key = elem_node.get('key')
      value = elem_node.text
      if 'message_signing' in key:
        if 'disabled' in value:
          service['smbv1_signing'] = True
