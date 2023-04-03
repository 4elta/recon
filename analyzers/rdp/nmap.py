import copy
import pathlib
import re

try:
  # https://github.com/tiran/defusedxml
  import defusedxml.ElementTree
except:
  sys.exit("this script requires the 'defusedxml' module.\nplease install it via 'pip3 install defusedxml'.")

from . import SERVICE_SCHEMA

ENCRYPTION_LEVELS = {
  'Low': 'ENCRYPTION_LEVEL_LOW',
  'Client Compatible': 'ENCRYPTION_LEVEL_CLIENT',
  'High': 'ENCRYPTION_LEVEL_HIGH',
  'FIPS Compliant': 'ENCRYPTION_LEVEL_FIPS',
}

class Parser:
  '''
  parse results of the Nmap RDP scan.

  $ nmap -sT -sU -Pn -sV -p {port} --script="banner,rdp-enum-encryption" -oN "{result_file}.log" -oX "{result_file}.xml" {address}
  '''

  name = 'nmap'
  file_type = 'xml'

  def __init__(self):
    self.services = {}

  def parse_files(self, files):
    for path in files[self.file_type]:
      self.parse_file(path)

    return self.services

  def parse_file(self, path):
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
          <port protocol="tcp" portid="3389">
            <state state="open" .../>
            <service name="ms-wbt-server" product="xrdp" method="probed" conf="10">...</service>
            <script id="rdp-enum-encryption" output="..." />
          </port>
          <port protocol="udp" portid="3389">
          ...
          </port>
        </ports>
    '''

    nmaprun_node = defusedxml.ElementTree.parse(path).getroot()

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

        for script_node in port_node.iter('script'):
          script_ID = script_node.get('id')

          if script_ID == 'rdp-enum-encryption':
            self.parse_rdp_enum_encryption(script_node, service)

  def parse_rdp_enum_encryption(self, script_node, service):
    script_output = script_node.get('output')

    patterns_PROTOCOL = {
      'PROTOCOL_RDP': 'Native RDP: SUCCESS',
      'PROTOCOL_SSL': 'SSL: SUCCESS',
      'PROTOCOL_HYBRID': 'CredSSP (NLA): SUCCESS',
      'PROTOCOL_RDSTLS': 'RDSTLS: SUCCESS',
      'PROTOCOL_HYBRID_EX': 'CredSSP with Early User Auth: SUCCESS',
      #'PROTOCOL_RDSAAD': ,
    }

    for key, pattern in patterns_PROTOCOL.items():
      if pattern in script_output:
        service['protocols'].append(key)

    regex_ENCRYPTION_LEVEL = re.compile(r'RDP Encryption level: (Low|Client Compatible|High|FIPS Compliant)')
    m = regex_ENCRYPTION_LEVEL.search(script_output)
    if not m:
      service['encryption_level'] = 'ENCRYPTION_LEVEL_NONE'
    if m:
      service['encryption_level'] = ENCRYPTION_LEVELS[m.group(1)]

    pattern_NLA = 'CredSSP (NLA): SUCCESS'
    if pattern_NLA in script_output:
      service['NLA'] = True