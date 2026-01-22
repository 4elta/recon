import copy
import re

try:
  # https://github.com/tiran/defusedxml
  import defusedxml.ElementTree
except ImportError:
  import sys
  sys.exit("this script requires the 'defusedxml' module.\nplease install it via 'pip3 install defusedxml'.")

from .. import Issue, AbstractParser
from . import SERVICE_SCHEMA

class Parser(AbstractParser):
  '''
  parse results of the Nmap NTP scan.

  $ nmap -sU -Pn -sV -p {port} --script="banner,ntp-info,ntp-monlist" -oN "{result_file}.log" -oX "{result_file}.xml" {address}
  '''

  def __init__(self):
    super().__init__()

    self.name = 'nmap'
    self.file_type = 'xml'

  def parse_file(self, path):
    super().parse_file(path)

    '''
    https://nmap.org/book/nmap-dtd.html

    nmaprun
      host [could be multiple]
        address ("addr")
        ports [could be multiple]
          port (protocol, portid)
            state (state="open")
            service (version)
            script (id="ntp-info")
              elem (key="type") [multiple]
            script (id="ntp-monlist")
    '''

    nmaprun_node = defusedxml.ElementTree.parse(path).getroot()

    for host_node in nmaprun_node.iter('host'):
      address = host_node.find('address').get('addr')

      for port_node in host_node.iter('port'):
        if port_node.find('state').get('state') != 'open':
          continue

        transport_protocol = port_node.get('protocol') # tcp/udp
        port = port_node.get('portid') # port number

        identifier = f"{address}:{port} ({transport_protocol})"

        if identifier in self.services:
          continue

        service = copy.deepcopy(SERVICE_SCHEMA)
        self.services[identifier] = service

        service['address'] = address
        #service['transport_protocol'] = transport_protocol
        service['port'] = port

        service['version'] = self._parse_version(port_node.find('service'))

        for script_node in port_node.iter('script'):
          script_ID = script_node.get('id')

          if script_ID == 'ntp-monlist':
            service['issues'].append(
              Issue(
                "mode 7",
                version = 2,
                implementation = 3,
                req_code = 42,
              )
            )
            service['misc'] += self._parse_monlist(script_node)
            continue

          if script_ID == 'ntp-info':
            self._parse_info(script_node, service)
            continue

          if 'ntp' in script_ID:
            self.__class__.logger.info(f"Nmap script scan result not parsed: '{script_ID}'")
            service['info'].append(f"Nmap script scan result not parsed: '{script_ID}'")
            #TODO: implement this

  def _parse_version(self, service_node):
    version = service_node.get('version')
    if version:
      m = re.search(
        r'v(?P<version>[^@]+)', # v4.2.8p15@1.3728-o
        version,
      )

      return m.group('version')

  def _parse_monlist(self, monlist_node):
    addresses = []

    assoc_type = None
    for line in monlist_node.get('output').split('\n'):
      if re.match(r'  \w', line):
        assoc_type = line.strip().lower()

        if assoc_type == 'alternative target interfaces:':
          assoc_type = re.sub(r's:$', '', assoc_type)
        elif re.match(r'(public|private) (client|server|peer)s \(\d+\)', assoc_type):
          assoc_type = re.sub(r's \(\d+\)$', '', assoc_type)
        elif re.match(r'other associations \(\d+\)', assoc_type):
          assoc_type = re.sub(r's \(\d+\)$', '', assoc_type)

      if re.match('   ', line):
        for address in re.split(r'\s+', line.strip()):
          addresses.append(f"{assoc_type}: {address}")

    return addresses

  def _parse_info(self, info_node, service):
    mode_6 = False

    for elem_node in info_node.iter('elem'):
      key = elem_node.get('key')
      if key == 'receive time stamp':
        continue

      mode_6 = True
      value = elem_node.text.strip()
      service['misc'].append(f"`{key}={value}`")

    if mode_6:
      service['issues'].append(
        Issue(
          "mode 6",
          version = 2,
          opcode = 2,
        )
      )
