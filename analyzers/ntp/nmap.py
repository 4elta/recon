import copy
import re

try:
  # https://github.com/tiran/defusedxml
  import defusedxml.ElementTree
except:
  sys.exit("this script requires the 'defusedxml' module.\nplease install it via 'pip3 install defusedxml'.")

from .. import AbstractParser
from . import SERVICE_SCHEMA

class Parser(AbstractParser):
  '''
  parse results of the Nmap NTP scan.

  $ nmap -sU -Pn -sV -p {port} --script="banner,ntp-info,ntp-monlist" -oN "{result_file}.log" -oX "{result_file}.xml" {address}
  '''

  def __init__(self):
    super(self.__class__, self).__init__()

    self.name = 'nmap'
    self.file_type = 'xml'

  def parse_file(self, path):
    super(self.__class__, self).parse_file(path)

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

        transport_protocol = port_node.get('protocol').upper() # tcp/udp
        port = port_node.get('portid') # port number

        identifier = f"{address}:{port} ({transport_protocol})"

        if identifier in self.services:
          continue

        service = copy.deepcopy(SERVICE_SCHEMA)
        self.services[identifier] = service

        service['address'] = address
        service['transport_protocol'] = transport_protocol
        service['port'] = port

        service['version'] = self._parse_version(port_node.find('service'))

        for script_node in port_node.iter('script'):
          script_ID = script_node.get('id')

          if script_ID == 'ntp-monlist':
            service['monlist'] = self._parse_monlist(script_node)

          if script_ID == 'ntp-info':
            service['info'] = self._parse_info(script_node)

  def _parse_version(self, service_node):
    version = service_node.get('version')
    if version:
      m = re.search(
        r'v(?P<version>[^@]+)', # v4.2.8p15@1.3728-o
        version
      )

      return m.group('version')

  def _parse_monlist(self, monlist_node):
    # TODO: properly parse this as soon as we have access to an XML result
    return [ 'TODO' ]

  def _parse_info(self, info_node):
    info = []

    for elem_node in info_node.iter('elem'):
      key = elem_node.get('key')
      if key == 'receive time stamp':
        continue
      value = elem_node.text.strip()
      info.append(f'{key}="{value}"')

    return info
