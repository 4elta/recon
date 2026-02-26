import copy
import re

try:
  # https://github.com/tiran/defusedxml
  import defusedxml.ElementTree
except:
  sys.exit("this script requires the 'defusedxml' module.\nplease install it via 'pip3 install defusedxml'.")

from ... import Issue, AbstractParser
from .. import SERVICE_SCHEMA

class Parser(AbstractParser):
  '''
  parse results of the Nmap script scan.

  TODO: use the actual command (from `scanner.toml`)
  nmap -sU -Pn -sV
    -p {port}
    --script="banner,xyz* and not (brute or broadcast or dos or external or fuzzer)"
    -oN "{result_file}.log" -oX "{result_file}.xml"
    {address}
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
        <address addr="192.0.2.42" addrtype="ipv4"/>
        <address addr="2001:db8:a:b:c:d:e:f" addrtype="ipv6"/>
        <address addr="00:00:5e:00:53:00" addrtype="mac" vendor="Vendor"/>
        <hostnames>
          <hostname name="example.com" type="PTR"/>
        </hostname>
        <ports>
          <port protocol="tcp" portid="42">

            ...

            <script id="xyz">
              ...
            </script>

            ...

          </port>
        </ports>
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

        # TODO: further parsing if necessary

        # parse the results of the Nmap scripts
        for script_node in port_node.findall('./script'):
          match script_node.get('id'):
            case 'xyz': # TODO: change to the actual script ID
              self._parse_xyz(script_node, service)
            case _:
              self.__class__.logger.info(f"Nmap script scan result not parsed: '{script_ID}'")
              service['info'].append(f"Nmap script scan result not parsed: '{script_ID}'")
              # TODO: implement this


  def _parse_xyz(self, script_node, service):
    # TODO: add a link to the script's source
    # e.g.: https://svn.nmap.org/nmap/scripts/xyz.nse

    if script_node.get('output') == '':
      return

    # TODO: implement this
