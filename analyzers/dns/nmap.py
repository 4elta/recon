import copy

try:
  # https://github.com/tiran/defusedxml
  import defusedxml.ElementTree
except ImportError:
  import sys
  sys.exit("this script requires the 'defusedxml' module.\nplease install it via 'pip3 install defusedxml'.")

from .. import AbstractParser
from . import SERVICE_SCHEMA

class Parser(AbstractParser):
  '''
  parse results of the Nmap DNS scan.

  $ nmap -sT -sU -Pn -sV -p {port} --script="banner,dns-cache-snoop,dns-nsec-enum,dns-recursion,dns-nsec3-enum,dns-zone-transfer" --script-args="dns-zone-transfer.domain={domain}" -oN "{result_file}.log" -oX "{result_file}.xml" {address}
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
          <port protocol="tcp" portid="53">
            <state state="open" .../>
            <service name="domain" product="Cloudflare public DNS" .../>
            <script id="dns-nsec3-enum" output="&#xa;  DNSSEC NSEC3 not supported&#xa;"/>
          </port>
          <port protocol="udp" portid="53">
            <state state="open" .../>
            <service name="domain" product="Cloudflare public DNS" .../>
            <script id="dns-cache-snoop" output="10 of 100 tested domains are cached.&#xa;google.com&#xa;..."/>
            <script id="dns-nsec-enum" output="&#xa;  No NSEC records found&#xa;"/>
            <script id="dns-recursion" output="Recursion appears to be enabled"/>
            <script id="dns-nsec3-enum" output="&#xa;  DNSSEC NSEC3 not supported&#xa;"/>
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

      hostname = None

      hostnames_node = host_node.find('hostnames')
      if hostnames_node is not None:
        hostname_node = hostnames_node.find("hostname[@type='PTR']")
        if hostname_node is not None:
          hostname = hostname_node.get('name')
        else:
          hostname_node = hostnames_node.find("hostname[@type='user']")
          if hostname_node is not None:
            hostname = hostname_node.get('name')

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
        service['port'] = port
        service['transport_protocol'] = transport_protocol

        if hostname:
          service['misc']['rDNS'] = hostname

        for script_node in port_node.iter('script'):
          script_ID = script_node.get('id')

          if script_ID == 'dns-recursion':
            service['recursive'] = 'Recursion appears to be enabled' in script_node.get('output')
            continue

          if script_ID == 'dns-zone-transfer':
            zone = []
            for line in script_node.get('output').splitlines():
              if line.strip():
                zone.append(line.strip())
            service['AXFR'] = zone
            continue

          if script_ID == 'fingerprint-strings':
            for elem_node in script_node.iter('elem'):
              elem_key = elem_node.get('key')
              if elem_key.startswith('DNSVersionBindReq'):
                service['misc']['version.bind'] = elem_node.text.splitlines()[-1].strip()
            continue

          if 'dns' in script_ID:
            self.__class__.logger.info(f"Nmap script scan result not parsed: '{script_ID}'")
            service['info'].append(f"Nmap script scan result not parsed: '{script_ID}'")
            #TODO: parse results

