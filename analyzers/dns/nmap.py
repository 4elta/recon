import copy
import pathlib
import re

try:
  # https://github.com/tiran/defusedxml
  import defusedxml.ElementTree
except:
  sys.exit("this script requires the 'defusedxml' module.\nplease install it via 'pip3 install defusedxml'.")

from . import SERVICE_SCHEMA

class Parser:
  '''
  parse results of the Nmap NTP scan.

  $ nmap -sU -Pn -sV -p {port} --script="banner,ntp-info,ntp-monlist" -oN "{result_file}.log" -oX "{result_file}.xml" {address}
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
        service['info']['rDNS'] = hostname

        for script_node in port_node.iter('script'):
          script_ID = script_node.get('id')

          if script_ID == 'dns-recursion':
            service['recursive'] = self.parse_recursion(script_node)

  def parse_recursion(self, script_node):
    return 'Recursion appears to be enabled' in script_node.get('output')
