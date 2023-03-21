import copy
import pathlib
import re
import xml.etree.ElementTree as ET

try:
  # https://github.com/tiran/defusedxml
  import defusedxml.ElementTree
except:
  sys.exit("this script requires the 'defusedxml' module.\nplease install it via 'pip3 install defusedxml'.")

from . import SERVICE_SCHEMA

class Parser:
  '''
  parse results of the Nmap SSH scan.

  $ nmap -Pn -sV -p ${port} --script="banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" -oN "${result_file}.log" -oX "${result_file}.xml" ${hostname}
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

    nmaprun
      host [could be multiple]
        address ("addr")
        <hostnames>
          <hostname name="example.com" type="user" />
          <hostname name="example.com" type="PTR" />
        </hostnames>
        ports [could be multiple]
          port (protocol, portid)
            state (state="open")
            <service name="http" product="Apache httpd" tunnel="ssl" method="probed" conf="10"/>
            <script id="http-headers" output="&#xa;  Date: Thu, 09 Mar 2023 09:58:15 GMT&#xa;  Server: Apache/2.4.7 (Ubuntu)&#xa;  Accept-Ranges: bytes&#xa;  Vary: Accept-Encoding&#xa;  Connection: close&#xa;  Content-Type: text/html&#xa;  &#xa;  (Request type: HEAD)&#xa;" />
    '''

    nmaprun_node = defusedxml.ElementTree.parse(path).getroot()

    for host_node in nmaprun_node.iter('host'):
      host = host_node.find('address').get('addr')

      for hostname_node in host_node.iter('hostname'):
        if hostname_node.get('type') == 'user':
          host = hostname_node.get('name')
          break

      ports_node = host_node.find('ports')

      for port_node in ports_node.iter('port'):
        if not port_node.find('state').get('state') == 'open':
          continue

        port = port_node.get('portid') # port number

        service_node = port_node.find('service')
        #print(ET.dump(service_node))

        scheme = 'http'
        if service_node.get('tunnel') in ('ssl', 'tls'):
          scheme = 'https'

        identifier = f"{scheme}://{host}:{port}"
        #print(identifier)

        if identifier in self.services:
          continue

        service = copy.deepcopy(SERVICE_SCHEMA)
        self.services[identifier] = service

        service['scheme'] = scheme
        service['host'] = host
        service['port'] = port

        self.parse_http_headers(
          port_node.find("script[@id='http-headers']"),
          service['response_headers']
        )

  def parse_http_headers(self, script_node, response_headers):
    # strip whitespace characters
    output = script_node.get('output').strip()

    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
    p = re.compile(r'\s*(?P<name>[A-Za-z-]+):\s*(?P<value>.+)\s*')

    for header in output.split('\n'):
      match = p.match(header)

      if not match:
        continue

      header_name = match.group('name').lower()
      header_value = match.group('value')

      if header_name not in response_headers:
        response_headers[header_name] = []

      response_headers[header_name].append(header_value)
