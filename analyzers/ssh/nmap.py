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
  parse results of the Nmap SSH scan.

  $ nmap -Pn -sV -p {port} --script="banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods" -oN "{result_file}.log" -oX "{result_file}.xml" {address}
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
        ports [could be multiple]
          port (protocol, portid)
            state (state="open")
            service (name, product, version, extrainfo )
            script (id="ssh-hostkey")
              table [multiple]
                elem (key="type", key="bits")
            script (id="ssh-auth-methods")
              table
                elem [multiple]
            script (id="ssh2-enum-algos")
              table (key="kex_algorithms", key="encryption_algorithms", key="mac_algorithms", key="compression_algorithms")
                elem [multiple]
            script (id="banner", output)
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
        service['port'] = port
        service['transport_protocol'] = transport_protocol

        service_node = port_node.find('service')
        if service_node:
          descriptions = []

          product = service_node.get('product')
          if product:
            descriptions.append(product)

          version = service_node.get('version')
          if version:
            descriptions.append(version)

          service['description'] = " ".join(descriptions)

          service['protocol_version'] = self.parse_protocol_version(service_node.get('extrainfo'))

        for script_node in port_node.iter('script'):
          script_ID = script_node.get('id')

          if script_ID == 'ssh-hostkey':
            service['server_host_keys'] = self.parse_host_key(script_node)

          elif script_ID == 'ssh-auth-methods':
            service['client_authentication_methods'] = self.parse_table(script_node.find('table'))

          elif script_ID == 'ssh2-enum-algos':
            for table_node in script_node.iter('table'):
              table_key = table_node.get('key')

              if table_key == 'kex_algorithms':
                service['key_exchange_methods'] = self.parse_table(table_node)

              elif table_key == 'encryption_algorithms':
                service['encryption_algorithms'] = self.parse_table(table_node)

              elif table_key == 'mac_algorithms':
                service['MAC_algorithms'] = self.parse_table(table_node)

              elif table_key == 'compression_algorithms':
                service['compression_algorithms'] = self.parse_table(table_node)

          elif script_ID == 'banner':
            service['banner'] = script_node.get('output')

  def parse_protocol_version(self, extrainfo):
    if extrainfo:
      m = re.search(
        r'protocol (?P<protocol_version>\d+(\.\d+)?)',
        extrainfo
      )

      return m.group('protocol_version')

  def parse_host_key(self, script_node):
    '''
    <script id="ssh-hostkey" output="...">
      <table>
        <elem key="type">ssh-dss</elem>
        ...
        <elem key="bits">1024</elem>
      </table>
      <table>...</table>
    '''

    keys = []

    for table_node in script_node.iter('table'):
      key = {
        'type': None,
        'size': None
      }

      for elem_node in table_node.iter('elem'):
        element_key = elem_node.get('key')
        if element_key == 'type':
          key['type'] = elem_node.text
        elif element_key == 'bits':
          key['size'] = int(elem_node.text)

      keys.append(key)

    return keys

  def parse_table(self, table_node):
    '''
    <table ...>
      <elem>{info}</elem>
      <elem>{info}</elem>
    </table>
    '''

    info = []
    for elem_node in table_node.iter('elem'):
      info.append(elem_node.text)

    return info
