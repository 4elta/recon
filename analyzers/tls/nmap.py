import copy
import re

try:
  # https://github.com/tiran/defusedxml
  import defusedxml.ElementTree
except:
  sys.exit("this script requires the 'defusedxml' module.\nplease install it via 'pip3 install defusedxml'.")

from .. import AbstractParser
from . import CERTIFICATE_SCHEMA, SERVICE_SCHEMA

PROTOCOL_VERSIONS = {
  'SSLv2': 'SSL 2.0',
  'SSLv3': 'SSL 3.0',
  'TLSv1.0': 'TLS 1.0',
  'TLSv1.1': 'TLS 1.1',
  'TLSv1.2': 'TLS 1.2',
  'TLSv1.3': 'TLS 1.3'
}

class Parser(AbstractParser):
  '''
  parse results of the Nmap TLS scan.

  $ nmap -Pn -sV -p {port} --script="banner,ssl*" -oN "{result_file}.log" -oX "{result_file}.xml" {address}
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
            service (name)
            script (id="ssl-cert")
              table (key="subject")
              table (key="issuer")
              table (key="pubkey")
              table (key="extensions")
                table (elem: key="name"; value: "X509v3 Subject Alternative Name")
              table (key="validity")
              elem (key="sig_algo")
            script (id="ssl-enum-ciphers")
              table (key="<TLS version>")
                table (key="ciphers")
                  table [multiple]
                    elem (key="name")
                    elem (key="kex_info")
                table (key="compressors")
                elem (key="cipher preference")
    '''

    nmaprun_node = defusedxml.ElementTree.parse(path).getroot()

    for host_node in nmaprun_node.iter('host'):
      address = host_node.find('address').get('addr')

      host = address

      hostnames_node = host_node.find('hostnames')
      if hostnames_node is not None:
        hostname_node = hostnames_node.find("hostname[@type='user']")
        if hostname_node is not None:
          host = hostname_node.get('name')

      for port_node in host_node.iter('port'):
        if port_node.find('state').get('state') != 'open':
          continue

        transport_protocol = port_node.get('protocol') # tcp/udp
        port = port_node.get('portid') # port number

        identifier = f"{host}:{port} ({transport_protocol})"

        if identifier in self.services:
          continue

        service = copy.deepcopy(SERVICE_SCHEMA)
        self.services[identifier] = service

        service['host'] = host
        service['port'] = port
        service['transport_protocol'] = transport_protocol

        service_node = port_node.find('service')
        if service_node is not None:
          service['application_protocol'] = service_node.get('name')

        for script_node in port_node.findall('./script'):
          script_ID = script_node.get('id')

          if script_ID == 'ssl-cert':
            self._parse_certificate(script_node, service)

          if script_ID == 'ssl-enum-ciphers':
            self._parse_cipher_suites(script_node, service)

          if script_ID in ('ssl-heartbleed', 'ssl-known-key', 'ssl-poodle', 'sslv2-drown'):
            service['issues'].append(f"Nmap script scan result not parsed: {script_ID}")
            #TODO: parse results

  def _parse_certificate_subject_node(self, node, subjects):
    common_name_node = node.find('./elem[@key="commonName"]')
    if common_name_node is not None:
      subjects.append(common_name_node.text)

  def _parse_certificate_pk_node(self, node, public_key):
    public_key['bits'] = int(node.find('./elem[@key="bits"]').text)

    pk_type = node.find('./elem[@key="type"]').text

    if pk_type == 'ec':
      pk_type = 'ECDSA'
      public_key['curve'] = node.find('./table/table/elem[@key="curve"]').text

    if pk_type == 'rsa':
      pk_type = 'RSA'

    public_key['type'] = pk_type

  def _parse_certificate_SAN_node(self, node, subjects):
    elem_node = node.find('./table[elem="X509v3 Subject Alternative Name"]/elem[@key="value"]')

    if elem_node is None:
      return

    for altname in elem_node.text.split(', '):
      subject = altname.split(':')[1]
      if subject not in subjects:
        subjects.append(subject)

  def _parse_certificate_validity_node(self, node, validity):
    # 2023-06-01T22:20:23
    validity['not_before'] = node.find('./elem[@key="notBefore"]').text.replace('T', ' ')
    validity['not_after'] = node.find('./elem[@key="notAfter"]').text.replace('T', ' ')

  def _parse_certificate(self, script_node, service):
    certificate = copy.deepcopy(CERTIFICATE_SCHEMA)
    service['certificates'].append(certificate)

    for table_node in script_node.findall('./table'):
      table_key = table_node.get('key')

      if table_key == 'subject':
        self._parse_certificate_subject_node(
          table_node,
          certificate['subjects']
        )

      elif table_key == 'pubkey':
        self._parse_certificate_pk_node(
          table_node,
          certificate['public_key']
        )

      elif table_key == 'extensions':
        self._parse_certificate_SAN_node(
          table_node,
          certificate['subjects']
        )

      elif table_key == 'validity':
        self._parse_certificate_validity_node(
          table_node,
          certificate['validity']
        )

    sig_algo_node = script_node.find('./elem[@key="sig_algo"]')
    if sig_algo_node is not None:
      certificate['signature_algorithm'] = sig_algo_node.text

  def _parse_protocol_node(self, node, service):
    protocol_version = PROTOCOL_VERSIONS[node.get('key')]
    service['protocol_versions'].append(protocol_version)

    for cipher_node in node.findall('./table[@key="ciphers"]/table'):
      cipher_name = cipher_node.find('./elem[@key="name"]').text

      if protocol_version == 'TLS 1.3':
        # TLS_AKE_WITH_CHACHA20_POLY1305_SHA256
        cipher_name = cipher_name.replace('AKE_WITH_', '')

      if cipher_name not in service['cipher_suites']:
        service['cipher_suites'].append(cipher_name)

      key_exchange = service['key_exchange']

      kex_info = cipher_node.find('./elem[@key="kex_info"]').text

      if re.match(r'(dh|rsa) \d+', kex_info):
        kex_type, kex_bits = kex_info.split(' ')
        kex = ( kex_type.upper(), int(kex_bits) )
      else: # ECDH
        kex = ( 'ECDH', None ) # TODO: parse bits
        if kex_info not in key_exchange['groups']:
          key_exchange['groups'].append(kex_info)

      kex_methods = key_exchange['methods']
      if kex[0] not in kex_methods:
        kex_methods[kex[0]] = kex[1]
      elif kex[1] and kex_methods[kex[0]] and kex[1] < kex_methods[kex[0]]:
        kex_methods[kex[0]] = kex[1]

    compressor_node = node.find('./table[@key="compressors"]')
    if compressor_node and compressor_node.find('./elem').text != 'NULL':
      if 'CRIME' not in service['vulnerabilities']:
        service['vulnerabilities'].append('CRIME')

    cipher_pref_node = node.find('./elem[@key="cipher preference"]')
    if cipher_pref_node:
      cipher_preference = cipher_pref_node.text
      #TODO: how to handle the situation where this different for each protocol version (e.g. TLS 1.2: client; TLS 1.3: server)?

  def _parse_cipher_suites(self, script_node, service):
    for protocol_table in script_node.findall('./table'):
      table_key = protocol_table.get('key')
      if 'TLS' in table_key or 'SSL' in table_key:
        self._parse_protocol_node(
          protocol_table,
          service
        )

