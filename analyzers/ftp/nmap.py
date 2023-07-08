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
  parse results of the Nmap FTP scan.

  $ nmap -sT -sU -Pn -sV -p {port} --script="banner,ssl-cert,ftp* and not (brute or broadcast or dos or external or fuzzer)" -oN "{result_file}.log" -oX "{result_file}.xml" {address}
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
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <address addr="aa:bb:cc:dd:ee:ff" addrtype="mac" vendor="Vendor"/>
        <hostnames>
          <hostname name="example.com" type="PTR"/>
        </hostname>
        <ports>
          <port protocol="tcp" portid="21">
            <state state="open" .../>
            <script id="ssl-cert" output="..." />
            <script id="ftp-anon" output="..." />
            <script id="ftp-bounce" output="..." />
            <script id="ftp-proftpd-backdoor" output="..." />
            <script id="ftp-vsftpd-backdoor" output="..." />
            <script id="ftp-vuln-cve2010-4221" output="..." />
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

        # https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=ftps
        if port == '990':
          service['FTPS'] = True

        for script_node in port_node.iter('script'):
          script_ID = script_node.get('id')

          if script_ID == 'ssl-cert':
            service['FTPS'] = True

          if script_ID == 'ftp-anon':
            self._parse_ftp_anon(script_node, service)

          if script_ID == 'ftp-bounce':
            self._parse_ftp_bounce(script_node, service)

          if script_ID == 'ftp-proftpd-backdoor':
            self._parse_ftp_proftpd_backdoor(script_node, service)

          if script_ID == 'ftp-vsftpd-backdoor':
            self._parse_ftp_vsftpd_backdoor(script_node, service)

          if script_ID == 'ftp-vuln-cve2010-4221':
            self._parse_ftp_vuln_cve2010_4221(script_node, service)

  def _parse_ftp_anon(self, script_node, service):
    # https://nmap.org/nsedoc/scripts/ftp-anon.html

    script_output = script_node.get('output')

    if 'Anonymous FTP login allowed' in script_output:
      service['anonymous'] = True

  def _parse_ftp_bounce(self, script_node, service):
    # https://nmap.org/nsedoc/scripts/ftp-bounce.html

    script_output = script_node.get('output')

    if 'bounce working!' in script_output:
      service['issues'].append('server allows bouncing')

    if 'server forbids bouncing to low ports <1025' in script_output:
      service['issues'].append('server forbids bouncing to low ports <1025')

  def _parse_ftp_proftpd_backdoor(self, script_node, service):
    # https://nmap.org/nsedoc/scripts/ftp-proftpd-backdoor.html

    script_output = script_node.get('output')

    if 'This installation has been backdoored.' in script_output:
      service['issues'].append("the server seems to be running a version of ProFTPD that contains a backdoor (i.e. `1.3.3c`)")

  def _parse_ftp_vsftpd_backdoor(self, script_node, service):
    # https://nmap.org/nsedoc/scripts/ftp-vsftpd-backdoor.html

    script_output = script_node.get('output')

    if 'State: VULNERABLE (Exploitable)' in script_output:
      service['issues'].append("the server seems to be running a version of vsFTPd that contains a backdoor (i.e. `2.3.4`)")

  def _parse_ftp_vuln_cve2010_4221(self, script_node, service):
    # https://nmap.org/nsedoc/scripts/ftp-vuln-cve2010-4221.html

    script_output = script_node.get('output')

    if 'State: VULNERABLE' in script_output:
      service['issues'].append("the server seems to be running a version of ProFTPD that contains a buffer-overflow vulnerability (i.e. versions `1.3.2rc3` through `1.3.3b`)")
