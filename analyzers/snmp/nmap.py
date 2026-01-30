import copy
import re

try:
  # https://github.com/tiran/defusedxml
  import defusedxml.ElementTree
except:
  sys.exit("this script requires the 'defusedxml' module.\nplease install it via 'pip3 install defusedxml'.")

from .. import Issue, AbstractParser
from . import SERVICE_SCHEMA

class Parser(AbstractParser):
  '''
  parse results of the Nmap SNMP scan.

  nmap -sU -Pn -sV
    -p {port}
    --script="banner,snmp* and not (brute or broadcast or dos or external or fuzzer)"
    --script-args snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt
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
        <address addr="192.168.42.1" addrtype="ipv4"/>
        <address addr="aa:bb:cc:dd:ee:ff" addrtype="mac" vendor="Vendor"/>
        <hostnames>
          <hostname name="example.com" type="PTR"/>
        </hostname>
        <ports>
          <port protocol="tcp" portid="161">
            <state state="open" reason="udp-response" reason_ttl="63"/>
            <service name="snmp" product="net-snmp; net-snmp SNMPv3 server" method="probed" conf="10">
              <cpe>cpe:/a:net-snmp:net-snmp</cpe>
            </service>

            <script id="snmp-*">
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

        for script_node in host_node.findall('./ports/port/script'):
          script_ID = script_node.get('id')

          if script_ID == 'snmp-brute':
            self._parse_snmp_brute(script_node, service)
            continue

          if script_ID == 'snmp-hh3c-logins':
            self._parse_snmp_hh3c_logins(script_node, service)
            continue

          if script_ID == 'snmp-info':
            self._parse_snmp_info(script_node, service)
            continue

          if script_ID == 'snmp-interfaces':
            self._parse_snmp_interfaces(script_node, service)
            continue

          if script_ID == 'snmp-ios-config':
            self._parse_snmp_ios_config(script_node, service)
            continue

          if script_ID == 'snmp-netstat':
            self._parse_snmp_netstat(script_node, service)
            continue

          if script_ID == 'snmp-processes':
            self._parse_snmp_processes(script_node, service)
            continue

          if script_ID == 'snmp-sysdescr':
            self._parse_snmp_sysdescr(script_node, service)
            continue

          if script_ID == 'snmp-win32-services':
            self._parse_snmp_win32_services(script_node, service)
            continue

          if script_ID == 'snmp-win32-software':
            self._parse_snmp_win32_software(script_node, service)
            continue

          if script_ID == 'snmp-win32-users':
            self._parse_snmp_win32_users(script_node, service)
            continue

          if 'snmp' in script_ID:
            self.__class__.logger.info(f"Nmap script scan result not parsed: '{script_ID}'")
            service['info'].append(f"Nmap script scan result not parsed: '{script_ID}'")
            #TODO: implement this

  def _parse_snmp_brute(self, script_node, service):
    # https://svn.nmap.org/nmap/scripts/snmp-brute.nse

    if script_node.get('output') == '':
      return

    '''
    ```
    local request = snmp.buildGetRequest({}, "1.3.6.1.2.1.1.3.0")
    ```
    https://mibs.observium.org/mib/SNMPv2-MIB/#sysUpTime

    ```
    payload = snmp.encode(snmp.buildPacket(request, nil, community))
    ```
    this means, that `SNMPv1` (the default) is used:
    https://nmap.org/nsedoc/lib/snmp.html#new
    '''
    service['versions'].add('SNMPv1')

    for table_node in script_node.iter('table'):
      community_string = table_node.find('./elem[@key="password"]').text
      service['community_strings'].add(community_string)

  def _parse_snmp_hh3c_logins(self, script_node, service):
    # https://svn.nmap.org/nmap/scripts/snmp-hh3c-logins.nse

    if script_node.get('output') == '':
      return

    '''
    ```
    -- h3c-user MIB OIDs (oldoid)
    local h3cUserName = "1.3.6.1.4.1.2011.10.2.12.1.1.1.1"
    local h3cUserPassword = "1.3.6.1.4.1.2011.10.2.12.1.1.1.2"
    local h3cUserLevel = "1.3.6.1.4.1.2011.10.2.12.1.1.1.4"
    ```
    https://mibs.observium.org/mib/H3C-USER-MIB/#h3cUserName
    https://mibs.observium.org/mib/H3C-USER-MIB/#h3cUserPassword
    https://mibs.observium.org/mib/H3C-USER-MIB/#h3cUserLevel

    ```
    -- hh3c-user MIB OIDs (newoid)
    local hh3cUserName = "1.3.6.1.4.1.25506.2.12.1.1.1.1"
    local hh3cUserPassword = "1.3.6.1.4.1.25506.2.12.1.1.1.2"
    local hh3cUserLevel = "1.3.6.1.4.1.25506.2.12.1.1.1.4"
    ```
    https://mibs.observium.org/mib/HH3C-USER-MIB/#hh3cUserName
    https://mibs.observium.org/mib/HH3C-USER-MIB/#hh3cUserPassword
    https://mibs.observium.org/mib/HH3C-USER-MIB/#hh3cUserLevel

    ```
    local snmpHelper = snmp.Helper:new(host, port)
    ```

    this means, that `SNMPv1` (the default) is used:
    https://nmap.org/nsedoc/lib/snmp.html#new
    '''
    service['versions'].add('SNMPv1')

    service['MIB']['hh3cUser'] = "see 'h3cUser'"
    service['MIB']['h3cUser'] = {
      '_info': {
        'ID': 'H3C-USER',
        'URL': 'https://mibs.observium.org/mib/H3C-USER-MIB/',
      },
      'h3cUserObjects': {
        'h3cUserInfoTable': []
      }
    }

    h3cUserInfoTable = service['MIB']['h3cUser']['h3cUserObjects']['h3cUserInfoTable']

    for table_node in script_node.iter('table'):
      h3cUserInfoEntry = {}

      for elem_node in table_node.iter('elem'):
        key = elem_node.get('key')
        match key:
          case 'username':
            key = 'h3cUserName'
          case 'password':
            key = 'h3cUserPassword'
          case 'level':
            key = 'h3cUserLevel'

        value = elem_node.text
        h3cUserInfoEntry[key] = value

      if len(h3cUserInfoEntry):
        h3cUserInfoTable.append(h3cUserInfoEntry)

  def _parse_snmp_info(self, script_node, service):
    # https://svn.nmap.org/nmap/scripts/snmp-info.nse

    if script_node.get('output') == '':
      return

    '''
    > Extracts basic information from an SNMPv3 GET request.
    from the script
    '''
    service['versions'].add('SNMPv3')

    '''
    -- This really only works for User-based Security Model (USM)
    from the script
    '''
    service['security_model'] = 'USM'

    # https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
    enterprise = script_node.find('./elem[@key="enterprise"]').text
    snmpEngineID = script_node.find('./elem[@key="engineIDData"]').text

    # https://mibs.observium.org/mib/SNMP-FRAMEWORK-MIB
    service['MIB']['snmpFrameworkMIB'] = {
      '_info': {
        'ID': 'SNMP-FRAMEWORK',
        'URL': 'https://mibs.observium.org/mib/SNMP-FRAMEWORK-MIB/',
      },
      'snmpFrameworkMIBObjects': {
        'snmpEngine': {
          'snmpEngineID': f'{snmpEngineID} ({enterprise})',
          'snmpEngineBoots': script_node.find('./elem[@key="snmpEngineBoots"]').text,
          'snmpEngineTime': script_node.find('./elem[@key="snmpEngineTime"]').text,
        }
      }
    }

  def _parse_snmp_interfaces(self, script_node, service):
    # https://svn.nmap.org/nmap/scripts/snmp-interfaces.nse

    output = script_node.get('output')

    if output == '':
      return

    '''
    ```
    local if_index = "1.3.6.1.2.1.2.2.1.1."
    local if_descr = "1.3.6.1.2.1.2.2.1.2."
    local if_type = "1.3.6.1.2.1.2.2.1.3."
    local if_speed = "1.3.6.1.2.1.2.2.1.5."
    local if_phys_addr = "1.3.6.1.2.1.2.2.1.6."
    local if_status = "1.3.6.1.2.1.2.2.1.8."
    local if_in_octets = "1.3.6.1.2.1.2.2.1.10."
    local if_out_octets = "1.3.6.1.2.1.2.2.1.16."
    ```
    https://mibs.observium.org/mib/IF-MIB/

    ```
    local ip_addr = "1.3.6.1.2.1.4.20.1.1."
    local ip_netmask = "1.3.6.1.2.1.4.20.1.3."
    ```
    https://mibs.observium.org/mib/IP-MIB/#ipAdEntAddr
    https://mibs.observium.org/mib/IP-MIB/#ipAdEntNetMask

    ```
    local snmpHelper = snmp.Helper:new(host, port)
    ```
    this means, that `SNMPv1` (the default) is used:
    https://nmap.org/nsedoc/lib/snmp.html#new
    '''
    service['versions'].add('SNMPv1')

    service['MIB']['interfaces'] = {
      '_info': {
        'ID': 'IF',
        'URL': 'https://mibs.observium.org/mib/IF-MIB/',
      },
      'ifTable': [],
    }

    ifTable = service['MIB']['interfaces']['ifTable']

    for name, info in re.findall(r'^  (?P<name>.+)$\n(?:^    (?P<info>.+)$\n)', output, flags=re.MULTILINE):
      ifEntry = {
        'ifDescr': name,
      }

      for key_value in re.split(r'\s{2,}', info):
        key, value = key_value.split(': ')

        match key:
          case 'IP address':
            key = 'ip.ipAddrTable.ipAddrEntry.ipAdEntAddr'
          case 'Netmask':
            key = 'ip.ipAddrTable.ipAddrEntry.ipAdEntNetMask'
          case 'Type':
            key = 'ifType'
          case 'Speed':
            key = 'ifSpeed'
          case 'Traffic stats':
            # value: '6.45 Mb sent, 15.01 Mb received'
            values = value.split(', ')

            key = 'ifOutOctets'
            ifEntry[key] = values[0].strip(' sent')

            key = 'ifInOctets'
            value = values[1].strip(' received')

        ifEntry[key] = value

      ifTable.append(ifEntry)

  def _parse_snmp_ios_config(self, script_node, service):
    # https://svn.nmap.org/nmap/scripts/snmp-ios-config.nse

    output = script_node.get('output')

    if output == '':
      return

    '''
    ```
    local request = snmpHelper:set({reqiId=28428},".1.3.6.1.4.1.9.9.96.1.1.1.1.2.9999",1)
    ```
    https://mibs.observium.org/mib/CISCO-CONFIG-COPY-MIB/

    ```
    local snmpHelper = snmp.Helper:new(host, port)
    ```
    this means, that `SNMPv1` (the default) is used:
    https://nmap.org/nsedoc/lib/snmp.html#new
    '''
    service['versions'].add('SNMPv1')

    service['MIB']['ciscoConfigCopy'] = {
      '_info': {
        'ID': 'CISCO-CONFIG-COPY',
        'URL': 'https://mibs.observium.org/mib/CISCO-CONFIG-COPY-MIB/',
      },
      'config': output.strip(),
    }

  def _parse_snmp_netstat(self, script_node, service):
    # https://svn.nmap.org/nmap/scripts/snmp-netstat.nse

    output = script_node.get('output').strip()

    if output == '':
      return

    '''
    ```
    local tcp_oid = "1.3.6.1.2.1.6.13.1.1"
    local udp_oid = "1.3.6.1.2.1.7.5.1.1"
    ```
    https://mibs.observium.org/mib/TCP-MIB/#tcpConnTable
    https://mibs.observium.org/mib/UDP-MIB/#udpTable

    ```
    local snmpHelper = snmp.Helper:new(host, port)
    ```
    this means, that `SNMPv1` (the default) is used:
    https://nmap.org/nsedoc/lib/snmp.html#new
    '''
    service['versions'].add('SNMPv1')

    service['MIB']['tcp'] = {
      '_info': {
        'ID': 'TCP',
        'URL': 'https://mibs.observium.org/mib/TCP-MIB/',
      },
      'tcpConnTable': []
    }
    tcpConnTable = service['MIB']['tcp']['tcpConnTable']

    service['MIB']['udp'] = {
      '_info': {
        'ID': 'UDP',
        'URL': 'https://mibs.observium.org/mib/UDP-MIB/',
      },
      'udpTable': []
    }
    udpTable = service['MIB']['udp']['udpTable']

    for line in output.split('\n'):
      line = line.strip()
      protocol, local, remote = re.split(r'\s+', line)

      local_addr, local_port = local.split(':')
      remote_addr, remote_port = remote.split(':')

      if protocol == 'TCP':
        entry = {
          'tcpConnLocalAddress': local_addr,
          'tcpConnLocalPort': local_port,
          'tcpConnRemAdress': remote_addr,
          'tcpConnRemPort': remote_port,
        }
        tcpConnTable.append(entry)

      elif protocol == 'UDP':
        entry = {
          'udpLocalAddress': local_addr,
          'udpLocalPort': local_port,
        }
        udpTable.append(entry)

  def _parse_snmp_processes(self, script_node, service):
    # https://svn.nmap.org/nmap/scripts/snmp-processes.nse

    if script_node.get('output') == '':
      return

    '''
    ```
    local swrun_name = "1.3.6.1.2.1.25.4.2.1.2"
    local swrun_pid = "1.3.6.1.2.1.25.4.2.1.1"
    local swrun_path = "1.3.6.1.2.1.25.4.2.1.4"
    local swrun_params = "1.3.6.1.2.1.25.4.2.1.5"
    ```
    https://mibs.observium.org/mib/HOST-RESOURCES-MIB/#hrSWRunEntry

    ```
    local snmpHelper = snmp.Helper:new(host, port)
    ```
    this means, that `SNMPv1` (the default) is used:
    https://nmap.org/nsedoc/lib/snmp.html#new
    '''
    service['versions'].add('SNMPv1')

    if 'host' not in service['MIB'] or 'hrSWRun' not in service['MIB']['host']:
      service['MIB']['host'] = {
        '_info': {
          'ID': 'HOST-RESOURCES',
          'URL': 'https://mibs.observium.org/mib/HOST-RESOURCES-MIB/',
        },
        'hrSWRun': {
          'hrSWRunTable': [],
        },
      }
    hrSWRunTable = service['MIB']['host']['hrSWRun']['hrSWRunTable']

    for table_node in script_node.iter('table'):
      hrSWRunEntry = {
        # PID
        'hrSWRunIndex': table_node.get('key'),
      }

      for elem_node in table_node.iter('elem'):
        key = elem_node.get('key')
        if key == 'Params':
          key = 'Parameters'

        key = f'hrSWRun{key}'
        value = elem_node.text
        hrSWRunEntry[key] = value

      # make sure that the entry holds more than just the PID
      if len(hrSWRunEntry.keys()) > 1:
        hrSWRunTable.append(hrSWRunEntry)

    if len(hrSWRunTable) == 0:
      service['MIB'].pop('host')

  def _parse_snmp_sysdescr(self, script_node, service):
    # https://svn.nmap.org/nmap/scripts/snmp-sysdescr.nse

    output = script_node.get('output')

    if output == '':
      return

    '''
    ```
    local status, response = snmpHelper:get({reqId=28428}, "1.3.6.1.2.1.1.1.0")
    ```
    https://mibs.observium.org/mib/SNMPv2-MIB#sysDescr

    ```
    status, response = snmpHelper:get({reqId=28428}, "1.3.6.1.2.1.1.3.0")
    ```
    https://mibs.observium.org/mib/SNMPv2-MIB#sysUpTime

    ```
    local snmpHelper = snmp.Helper:new(host, port)
    ```
    this means, that `SNMPv1` (the default) is used:
    https://nmap.org/nsedoc/lib/snmp.html#new
    '''
    service['versions'].add('SNMPv1')

    descr, uptime = re.split(r'\s{3}System uptime: ', output, flags=re.MULTILINE)

    match = re.search(r'^(?P<uptime_formatted>.+?) \((?P<uptime_raw>\d+) timeticks\)', uptime)

    service['MIB']['system'] = {
      '_info': {
        'ID': 'SNMPv2',
        'URL': 'https://mibs.observium.org/mib/SNMPv2-MIB/',
      },
      'sysDescr': descr,
      'sysUpTime': f"{match['uptime_raw']} ({match['uptime_formatted']})",
    }

  def _parse_snmp_win32_services(self, script_node, service):
    # https://svn.nmap.org/nmap/scripts/snmp-win32-services.nse

    if script_node.get('output') == '':
      return

    '''
    ```
    local snmpoid = "1.3.6.1.4.1.77.1.2.3.1.1"
    ```
    https://mibs.observium.org/mib/LanMgr-Mib-II-MIB/#svSvcName

    ```
    local snmpHelper = snmp.Helper:new(host, port)
    ```
    this means, that `SNMPv1` (the default) is used:
    https://nmap.org/nsedoc/lib/snmp.html#new
    '''
    service['versions'].add('SNMPv1')

    if 'lanmanager' not in service['MIB']:
      service['MIB']['lanmanager'] = {
        '_info': {
          'ID': 'LanMgr-Mib-II',
          'URL': 'https://mibs.observium.org/mib/LanMgr-Mib-II-MIB/',
        },
        'lanmgr-2': {
          'server': {
            'svSvcTable': [],
          }
        }
      }
    elif 'svSvcTable' not in service['MIB']['lanmanager']['lanmgr-2']['server']:
      service['MIB']['lanmanager']['lanmgr-2']['server'] = {
        'svSvcTable': []
      }

    svSvcTable = service['MIB']['lanmanager']['lanmgr-2']['server']['svSvcTable']

    for table_node in script_node.iter('table'):
      for elem_node in table_node.iter('elem'):
        svSvcTable.append({'svSvcName': elem_node.text})

  def _parse_snmp_win32_shares(self, script_node, service):
    # https://svn.nmap.org/nmap/scripts/snmp-win32-shares.nse

    '''
    ```
    local share_name = "1.3.6.1.4.1.77.1.2.27.1.1"
    local share_path = "1.3.6.1.4.1.77.1.2.27.1.2"
    ```
    https://mibs.observium.org/mib/LanMgr-Mib-II-MIB/#svShareName
    https://mibs.observium.org/mib/LanMgr-Mib-II-MIB/#svSharePath

    ```
    local snmpHelper = snmp.Helper:new(host, port)
    ```
    this means, that `SNMPv1` (the default) is used:
    https://nmap.org/nsedoc/lib/snmp.html#new
    '''
    service['versions'].add('SNMPv1')

    if 'lanmanager' not in service['MIB']:
      service['MIB']['lanmanager'] = {
        '_info': {
          'ID': 'LanMgr-Mib-II',
          'URL': 'https://mibs.observium.org/mib/LanMgr-Mib-II-MIB/',
        },
        'lanmgr-2': {
          'server': {
            'svShareTable': [],
          }
        }
      }
    elif 'svShareTable' not in service['MIB']['lanmanager']['lanmgr-2']['server']:
      service['MIB']['lanmanager']['lanmgr-2']['server'] = {
        'svShareTable': []
      }

    svShareTable = service['MIB']['lanmanager']['lanmgr-2']['server']['svShareTable']

    for table_node in script_node.iter('table'):
      for elem_node in table_node.iter('elem'):
        name = elem_node.get('key')
        path = elem_node.text

        svShareTable.append({
          'svShareName': name,
          'svSharePath': path,
        })

  def _parse_snmp_win32_software(self, script_node, service):
    # https://svn.nmap.org/nmap/scripts/snmp-win32-software.nse

    if script_node.get('output') == '':
      return

    '''
    ```
    local sw_name = "^1.3.6.1.2.1.25.6.3.1.2"
    local sw_date = "1.3.6.1.2.1.25.6.3.1.5"
    ```
    https://mibs.observium.org/mib/HOST-RESOURCES-MIB/#hrSWInstalledName
    https://mibs.observium.org/mib/HOST-RESOURCES-MIB/#hrSWInstalledDate

    the `hrSWInstalledDate` is defined in SNMPv2-TC

    ```
    local snmpHelper = snmp.Helper:new(host, port)
    ```
    this means, that `SNMPv1` (the default) is used:
    https://nmap.org/nsedoc/lib/snmp.html#new
    '''
    service['versions'].add('SNMPv1')

    if 'host' not in service['MIB'] or 'hrSWRun' not in service['MIB']['host']:
      service['MIB']['host'] = {
        '_info': {
          'ID': 'HOST-RESOURCES',
          'URL': 'https://mibs.observium.org/mib/HOST-RESOURCES-MIB/',
        },
        'hrSWInstalled': {
          'hrSWInstalledTable': [],
        },
      }
    hrSWInstalledTable = service['MIB']['host']['hrSWInstalled']['hrSWInstalledTable']

    for table_node in script_node.iter('table'):
      entry = {}

      for elem_node in table_node.iter('elem'):
        match elem_node.get('key'):
          case 'name':
            key = 'hrSWInstalledName'
          case 'install_date':
            key = 'hrSWInstalledDate'
        value = elem_node.text
        entry[key] = value

      if len(entry):
        hrSWInstalledTable.append(entry)

  def _parse_snmp_win32_users(self, script_node, service):
    # https://svn.nmap.org/nmap/scripts/snmp-win32-users.nse

    if script_node.get('output') == '':
      return

    '''
    ```
    local snmpoid = "1.3.6.1.4.1.77.1.2.25"
    ```
    https://mibs.observium.org/mib/LanMgr-Mib-II-MIB/#svUserTable

    ```
    local snmpHelper = snmp.Helper:new(host, port)
    ```
    this means, that `SNMPv1` (the default) is used:
    https://nmap.org/nsedoc/lib/snmp.html#new
    '''
    service['versions'].add('SNMPv1')

    if 'lanmanager' not in service['MIB']:
      service['MIB']['lanmanager'] = {
        '_info': {
          'ID': 'LanMgr-Mib-II',
          'URL': 'https://mibs.observium.org/mib/LanMgr-Mib-II-MIB/',
        },
        'lanmgr-2': {
          'server': {
            'svUserTable': [],
          }
        }
      }
    elif 'svUserTable' not in service['MIB']['lanmanager']['lanmgr-2']['server']:
      service['MIB']['lanmanager']['lanmgr-2']['server'] = {
        'svUserTable': []
      }

    svUserTable = service['MIB']['lanmanager']['lanmgr-2']['server']['svUserTable']

    for table_node in script_node.iter('table'):
      for elem_node in table_node.iter('elem'):
        username = elem_node.text
        svUserTable.append(user)

