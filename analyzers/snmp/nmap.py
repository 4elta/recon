"""
Parser for SNMP results extracted from Nmap XML scans.
Handles various host address formats with fallback.
"""

import copy
import ipaddress
import re
import xml.etree.ElementTree as ET
from .. import AbstractParser
from . import SERVICE_SCHEMA

class Parser(AbstractParser):
  """
  Nmap XML parser for SNMP services.
  Extracts SNMP port, protocol, community strings, system description, and script outputs.
  """
  def __init__(self):
    super().__init__()
    self.name = 'nmap'
    self.file_type = 'xml'

  def parse_file(self, path):
    super().parse_file(path)
    try:
      tree = ET.parse(path)
      root = tree.getroot()
    except ET.ParseError as e:
      self.__class__.logger.warning('Could not parse XML file %s: %s', path, e)
      return self.services

    for host in root.findall('host'):
      # Try IPv4, then IPv6, then any address element
      address_elem = host.find('address[@addrtype="ipv4"]')
      if address_elem is None:
        address_elem = host.find('address[@addrtype="ipv6"]')
      if address_elem is None:
        address_elem = host.find('address')
      if address_elem is None:
        self.__class__.logger.debug(f'No address element found in host, skipping host: {ET.tostring(host)[:200]}')
        continue
      
      address = address_elem.get('addr')
      if not address:
        self.__class__.logger.debug(f'Address element missing addr attribute, skipping host: {ET.tostring(host)[:200]}')
        continue
      self.__class__.logger.debug('Processing host with address: %s', address)

      for port in host.findall('.//port'):
        port_id = port.get('portid')
        protocol = port.get('protocol', 'udp')
        self.__class__.logger.debug('Processing port %s/%s', port_id, protocol)

        svc = port.find('service')
        if svc is None or 'snmp' not in svc.get('name', '').lower():
          continue

        identifier = f"{address}:{port_id} ({protocol})"
        service = copy.deepcopy(SERVICE_SCHEMA)
        service['address'] = address
        service['port'] = int(port_id)
        service['transport_protocol'] = protocol
        # Initialize Nmap-specific misc field for structured script data
        service['misc'] = {}
        self.__class__.logger.debug('Found SNMP service: %s', identifier)

        product = svc.get('product', '')
        extrainfo = svc.get('extrainfo', '')
        self.__class__.logger.debug('Service product: %s, extrainfo: %s', product, extrainfo)

        # Initial version detection from service product
        if 'SNMPv1' in product:
          service['version'] = 'SNMPv1'
          self.__class__.logger.debug('Detected SNMP version from product: SNMPv1')
        elif 'SNMPv2' in product or 'SNMPv2c' in product:
          service['version'] = 'SNMPv2c'
          self.__class__.logger.debug('Detected SNMP version from product: SNMPv2c')
        elif 'SNMPv3' in product:
          service['version'] = 'SNMPv3'
          self.__class__.logger.debug('Detected SNMP version from product: SNMPv3')

        if extrainfo and extrainfo.strip():
          community = extrainfo.strip()
          service['community_strings'].append(community)
          self.__class__.logger.debug('Found community string: %s', community)

        # Track which scripts succeeded to help with version detection
        successful_scripts = []

        for script in port.findall('script'):
          sid = script.get('id')
          out = script.get('output', '')
          service['script_outputs'][sid] = out
          self.__class__.logger.debug('Processing script %s, output length: %d', sid, len(out) if out else 0)

          # Check if script failed (has ERROR in output)
          if out and ('ERROR:' in out or 'error:' in out.lower()):
            self.__class__.logger.debug('Script %s failed: %s', sid, out[:100])
            continue

          # Parse each script with dedicated function
          script_succeeded = False
          if sid == 'snmp-sysdescr':
            self._parse_snmp_sysdescr(script, service)
            script_succeeded = True
          elif sid == 'snmp-info':
            self._parse_snmp_info(script, service)
            script_succeeded = True
          elif sid == 'snmp-interfaces':
            self._parse_snmp_interfaces(script, service)
            script_succeeded = True
          elif sid == 'snmp-processes':
            self._parse_snmp_processes(script, service)
            script_succeeded = True
          elif sid == 'snmp-netstat':
            self._parse_snmp_netstat(script, service)
            script_succeeded = True
          elif sid == 'snmp-win32-software':
            self._parse_snmp_win32_software(script, service)
            script_succeeded = True
          elif sid == 'snmp-win32-services':
            self._parse_snmp_win32_services(script, service)
            script_succeeded = True
          elif sid == 'snmp-win32-shares':
            self._parse_snmp_win32_shares(script, service)
            script_succeeded = True
          elif sid == 'snmp-win32-users':
            self._parse_snmp_win32_users(script, service)
            script_succeeded = True
          elif sid == 'snmp-ios-config':
            self._parse_snmp_ios_config(script, service)
            script_succeeded = True
          elif sid == 'snmp-hh3c-logins':
            self._parse_snmp_hh3c_logins(script, service)
            script_succeeded = True

          # Only add to successful scripts if it actually succeeded and has meaningful output
          if script_succeeded and out and out.strip():
            successful_scripts.append(sid)
            self.__class__.logger.debug('Script %s succeeded', sid)

        # Refine version detection based on successful scripts and their outputs
        # SNMP version detection logic based on NSE script results:
        # - SNMPv3: snmp-info with engine info, no community strings, or explicit v3 mentions
        # - SNMPv2c: scripts work with community strings, most modern scripts default to v2c
        # - SNMPv1: older patterns, explicit v1 mentions, or limited script compatibility
        if not service['version']:
          detected_version = self._detect_version_from_script_analysis(service, successful_scripts)
          if detected_version:
            service['version'] = detected_version
            self.__class__.logger.debug('Detected SNMP version from script analysis: %s', detected_version)

        self.__class__.logger.debug('Final service version: %s', service['version'])
        self.__class__.logger.debug('Final community strings: %s', service['community_strings'])

        self.services[identifier] = service

    return self.services

  def _parse_snmp_sysdescr(self, script_node, service):
    """Parse snmp-sysdescr script output."""
    # https://nmap.org/nsedoc/scripts/snmp-sysdescr.html
    out = script_node.get('output', '')
    if out:
      service['system_description'] = out
      # Parse structured data if available
      if 'misc' not in service:
        service['misc'] = {}
      if 'sysdescr' not in service['misc']:
        service['misc']['sysdescr'] = {}
      
      # Extract uptime if present
      uptime_match = re.search(r'System uptime:\s*(.+?)(?:\s*\(|$)', out)
      if uptime_match:
        service['misc']['sysdescr']['uptime'] = uptime_match.group(1).strip()
      
      service['misc']['sysdescr']['descr'] = out
      self.__class__.logger.debug('Extracted system description: %s', out[:100] if out else 'None')

  def _parse_snmp_info(self, script_node, service):
    """Parse snmp-info script output."""
    # https://nmap.org/nsedoc/scripts/snmp-info.html
    if 'misc' not in service:
      service['misc'] = {}
    service['misc']['info'] = {}
    
    # Parse structured XML output
    for elem_node in script_node.findall('.//elem'):
      key = elem_node.get('key')
      value = elem_node.text
      if key == 'enterprise':
        service['misc']['info']['enterprise'] = value
      elif key == 'engineIDFormat':
        service['misc']['info']['engineIDFormat'] = value
      elif key == 'engineIDData':
        service['misc']['info']['engineIDData'] = value
      elif key == 'snmpEngineBoots':
        service['misc']['info']['snmpEngineBoots'] = value
      elif key == 'snmpEngineTime':
        service['misc']['info']['snmpEngineTime'] = value
    
    self.__class__.logger.debug('Parsed snmp-info data')

  def _parse_snmp_interfaces(self, script_node, service):
    """Parse snmp-interfaces script output."""
    # https://nmap.org/nsedoc/scripts/snmp-interfaces.html
    if 'misc' not in service:
      service['misc'] = {}
    service['misc']['interfaces'] = {}
    
    # Parse table structure
    for table_node in script_node.findall('.//table'):
      iface_index = table_node.get('key')
      if not iface_index:
        continue
      
      interface_data = {}
      for elem_node in table_node.findall('.//elem'):
        key = elem_node.get('key')
        value = elem_node.text
        if key == 'IP address':
          interface_data['IP address'] = value
          # Also add to network_interfaces list if valid IPv4/IPv6
          try:
            ip = ipaddress.ip_address(value)
            service['network_interfaces'].append(value)
          except ValueError:
            # Not a valid IP address, skip
            pass
        elif key == 'MAC address':
          interface_data['MAC address'] = value
        elif key == 'type':
          interface_data['type'] = value
      
      if interface_data:
        service['misc']['interfaces'][iface_index] = interface_data
    
    self.__class__.logger.debug('Parsed %d interfaces from snmp-interfaces', len(service['misc']['interfaces']))

  def _parse_snmp_processes(self, script_node, service):
    """Parse snmp-processes script output."""
    # https://nmap.org/nsedoc/scripts/snmp-processes.html
    if 'misc' not in service:
      service['misc'] = {}
    service['misc']['processes'] = {}
    
    # Parse table structure
    for table_node in script_node.findall('.//table'):
      pid = table_node.get('key')
      if not pid:
        continue
      
      process_data = {}
      for elem_node in table_node.findall('.//elem'):
        key = elem_node.get('key')
        value = elem_node.text
        if key == 'name':
          process_data['name'] = value
        elif key == 'path':
          process_data['path'] = value
        elif key == 'params':
          process_data['params'] = value
      
      if process_data:
        service['misc']['processes'][pid] = process_data
        # Also add to software_info for backward compatibility
        if 'name' in process_data:
          service['software_info'].append(process_data['name'])
    
    self.__class__.logger.debug('Parsed %d processes from snmp-processes', len(service['misc']['processes']))

  def _parse_snmp_netstat(self, script_node, service):
    """Parse snmp-netstat script output."""
    # https://nmap.org/nsedoc/scripts/snmp-netstat.html
    if 'misc' not in service:
      service['misc'] = {}
    service['misc']['netstat'] = []
    
    # Parse table structure
    for table_node in script_node.findall('.//table'):
      connection_data = {}
      for elem_node in table_node.findall('.//elem'):
        key = elem_node.get('key')
        value = elem_node.text
        if key == 'transport protocol':
          connection_data['transport protocol'] = value
        elif key == 'local':
          connection_data['local'] = value
        elif key == 'remote':
          connection_data['remote'] = value
      
      if connection_data:
        service['misc']['netstat'].append(connection_data)
    
    self.__class__.logger.debug('Parsed %d netstat entries', len(service['misc']['netstat']))

  def _parse_snmp_win32_software(self, script_node, service):
    """Parse snmp-win32-software script output."""
    # https://nmap.org/nsedoc/scripts/snmp-win32-software.html
    if 'misc' not in service:
      service['misc'] = {}
    service['misc']['win32-software'] = []
    
    # Parse table structure
    for table_node in script_node.findall('.//table'):
      software_data = {}
      for elem_node in table_node.findall('.//elem'):
        key = elem_node.get('key')
        value = elem_node.text
        if key == 'name':
          software_data['name'] = value
        elif key == 'date':
          software_data['date'] = value
      
      if software_data:
        service['misc']['win32-software'].append(software_data)
        # Also add to software_info for backward compatibility
        if 'name' in software_data:
          service['software_info'].append(software_data['name'])
    
    self.__class__.logger.debug('Parsed %d software entries from snmp-win32-software', len(service['misc']['win32-software']))

  def _parse_snmp_win32_services(self, script_node, service):
    """Parse snmp-win32-services script output."""
    # https://nmap.org/nsedoc/scripts/snmp-win32-services.html
    if 'misc' not in service:
      service['misc'] = {}
    service['misc']['win32-services'] = []
    
    # Parse table structure or simple list
    for table_node in script_node.findall('.//table'):
      service_name = table_node.get('key')
      if service_name:
        service['misc']['win32-services'].append(service_name)
      else:
        # Try to extract from elem nodes
        for elem_node in table_node.findall('.//elem'):
          if elem_node.text:
            service['misc']['win32-services'].append(elem_node.text)
    
    self.__class__.logger.debug('Parsed %d services from snmp-win32-services', len(service['misc']['win32-services']))

  def _parse_snmp_win32_shares(self, script_node, service):
    """Parse snmp-win32-shares script output."""
    # https://nmap.org/nsedoc/scripts/snmp-win32-shares.html
    if 'misc' not in service:
      service['misc'] = {}
    service['misc']['win32-shares'] = []
    
    # Parse table structure
    for table_node in script_node.findall('.//table'):
      share_data = {}
      for elem_node in table_node.findall('.//elem'):
        key = elem_node.get('key')
        value = elem_node.text
        if key == 'name':
          share_data['name'] = value
        elif key == 'path':
          share_data['path'] = value
      
      if share_data:
        service['misc']['win32-shares'].append(share_data)
    
    self.__class__.logger.debug('Parsed %d shares from snmp-win32-shares', len(service['misc']['win32-shares']))

  def _parse_snmp_win32_users(self, script_node, service):
    """Parse snmp-win32-users script output."""
    # https://nmap.org/nsedoc/scripts/snmp-win32-users.html
    if 'misc' not in service:
      service['misc'] = {}
    service['misc']['win32-users'] = []
    
    # Parse table structure or simple list
    for table_node in script_node.findall('.//table'):
      username = table_node.get('key')
      if username:
        service['misc']['win32-users'].append(username)
      else:
        # Try to extract from elem nodes
        for elem_node in table_node.findall('.//elem'):
          if elem_node.text:
            service['misc']['win32-users'].append(elem_node.text)
    
    self.__class__.logger.debug('Parsed %d users from snmp-win32-users', len(service['misc']['win32-users']))

  def _parse_snmp_ios_config(self, script_node, service):
    """Parse snmp-ios-config script output."""
    # https://nmap.org/nsedoc/scripts/snmp-ios-config.html
    if 'misc' not in service:
      service['misc'] = {}
    service['misc']['ios-config'] = []
    
    # Parse output lines
    out = script_node.get('output', '')
    if out:
      lines = [line.strip() for line in out.split('\n') if line.strip()]
      service['misc']['ios-config'] = lines
    
    self.__class__.logger.debug('Parsed %d lines from snmp-ios-config', len(service['misc']['ios-config']))

  def _parse_snmp_hh3c_logins(self, script_node, service):
    """Parse snmp-hh3c-logins script output."""
    # https://nmap.org/nsedoc/scripts/snmp-hh3c-logins.html
    if 'misc' not in service:
      service['misc'] = {}
    service['misc']['hh3c-logins'] = {}
    
    # Parse table structure
    for table_node in script_node.findall('.//table'):
      login_id = table_node.get('key')
      if not login_id:
        continue
      
      login_data = {}
      for elem_node in table_node.findall('.//elem'):
        key = elem_node.get('key')
        value = elem_node.text
        if key == 'h3cUserName':
          login_data['h3cUserName'] = value
        elif key == 'h3cUserPassword':
          login_data['h3cUserPassword'] = value
        elif key == 'h3cUserLevel':
          login_data['h3cUserLevel'] = value
        elif key == 'h3cUserState':
          login_data['h3cUserState'] = value
      
      if login_data:
        service['misc']['hh3c-logins'][login_id] = login_data
    
    self.__class__.logger.debug('Parsed %d logins from snmp-hh3c-logins', len(service['misc']['hh3c-logins']))

  def _detect_version_from_script_analysis(self, service, successful_scripts):
    """
    Detect SNMP version by analyzing script outputs and compatibility.
    
    Version detection strategy:
    1. Check for explicit version mentions in script outputs
    2. Check for SNMPv3-specific indicators (engine info, no communities)
    3. Analyze which scripts succeeded and their version compatibility
    4. Use community string presence as indicator (v1/v2c vs v3)
    5. Check for version-specific error patterns
    """
    script_outputs = service.get('script_outputs', {})
    
    # Step 1: Check for explicit version mentions in any script output
    for sid in successful_scripts:
      output = script_outputs.get(sid, '')
      if not output:
        continue
      
      output_lower = output.lower()
      
      # Check for explicit version mentions
      if 'snmpv3' in output_lower or 'snmp version 3' in output_lower or 'version 3' in output_lower:
        self.__class__.logger.debug('Found explicit SNMPv3 mention in %s', sid)
        return 'SNMPv3'
      elif 'snmpv2c' in output_lower or 'snmp version 2c' in output_lower:
        self.__class__.logger.debug('Found explicit SNMPv2c mention in %s', sid)
        return 'SNMPv2c'
      elif 'snmpv2' in output_lower and 'snmpv2c' not in output_lower:
        # Could be v2 or v2c, but v2 is rare - likely v2c
        self.__class__.logger.debug('Found explicit SNMPv2 mention in %s', sid)
        return 'SNMPv2c'
      elif 'snmpv1' in output_lower or 'snmp version 1' in output_lower or 'version 1' in output_lower:
        self.__class__.logger.debug('Found explicit SNMPv1 mention in %s', sid)
        return 'SNMPv1'
    
    # Step 2: Check for SNMPv3-specific indicators
    info_data = service.get('misc', {}).get('info', {})
    if info_data.get('engineIDFormat') or info_data.get('engineIDData') or \
       info_data.get('snmpEngineBoots') or info_data.get('snmpEngineTime'):
      self.__class__.logger.debug('Found SNMPv3 engine information in snmp-info')
      return 'SNMPv3'
    
    # Check if we have community strings - v3 uses users, not communities
    has_communities = bool(service.get('community_strings'))
    
    # Step 3: Analyze script compatibility and outputs
    # Most Nmap SNMP scripts default to trying v2c first, then v1, then v3
    # If scripts succeeded, analyze which version they likely used
    
    if successful_scripts:
      # Check for SNMPv3 indicators: no communities but scripts worked
      if not has_communities:
        # No community strings but scripts succeeded - likely v3 with authentication
        self.__class__.logger.debug('Scripts succeeded without community strings - likely SNMPv3')
        return 'SNMPv3'
      
      # With community strings, it's v1 or v2c
      # Check for v1-specific indicators
      v1_indicators = self._check_for_snmpv1_indicators(service, successful_scripts, script_outputs)
      if v1_indicators:
        self.__class__.logger.debug('Found SNMPv1 indicators in script outputs')
        return 'SNMPv1'
      
      # Default: if scripts worked with communities, assume v2c
      # (most modern scripts default to v2c, and v2c is more common than v1)
      self.__class__.logger.debug('Scripts succeeded with community strings - defaulting to SNMPv2c')
      return 'SNMPv2c'
    
    # No scripts succeeded and no version detected
    return None

  def _check_for_snmpv1_indicators(self, service, successful_scripts, script_outputs):
    """
    Check for indicators that suggest SNMPv1 rather than SNMPv2c.
    
    SNMPv1 indicators:
    - Explicit v1 mentions in outputs
    - Specific error patterns more common in v1
    - Limited script compatibility (some scripts don't work well with v1)
    - Older MIB object access patterns
    """
    for sid in successful_scripts:
      output = script_outputs.get(sid, '')
      if not output:
        continue
      
      output_lower = output.lower()
      
      # Explicit v1 mentions
      if 'snmpv1' in output_lower or 'snmp version 1' in output_lower:
        return True
      
      # SNMPv1-specific error patterns
      # v1 uses different error codes than v2c/v3
      if 'nosuchname' in output_lower or 'toobig' in output_lower:
        # These error codes are more common in v1
        # But not definitive - could also occur in v2c
        pass
      
      # Check for v1-specific limitations in script outputs
      # Some scripts may report limitations when using v1
      if 'v1' in output_lower and ('limit' in output_lower or 'not support' in output_lower):
        return True
    
    # Check script compatibility - some scripts are less likely to work with v1
    # If we have many modern scripts working, less likely to be v1
    modern_scripts = ['snmp-info', 'snmp-interfaces', 'snmp-netstat', 'snmp-processes']
    modern_script_count = sum(1 for s in successful_scripts if s in modern_scripts)
    
    # If we have many modern scripts working, likely v2c
    # If we have few/old scripts, could be v1
    if modern_script_count == 0 and len(successful_scripts) > 0:
      # Only older/basic scripts worked - could be v1
      # But this is weak evidence
      pass
    
    return False
