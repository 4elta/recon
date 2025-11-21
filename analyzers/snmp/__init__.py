"""
SNMP analyzer module: identifies security issues based on SNMP scan results.
"""

import ipaddress
import re
from .. import Issue, AbstractAnalyzer

SERVICE_SCHEMA = {
  'address': None,  # IP address of the SNMP service
  'port': None,  # port number
  'transport_protocol': None,  # transport protocol, e.g. "udp" or "tcp"
  'version': None,  # SNMP version, e.g. "SNMPv1", "SNMPv2c", "SNMPv3"
  'community_strings': [],  # list of community strings discovered
  'system_description': None,  # system description from SNMP sysDescr
  'software_info': [],  # software information from SNMP enumeration scripts
  'network_interfaces': [],  # list of IP addresses found in network interfaces
  'script_outputs': {},  # raw output from Nmap SNMP scripts
  'issues': [],  # list of security issues identified
}

class Analyzer(AbstractAnalyzer):
  """
  Analyzer for SNMP services. Flags insecure protocol versions,
  default community strings, public exposure, and information disclosure.
  """
  def analyze(self, files):
    super().analyze(files)
    services = self.parser.parse_files(files)
    self.services = services

    for service in services.values():
      issues = service.setdefault('issues', [])

      # Determine public/private IP address
      try:
        addr = service.get('address')
        if addr:
          ip = ipaddress.ip_address(addr)
          service['public'] = ip.is_global
          service['private'] = ip.is_private
      except ValueError:
        service['public'] = False
        service['private'] = False

      protocol = service.get('transport_protocol', 'udp')
      version = service.get('version')

      # Version checks
      recommended_versions = self.recommendations.get('versions', [])
      detected_versions = [version] if version else []
      
      # Check for versions that are supported but not recommended
      for detected_version in detected_versions:
        if detected_version not in recommended_versions:
          issues.append(Issue(
            'version: supported',
            version=detected_version,
            protocol=protocol,
          ))
      
      # Check for recommended versions that are not supported
      for recommended_version in recommended_versions:
        if recommended_version not in detected_versions:
          issues.append(Issue(
            'version: not supported',
            version=recommended_version,
            protocol=protocol,
          ))

      # Unusual transport protocol usage
      if protocol == 'tcp':
        issues.append(Issue(
          'unusual transport protocol',
          protocol='TCP',
          details='SNMP over TCP is uncommon and may indicate misconfiguration',
        ))

      # Public exposure
      if service.get('public'):
        issues.append(Issue(
          'public server',
          protocol=protocol,
          version=version or 'unknown',
        ))

      # Default community strings
      defaults = self.recommendations.get('default_communities', [])
      for community in service.get('community_strings', []):
        if community.lower() in (d.lower() for d in defaults):
          issues.append(Issue(
            'default community string',
            community=community,
            access='detected in service banner',
            protocol=protocol,
            exposure='public' if service.get('public') else 'private',
          ))

      # Information disclosure patterns
      desc = service.get('system_description') or ''
      if desc:
        patterns = [
          (r'Linux [^\s]+ [\d\.]+[^\s]*', 'Operating system version'),
          (r'Windows [^\n\r]+', 'Operating system version'),
          (r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', 'IP addresses'),
          (r'\b(?:admin|root|administrator|user)\b', 'User account names'),
          (r'Ubuntu [^\s]+', 'Operating system distribution'),
          (r'#[\d]+-[^\s]+', 'Kernel build information'),
        ]
        for pattern, info_type in patterns:
          if re.search(pattern, desc, re.IGNORECASE):
            issues.append(Issue(
              'information disclosure',
              info_type=info_type,
              source='system description',
              protocol=protocol,
              exposure='CRITICAL' if service.get('public') else 'WARNING',
              public=service.get('public', False),
              details=f"Revealed via SNMP: {desc[:80]}...",
            ))

      # Software enumeration
      sw = service.get('software_info', [])
      if sw:
        issues.append(Issue(
          'information disclosure',
          info_type='installed software',
          source='SNMP enumeration',
          protocol=protocol,
          exposure='CRITICAL' if service.get('public') else 'WARNING',
          public=service.get('public', False),
          count=len(sw),
          details=f"Exposed {len(sw)} software packages/processes",
        ))

      # Network interfaces - flag only public IPs disclosed
      interface_ips = service.get('network_interfaces', [])
      if interface_ips:
        public_ips = []
        for ip_str in interface_ips:
          try:
            addr_obj = ipaddress.ip_address(ip_str)
            if addr_obj.is_global:
              public_ips.append(ip_str)
          except ValueError:
            continue
        if public_ips:
          unique = sorted(set(public_ips))
          details = ', '.join(unique)
          issues.append(Issue(
            'information disclosure',
            info_type='network interfaces',
            source='SNMP enumeration',
            protocol=protocol,
            exposure='CRITICAL',
            public=True,
            details=f"Public interface IPs exposed: {details}",
          ))

      # Processes
      processes = service.get('script_outputs', {}).get('snmp-processes')
      if processes:
        issues.append(Issue(
          'information disclosure',
          info_type='running processes',
          source='SNMP enumeration',
          protocol=protocol,
          exposure='CRITICAL' if service.get('public') else 'WARNING',
          public=service.get('public', False),
          details='Process information exposed via SNMP',
        ))

      # Windows software
      win_sw = service.get('script_outputs', {}).get('snmp-win32-software')
      if win_sw:
        issues.append(Issue(
          'information disclosure',
          info_type='Windows software inventory',
          source='SNMP enumeration',
          protocol=protocol,
          exposure='CRITICAL' if service.get('public') else 'WARNING',
          public=service.get('public', False),
          details='Installed software list exposed',
        ))

    return services
