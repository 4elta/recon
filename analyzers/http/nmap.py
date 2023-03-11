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
            <script id="http-headers" output="&#xa;  Content-Type: text/html; charset=utf-8&#xa;  Content-Length: 53139&#xa;  Connection: close&#xa;  Server: meinheld/1.0.2&#xa;  Date: Thu, 09 Mar 2023 10:16:50 GMT&#xa;  X-Frame-Options: DENY&#xa;  Content-Security-Policy: child-src &apos;self&apos; *.mozilla.net *.mozilla.org *.mozilla.com *.mozilla.org www.googletagmanager.com www.google-analytics.com www.youtube-nocookie.com trackertest.org www.surveygizmo.com accounts.firefox.com accounts.firefox.com.cn www.youtube.com; script-src &apos;self&apos; *.mozilla.net *.mozilla.org *.mozilla.com *.mozilla.org &apos;unsafe-inline&apos; &apos;unsafe-eval&apos; www.googletagmanager.com www.google-analytics.com tagmanager.google.com www.youtube.com s.ytimg.com cdn-3.convertexperiments.com app.convert.com data.track.convertexperiments.com 1003350.track.convertexperiments.com 1003343.track.convertexperiments.com; font-src &apos;self&apos;; style-src &apos;self&apos; *.mozilla.net *.mozilla.org *.mozilla.com *.mozilla.org &apos;unsafe-inline&apos; app.convert.com; img-src &apos;self&apos; *.mozilla.net *.mozilla.org *.mozilla.com *.mozilla.org data: mozilla.org www.googletagmanager.com www.google-analytics.com adservice.google.com adservice.google.de adservice.google.dk creativecommons.org cdn-3.convertexperiments.com logs.convertexperiments.com images.ctfassets.net; frame-src &apos;self&apos; *.mozilla.net *.mozilla.org *.mozilla.com *.mozilla.org www.googletagmanager.com www.google-analytics.com www.youtube-nocookie.com trackertest.org www.surveygizmo.com accounts.firefox.com accounts.firefox.com.cn www.youtube.com; default-src &apos;self&apos; *.mozilla.net *.mozilla.org *.mozilla.com *.mozilla.org; connect-src &apos;self&apos; *.mozilla.net *.mozilla.org *.mozilla.com *.mozilla.org www.googletagmanager.com www.google-analytics.com region1.google-analytics.com logs.convertexperiments.com 1003350.metrics.convertexperiments.com 1003343.metrics.convertexperiments.com sentry.prod.mozaws.net o1069899.sentry.io o1069899.ingest.sentry.io https://accounts.firefox.com/ stage.cjms.nonprod.cloudops.mozgcp.net cjms.services.mozilla.com&#xa;  Cache-Control: max-age=600&#xa;  Expires: Thu, 09 Mar 2023 10:26:50 GMT&#xa;  X-Clacks-Overhead: GNU Terry Pratchett&#xa;  X-Backend-Server: bedrock-7f898b58f8-qf5vt.gcp-eu-west1&#xa;  Strict-Transport-Security: max-age=31536000&#xa;  X-Content-Type-Options: nosniff&#xa;  X-XSS-Protection: 1; mode=block&#xa;  Referrer-Policy: strict-origin-when-cross-origin&#xa;  Via: 1.1 google, 1.1 abf5199c76a5a64063b4cf8863f823aa.cloudfront.net (CloudFront)&#xa;  ETag: &quot;7733780120d83818c43f84606c8e073a&quot;&#xa;  Vary: Accept-Encoding,Accept-Language&#xa;  X-Cache: Hit from cloudfront&#xa;  X-Amz-Cf-Pop: AMS1-P2&#xa;  X-Amz-Cf-Id: 6ySovMITbt_L1TzYOztflfa7IMETVOXtyz93oftEmydCzX4uts0ubg==&#xa;  Age: 7&#xa;  &#xa;  (Request type: HEAD)&#xa;"/>
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
