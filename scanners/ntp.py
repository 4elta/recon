#!/usr/bin/env python3

# polls an NTP server and estimates its security based on the replies.
# idea: https://github.com/ikstream/ntp-amp-check

import argparse
import ipaddress
import json
import pathlib
import re
import socket
import struct
import sys

PORT = 123
TIMEOUT = 2

VERSION_NUMBER = 2
IMPLEMENTATION_NUMBER = 3 # 0,2,3

def mode_6_request(opcode, version_number=VERSION_NUMBER):
  """
  NTP Message Format
  from https://datatracker.ietf.org/doc/html/rfc9327#section-2

  bytes      |       0       |       1       |       2       |       3       |
  bits       |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 0-3  |LI |  VN |Mode |R|E|M| opcode  |       Sequence Number         |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 4-7  |            Status             |       Association ID          |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 8-11 |            Offset             |            Count              |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  LI: leap indicator: 0
  VN: version number: 1...4
  Mode: 6
  R: response bit: 0
  E: error bit: 0
  M: more bit: 0
  opcode: command ID: 0...31
  Sequence Number: 0

  rest (8 bytes): 0
  """

  return struct.pack('<BBxx', version_number<<3 | 6, opcode) + b'\x00' * 8

def mode_6_response(response):
  """
  NTP Message Format
  from https://datatracker.ietf.org/doc/html/rfc9327#section-2

  bytes      |       0       |       1       |       2       |       3       |
  bits       |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 0-3  |LI |  VN |Mode |R|E|M| opcode  |       Sequence Number         |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 4-7  |            Status             |       Association ID          |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 8-11 |            Offset             |            Count              |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 12.. |                                                               |
             /                    Data (up to 468 bytes)                     /
             |                                                               |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  """

  #print(f"response:\n{response}") #TODO

  (offset, count) = struct.unpack('!HH', response[8 : 12])
  #print(f"offset: {offset}") #TODO
  #print(f"count: {count}") #TODO

  data = []
  # "parse" the key-value list
  for d in struct.unpack(f'!{count}s', response[12 : 12 + count])[0].decode().split(','):
    key_value = d.strip()
    print(f"  {key_value}")
    data.append(key_value)

  return data

def mode_7_request(request_code, version_number=VERSION_NUMBER, implementation_number=IMPLEMENTATION_NUMBER):
  """
  NTP Mode 7 Message Format
  from https://blog.qualys.com/vulnerabilities-threat-research/2014/01/21/how-qualysguard-detects-vulnerability-to-ntp-amplification-attacks

  bytes      |       0       |       1       |       2       |       3       |
  bits       |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 0-3  |R|M| VN  |Mode |A|  Sequence   |Implementation |   Req Code    |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 4-8  |  Err  | Number of data items  |  MBZ  |   Size of data item   |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  R: response bit: 0
  M: more bit: 0
  VN: version number: 1...4
  Mode: 7
  A: authenticated bit: 0
  Sequence: 0
  Implementation
  Req Code: specifies the operation: 0...45

  rest (4 bytes): 0
  """

  # https://docs.python.org/3/library/struct.html#format-characters
  return struct.pack('<BxBB', version_number<<3 | 7, implementation_number, request_code) + b'\x00'*4

def parse_monlist(monlist):
  """
  packet structure from
  * https://svn.nmap.org/nmap/scripts/ntp-monlist.nse
  * Wireshark
  * https://www.ntp.org/documentation/4.2.8-series/ntpq/

          |                    1          |
  bytes   |0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5|
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       0  |avgint |lstint | restr | count |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      16  |  RA   |  LA   | flags | P |M|V|
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      32  | IPv6  |       |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      40  |       remote addr (IPv6)      |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      56  |        local addr (IPv6)      |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  avgint: average interval in seconds between packets from this address
  lstint: interval in seconds between the receipt of the most recent packet from this address
    and the completion of the retrieval of the MRU list
  restr: restriction flags associated with this address
  count: packets received from this address
  RA: remote address (IPv4)
  LA: local address (IPv4)
  P: port
  M: mode
  V: version
  IPv6: flag to indicate that IPv6 addresses are used

  """

  if monlist[32] == b'\x01':
    remote_address = ipaddress.IPv6Address(monlist[40 : 40 + 16])
    local_address = ipaddress.IPv6Address(monlist[56 : 56 + 16])
  else:
    remote_address = ipaddress.IPv4Address(monlist[16 : 16 + 4])
    local_address = ipaddress.IPv4Address(monlist[20 : 20 + 4])

  return f"remote address: {str(remote_address)}, local address: {str(local_address)}"

def mode_7_response(response):
  """
  NTP Mode 7 Message Format
  from https://blog.qualys.com/vulnerabilities-threat-research/2014/01/21/how-qualysguard-detects-vulnerability-to-ntp-amplification-attacks


  bytes      |       0       |       1       |       2       |       3       |
  bits       |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 0-3  |R|M| VN  |Mode |A|  Sequence   |Implementation |   Req Code    |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 4-7  |  Err  | Number of data items  |  MBZ  |   Size of data item   |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 8... |                                                               |
             /                   Data (up to 500 octets)                     /
             |                                                               |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  """

  (err_num, mbz_size) = struct.unpack('!HH', response[4 : 8])

  err = err_num >> 12
  num = err_num & 0xFFF

  mbz = mbz_size >> 12
  size = mbz_size & 0xFFF

  data = []
  for i in range(num):
    monlist = parse_monlist(response[8 + i * size : 8 + (i + 1) * size])
    print(f"  {monlist}")
    data.append(monlist)

  return data

def process(args):
  try:
    address = ipaddress.ip_address(args.address)
    print(f"address: {address}")

    public = address.is_global
    print(f"public: {public}")
  except ValueError as e:
    sys.exit('\n'.join(e.args))

  # from here on the IP address must be a string instead of an instance of IPv(4|6)Address
  address = str(address)

  global PORT
  PORT = args.port
  print(f"port: {PORT}")

  global TIMEOUT
  TIMEOUT = args.timeout

  version = None
  requests = []
  misc = []
  mode_6 = {}
  mode_7 = {}

  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
    try:
      udp_socket.settimeout(TIMEOUT)

      opcode = 2 # read variables
      print(f"\nsending Mode 6 (opcode {opcode}) request ...")
      request = mode_6_request(opcode)

      udp_socket.sendto(
        request,
        (address, PORT)
      )

      data = []
      response_length = 0

      response, _ = udp_socket.recvfrom(1024)

      while True:
        try:
          response_length += len(response)
          d = mode_6_response(response)

          # parse version string
          # e.g. `version="ntpd 4.2.6p5@1.2349-o Fri Jul  6 20:19:54 UTC 2018 (1)"`
          for v in [v for v in d if v.startswith('version=')]:
            m = re.search(
              r'version="ntpd (?P<version>[^ ]+)',
              v
            )

            if m:
              version = m.group('version')
            else:
              version = v[8:]

            #print(f"version: {version}") #TODO

          data += d
          response, _ = udp_socket.recvfrom(1024)
        except socket.timeout:
          break

      if response_length:
        misc += data
        amplification_factor = response_length / len(request)
        print(f"amplification factor: {amplification_factor:.1f}")
        r = {
          'request': f"version {VERSION_NUMBER}, mode 6, opcode {opcode}",
          'amplification_factor': float(amplification_factor)
        }

        requests.append(r)

        mode_6['opcode'] = int(opcode)
        mode_6['amplification_factor'] = f"{amplification_factor:.1f}"

      req_code = 42 # MON_GETLIST=20, MON_GETLIST_1=42
      print(f"\nsending Mode 7 (req code {req_code}) request ...")
      request = mode_7_request(req_code)

      udp_socket.sendto(
        request,
        (address, PORT)
      )

      data = []
      response_length = 0

      response, _ = udp_socket.recvfrom(1024)

      while True:
        try:
          response_length += len(response)
          data += mode_7_response(response)
          response, _ = udp_socket.recvfrom(1024)
        except socket.timeout:
          break

      if response_length:
        misc += data
        amplification_factor = response_length / len(request)
        print(f"amplification factor: {amplification_factor:.1f}")
        r = {
          'request': f"version {VERSION_NUMBER}, mode 7, implementation {IMPLEMENTATION_NUMBER}, req code {req_code}",
          'amplification_factor': float(amplification_factor)
        }

        requests.append(r)

        mode_7['req_code'] = int(req_code)
        mode_7['amplification_factor'] = f"{amplification_factor:.1f}"

    except (socket.timeout, socket.error) as e:
      print("no response")

  if args.json:
    result = {
      'address': address,
      'public': public,
      'port': PORT,
      'version': version,
      'requests': requests,
      'misc': misc,
      'mode_6': mode_6,
      'mode_7': mode_7
    }

    with open(args.json, 'w') as f:
      json.dump(result, f, indent=2)

def main():
  parser = argparse.ArgumentParser()
  
  parser.add_argument(
    'address',
    help = "the IP address of the NTP server to be scanned"
  )

  parser.add_argument(
    '--port',
    help = f"the port number where the NTP server is listening for queries (default: {PORT})",
    type = int,
    default = PORT
  )

  parser.add_argument(
    '--timeout',
    help = f"time in seconds to wait for the server's response (default: {TIMEOUT})",
    type = int,
    default = TIMEOUT
  )

  parser.add_argument(
    '--json',
    help = "in addition to the scan result being printed to STDOUT, also save the result as a JSON document",
    type = pathlib.Path
  )

  process(parser.parse_args())
  
if __name__ == '__main__':
  main()
