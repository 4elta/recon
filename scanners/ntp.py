#!/usr/bin/env python3

'''
this script polls an NTP server and estimates its security based on the replies.

1. send a mode 3 (client) request, to get the current time
  this request will show up in (3)
2. send a mode 6 (READ_VARIABLES) request
3. send a mode 7 (XNTPD, MON_GETLIST_1) request
if (3) succeeds, send a mode 7 (XNTPD, PEER_LIST) request

idea:
- https://github.com/ikstream/ntp-amp-check
- https://nmap.org/nsedoc/scripts/ntp-info.html
- https://nmap.org/nsedoc/scripts/ntp-monlist.html
'''

import argparse
import datetime
import ipaddress
import json
import pathlib
import re
import socket
import struct
import sys

PORT = 123
TIMEOUT = 5 # seconds

VERSION_NUMBER = 2

OPCODE_READ_STATUS = 1
OPCODE_READ_VARIABLES = 2

IMPLEMENTATION_UNIV = 0
IMPLEMENTATION_XNTPD_OLD = 2 # pre IPv6
IMPLEMENTATION_XNTPD = 3

REQUEST_PEER_LIST = 0
REQUEST_MON_GETLIST = 20
REQUEST_MON_GETLIST_1 = 42

ASSOCIATION_MODES = {
  1: 'symmetric',
  2: 'symmetric',
  3: 'client',
  4: 'server',
  5: 'broadcast server'
}

def mode_3_request(
  leap_indicator,
  version_number,
  # mode = 3
  peer_clock_stratum,
  peer_polling_interval,
  peer_clock_precision,
  root_delay,
  root_dispersion,
  reference_ID,
  reference_timestamp,
  origin_timestamp,
  receive_timestamp,
  transmit_timestamp
):
  """
  packet structure from Wireshark

  bytes       |       0       |       1       |       2       |       3       |
  bits        |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 0-3   |LI | VN  |Mode |      PCS      |      PPI      |      PCP      |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 4-7   |                           root delay                          |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 8-11  |                        root dispersion                        |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 12-15 |                          reference ID                         |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 16-23 |                reference timestamp: seconds                   |
              |                reference timestamp: fractions                 |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 24-31 |                  origin timestamp: seconds                    |
              |                  origin timestamp: fractions                  |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 32-39 |                 receive timestamp: seconds                    |
              |                 receive timestamp: fractions                  |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 40-47 |                 transit timestamp: seconds                    |
              |                 transit timestamp: fractions                  |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  LI: leap indicator: 0
  VN: version number: 1...4
  Mode: 3
  PCS: peer clock stratum
  PPI: peer polling interval
  PCP: peer clock precision
  """

  flags = (leap_indicator << 6) | (version_number << 3) | 3

  return struct.pack(
    '! B B B B    L L    4s    Q Q Q Q',
    flags, peer_clock_stratum, peer_polling_interval, peer_clock_precision,
    root_delay, root_dispersion,
    reference_ID,
    reference_timestamp, origin_timestamp, receive_timestamp, transmit_timestamp
  )

def parse_mode_3_response(response):
  """
  packet structure from Wireshark

  bytes       |       0       |       1       |       2       |       3       |
  bits        |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 0-3   |LI | VN  |Mode |      PCS      |      PPI      |      PCP      |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 4-7   |                           root delay                          |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 8-11  |                        root dispersion                        |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 12-15 |                          reference ID                         |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 16-23 |                reference timestamp: seconds                   |
              |                reference timestamp: fractions                 |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 24-31 |                  origin timestamp: seconds                    |
              |                  origin timestamp: fractions                  |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 32-39 |                 receive timestamp: seconds                    |
              |                 receive timestamp: fractions                  |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 40-47 |                 transit timestamp: seconds                    |
              |                 transit timestamp: fractions                  |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  LI: leap indicator: 0
  VN: version number: 1...4
  Mode: 3
  PCS: peer clock stratum
  PPI: peer polling interval
  PCP: peer clock precision
  """

  seconds, fractions = struct.unpack('!LL', response[32 : 32 + 8])

  # NTP epoch starts at 1900-01-01
  # UNIX epoch starts at 1970-01-01
  # the difference is 2208988800 seconds
  # see https://www.rfc-editor.org/rfc/rfc5905#page-14
  timestamp = seconds - 2208988800 + fractions / 0x10000000

  dt = datetime.datetime.fromtimestamp(timestamp)
  formatted_datetime = dt.strftime('%Y-%m-%d %H:%M:%S.%f')
  print(f"  {formatted_datetime}")

  return formatted_datetime

def test_mode_3(udp_socket, address):
  print(f"\nrequesting current time ...")
  request = mode_3_request(
    0b11, # clock unsynchronized
    VERSION_NUMBER,
    0,
    0,
    0,
    0,
    0,
    b'',
    0,
    0,
    0,
    0xffffffffffffffff, # some time in 2036-02-07
  )

  data = []

  try:
    udp_socket.sendto(request, (address, PORT))
    response = udp_socket.recv(1024)
    return parse_mode_3_response(response)
  except socket.timeout:
    print(f"no response within {TIMEOUT} seconds")
    return

def mode_6_request(opcode, version_number=VERSION_NUMBER):
  """
  from https://datatracker.ietf.org/doc/html/rfc9327#section-2

  bytes      |       0       |       1       |       2       |       3       |
  bits       |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 0-3  |LI | VN  |Mode |R|E|M| opcode  |       Sequence Number         |
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

  remaining 8 bytes: 0
  """

  return struct.pack('!BBxx', version_number << 3 | 6, opcode) + b'\x00' * 8

def parse_mode_6_response(response):
  """
  from https://datatracker.ietf.org/doc/html/rfc9327#section-2

  bytes      |       0       |       1       |       2       |       3       |
  bits       |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  bytes 0-3  |LI | VN  |Mode |R|E|M| opcode  |       Sequence Number         |
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

  r_e_m_opcode = response[1]
  error = (r_e_m_opcode >> 6) & 0b1
  if error != 0:
    print("error")
    return

  more = (r_e_m_opcode >> 5) & 0b1

  opcode = r_e_m_opcode & 0b11111

  offset, count = struct.unpack('!HH', response[8 : 12])

  data = []
  # "parse" the key-value list
  for d in struct.unpack(f'!{count}s', response[12 : 12 + count])[0].decode().split(','):
    key_value = d.strip()
    print(f"  {key_value}")
    data.append(f"`{key_value}`")

  return (data, more)

def test_mode_6(udp_socket, address, opcode):
  print(f"\nsending NTPv{VERSION_NUMBER} 'mode 6, opcode {opcode}' request ...")
  request = mode_6_request(opcode)

  data = []
  response_length = 0

  try:
    udp_socket.sendto(request, (address, PORT))
    response = udp_socket.recv(1024)
  except socket.timeout:
    print(f"no response within {TIMEOUT} seconds")
    return

  while True:
    more = False
    response_length += len(response)
    result = parse_mode_6_response(response)

    if result:
      data += result[0]
      more = result[1]
    else:
      break

    if more:
      try:
        response = udp_socket.recv(1024)
      except socket.timeout:
        print(f"no response within {TIMEOUT} seconds")
        break
    else:
      break

  if response_length:
    amplification_factor = response_length / len(request)
    print(f"amplification factor: {amplification_factor:.1f}")

    return {
      'amplification_factor': f"{amplification_factor:.1f}",
      'data': data,
    }

def mode_7_request(implementation, request_code, version_number=VERSION_NUMBER):
  """
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
  return struct.pack('!BxBB', version_number << 3 | 7, implementation, request_code) + b'\x00'*4

def parse_peerlist(peerlist):
  """
  packet structure from:
  * https://svn.nmap.org/nmap/scripts/ntp-monlist.nse
  * Wireshark

          |                    1          |
  bytes   |0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5|
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       0  | addr  | P |M|F| IPv6  | xxxxx |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      16  |          addr (IPv6)          |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  addr: remote address (IPv4)
  P: remote port
  M: association mode (client/server)
  F: flags
  IPv6: flag to indicate that IPv6 addresses are used

  """

  if len(peerlist) == 8 or peerlist[8] != b'\x01':
    remote_address = ipaddress.IPv4Address(peerlist[0 : 4])
    address_string = str(remote_address)
  else:
    remote_address = ipaddress.IPv6Address(peerlist[16 : 16 + 16])
    address_string = f"[{str(remote_address)}]"

  port = struct.unpack('!H', peerlist[5 : 5 + 2])[0]
  assoc_mode = peerlist[6]

  return f"remote address: {address_string} ({ASSOCIATION_MODES[assoc_mode]})"

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
      32  | IPv6  | xxxxx |
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
  M: association mode (client/server/peers)
  V: version
  IPv6: flag to indicate that IPv6 addresses are used
  """

  if len(monlist) == 32 or monlist[32] != b'\x01':
    remote_address = ipaddress.IPv4Address(monlist[16 : 16 + 4])
    remote_address_str = str(remote_address)
    local_address = ipaddress.IPv4Address(monlist[20 : 20 + 4])
    local_address_str = str(local_address)
  else:
    remote_address = ipaddress.IPv6Address(monlist[40 : 40 + 16])
    remote_address_str = f"[{str(remote_address)}]"
    local_address = ipaddress.IPv6Address(monlist[56 : 56 + 16])
    local_address_str = f"[{str(local_address)}]"

  port = struct.unpack('!H', monlist[28 : 28 + 2])[0]
  assoc_mode = monlist[30]

  return f"remote address: {remote_address_str} ({ASSOCIATION_MODES[assoc_mode]}), local address: {local_address_str}"

def parse_mode_7_response(response):
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

  more = (response[0] >> 6) & 0b1
  implementation, req_code = struct.unpack('!BB', response[2 : 4])

  if implementation not in (2, IMPLEMENTATION_XNTPD):
    return

  if req_code not in (REQUEST_MON_GETLIST_1, REQUEST_PEER_LIST):
    return

  err_num, mbz_size = struct.unpack('!HH', response[4 : 8])

  err = err_num >> 12

  if err != 0:
    print(f"error code {err}")
    return

  num = err_num & 0xFFF

  mbz = mbz_size >> 12
  size = mbz_size & 0xFFF

  data = []

  for i in range(num):
    pkt = response[8 + i * size : 8 + (i + 1) * size]

    if req_code == REQUEST_MON_GETLIST_1:
      d = parse_monlist(pkt)
    elif req_code == REQUEST_PEER_LIST:
      d = parse_peerlist(pkt)

    print(f"  {d}")
    data.append(d)

  return (data, more)

def test_mode_7(udp_socket, address, implementation, req_code):
  print(f"\nsending NTPv{VERSION_NUMBER} 'mode 7, implementation {implementation}, req code {req_code}' request ...")
  request = mode_7_request(implementation, req_code)

  data = []
  response_length = 0

  try:
    udp_socket.sendto(request, (address, PORT))
    response = udp_socket.recv(1024)
  except socket.timeout:
    print(f"no response within {TIMEOUT} seconds")
    return

  while True:
    more = False
    response_length += len(response)
    result = parse_mode_7_response(response)

    if result:
      data += result[0]
      more = result[1]
    else:
      break

    if more:
      print("expecting more data ...")
      try:
        response = udp_socket.recv(1024)
      except socket.timeout:
        print(f"no response within {TIMEOUT} seconds")
        break
    else:
      break

  if response_length:
    amplification_factor = response_length / len(request)
    print(f"amplification factor: {amplification_factor:.1f}")

    return {
      'amplification_factor': f"{amplification_factor:.1f}",
      'data': data
    }

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

  tests = {
    VERSION_NUMBER: {},
  }

  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
    udp_socket.settimeout(TIMEOUT)

    result = test_mode_3(udp_socket, address)

    if result:
      current_datetime = datetime.datetime.now()
      tests[VERSION_NUMBER][3] = {
        'current timestamp': current_datetime.strftime('%Y-%m-%d %H:%M:%S.%f'),
        'receive timestamp': result
      }

    opcode = OPCODE_READ_VARIABLES
    result = test_mode_6(udp_socket, address, opcode)

    if result:
      tests[VERSION_NUMBER][6] = {
        opcode: result,
      }

      # look for version strings in the data array
      # e.g. `version="ntpd 4.2.6p5@1.2349-o Fri Jul  6 20:19:54 UTC 2018 (1)"`
      for version_info in [data for data in result['data'] if data.startswith('`version=')]:
        m = re.search(
          r'`version="ntpd (?P<version>[^ ]+)',
          version_info,
        )

        if m:
          version = m.group('version')
        else:
          version = version_info[len('version='):]

    implementation = IMPLEMENTATION_XNTPD
    req_code = REQUEST_MON_GETLIST_1
    result = test_mode_7(udp_socket, address, implementation, req_code)

    if result:
      tests[VERSION_NUMBER][7] = {
        implementation: {
          req_code: result,
        }
      }

      req_code = REQUEST_PEER_LIST
      result = test_mode_7(udp_socket, address, implementation, req_code)

      if result:
        tests[VERSION_NUMBER][7][implementation][req_code] = result

  if args.json:
    result = {
      'address': address,
      'public': public,
      'port': PORT,
      'version': version,
      'tests': tests,
    }

    with open(args.json, 'w') as f:
      json.dump(result, f, indent=2)

def main():
  parser = argparse.ArgumentParser()
  
  parser.add_argument(
    'address',
    help = "the IP address of the NTP server to be scanned",
  )

  parser.add_argument(
    '--port',
    help = f"the port number where the NTP server is listening for queries (default: {PORT})",
    type = int,
    default = PORT,
  )

  parser.add_argument(
    '--timeout',
    help = f"time in seconds to wait for the server's response (default: {TIMEOUT})",
    type = int,
    default = TIMEOUT,
  )

  parser.add_argument(
    '--json',
    help = "in addition to the scan result being printed to STDOUT, also save the result as a JSON document",
    type = pathlib.Path,
  )

  process(parser.parse_args())
  
if __name__ == '__main__':
  main()
