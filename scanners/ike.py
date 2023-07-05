#!/usr/bin/env python3

# this scrip tries to enumerate specific (problematic) transform attributes (i.e. encryption/hash algorithm, authentication method, etc) for IKEv1 servers.
# at the end, it also tries to establish an IKEv2 handshake with the server.
# it utilizes [`ike-scan`](https://github.com/royhills/ike-scan).

# [TR-02102-3](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-3.html) is used as a guideline (even though it covers IKEv2)

import argparse
import itertools
import os
import subprocess
import sys
import time

# default destination port
PORT = 500

SOURCE_PORT = 500
# 0: use a random UDP source port; default=500
# some IKE implementations require the client to use UDP source port 500 and will not talk to other ports.
# superuser privileges are normally required to use non-zero source ports below 1024.

# encryption algorithms:
# see https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-4
ENCRYPTION_ALGORITHMS = [
  "1", # DES-CBC
  "2", # IDEA-CBC
  "4", # RC5-R16-B64-CBC
  "5", # 3DES-CBC
  "6", # CAST-CBC
  "7/128", # AES-CBC/128
  "7/192", # AES-CBC/192
  "7/256", # AES-CBC/256
]

# hash algorithms:
# see https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-6
HASH_ALGORITHMS = [
  "1", # MD5
  "2", # SHA
  #"3", # Tiger, https://en.wikipedia.org/wiki/Tiger_(hash_function)
]

# authentication methods:
# see https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-8
AUTHENTICATION_METHODS = [
  "1", # pre-shared key
  "2", # DSS signatures
  "3", # RSA signatures
  "4", # encryption with RSA
  "64221", # HybridInitRSA, https://datatracker.ietf.org/doc/html/draft-zegman-ike-hybrid-auth#section-3.2.1
  "65001", # XAUTHInitPreShared, https://datatracker.ietf.org/doc/html/draft-beaulieu-ike-xauth-02#section-7.2
]

# Diffie-Hellman group descriptions
# see https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-10
DH_GROUPS = [
  "1", # 768-bit MODP
  "2", # alternate 1024-bit MODP
  "5", # 1536-bit MODP
  "14", # 2048-bit MODP
  "22", # 1024-bit MODP with 160-bit Prime Order Subgroup
  "23", # 2048-bit MODP with 224-bit Prime Order Subgroup
  "24", # 2048-bit MODP with 256-bit Prime Order Subgroup
]

def scan_ikev1(trans, target, dest_port, source_port, aggressive=False):
  args = [
    'ike-scan',
    f'--sport={source_port}',
    f'--trans={",".join(trans)}',
  ]

  if dest_port == 4500:
    args.append('--nat-t')
  else:
    args.append(f'--dport={dest_port}')

  if aggressive:
    args.append('--aggressive')
    args.append(f'--dhgroup={trans[-1]}')
    args.append('--id=test')

  args.append(target)

  print(f'\n{" ".join(args)}')

  process = subprocess.run(
    args,
    capture_output = True,
    text = True
  )

  print(process.stderr)

  if 'Handshake returned' in process.stdout:
    print(process.stdout)
    return True

def scan_ikev2(target, dest_port, source_port):
  args = [
    'ike-scan',
    f'--sport={source_port}',
    '--ikev2',
  ]

  if dest_port == 4500:
    args.append('--nat-t')
  else:
    args.append(f'--dport={dest_port}')

  args.append(target)

  print(f'\n{" ".join(args)}')

  process = subprocess.run(
    args,
    capture_output = True,
    text = True
  )

  if 'Handshake returned' in process.stdout:
    print(process.stdout)
    return True

def process(args):
  if args.source_port != 0 and os.geteuid() != 0:
    sys.exit('this script has to be run by the root user (i.e. with "sudo").')

  for trans in itertools.product(ENCRYPTION_ALGORITHMS, HASH_ALGORITHMS, AUTHENTICATION_METHODS, DH_GROUPS):
    if scan_ikev1(trans, args.target, args.port, args.source_port):
      scan_ikev1(trans, args.target, args.port, args.source_port, aggressive=True)

  # this delay seems to be necessary, as otherwise the last scan would not succeed
  time.sleep(5)

  scan_ikev2(args.target, args.port, args.source_port)

def main():
  parser = argparse.ArgumentParser()
  
  parser.add_argument(
    'target',
    help = "the hostname or IP address of the IKE server to be scanned"
  )

  parser.add_argument(
    '--port',
    help = f"the destination port (default: {PORT})",
    type = int,
    default = PORT
  )

  parser.add_argument(
    '--source_port',
    help = f"the source port (default: {SOURCE_PORT}). set to '0' to use a random port number above 1024.",
    type = int,
    default = SOURCE_PORT
  )

  process(parser.parse_args())
  
if __name__ == '__main__':
  main()
