#!/usr/bin/awk -f
# parse and analyze testssl result files

# be sure to run testssl with `--color 0`
# or use a sed filter: `sed 's,\x1B\[[0-9;]*[a-zA-Z],,g'`

# also, the patterns in this script are based on the IANA naming:
# so run testssl with `--mapping iana`

# invoke this program like this:
# /path/to/this/file /path/to/recon/*/services/*-testssl.log

# function to append a value to an array, if that array does not yet contain the value
function append_to_array(array, value) {
  for (i in array) {
    if (value == array[i])
      return
  }
  array[length(array)+1] = value
}

# function to print all entries of an array, if the array is not empty
function print_array(array, heading) {
  if (length(array) < 1) {
    return
  }

  printf "\n**%s**\n\n", heading
  for (i in array) {
    printf "* %s\n", array[i]
  }
}

BEGIN {
  desc_protocol_ssl2 = "SSL 2.0 offered"
  desc_protocol_ssl3 = "SSL 3.0 offered"
  desc_protocol_tls10 = "TLS 1.0 offered"
  desc_protocol_tls11 = "TLS 1.1 offered"
  desc_protocol_tls13 = "TLS 1.3 not offered"

  desc_cert_sig_alg = "insecure certificate signature algorithm"
  desc_cert_short_rsa_key = "certificate's RSA key (i.e. its modulus) has less than 3000 bits"
  desc_cert_trust = "certificate chain not trusted"
  desc_cert_expired = "certificate expired"

  desc_vuln_reneg_server = "secure renegotiation not supported"
  desc_vuln_reneg_client = "client-initiated renegotiation allowed"

  desc_vuln_scsv = "TLS Fallback SCSV not supported"
  desc_vuln_crime = "vulnerable to CRIME (CVE-2012-4929)"
  desc_vuln_lucky13 = "potentially vulnerable to Lucky Thirteen (CVE-2013-0169): use of ciphers in CBC mode"
  desc_vuln_heartbleed = "vulnerable to Heartbleed (CVE-2014-0160)"
  desc_vuln_ccs = "vulnerable to CCS injection (CVE-2014-0224)"
  desc_vuln_freak = "vulnerable to FREAK (CVE-2015-0204)"
  desc_vuln_drown = "vulnerable to DROWN (CVE-2016-0800, CVE-2016-0703)"
  desc_vuln_ticketbleed = "vulnerable to Ticketbleed (CVE-2016-9244)"
  desc_vuln_robot = "vulnerable to ROBOT (CVE-2017-13099)"

  desc_suite_hash_md5 = "cipher suites that are using an insecure hash algorithm: MD5"
  desc_suite_hash_sha1 = "cipher suites that are using an insecure hash algorithm: SHA-1"

  desc_suite_cipher_des = "cipher suites that are using an insecure cipher: DES/Triple-DES"
  desc_suite_cipher_rc2 = "cipher suites that are using an insecure cipher: RC2"
  desc_suite_cipher_rc4 = "cipher suites that are using an insecure cipher: RC4"
  desc_suite_cipher_idea = "cipher suites that are using an insecure cipher: IDEA"

  desc_suite_cipher_mode_cbc = "cipher suites that are using a potentially insecure cipher mode: CBC"

  desc_suite_auth_anon = "cipher suites that are using anonymous DH"

  desc_suite_gost = "insecure cipher suite: GOST"

  desc_suite_null = "cipher suites that are using no key exchange and/or encryption"

  desc_suite_keyex_psk = "cipher suites that are using a pre-shared key"
  desc_suite_keyex_dh_short = "cipher suites that are using a weak session key"
  desc_suite_keyex_pfs = "cipher suites that cannot guarantee PFS (no ephemeral DH key exchange)"
}

/Start/ && /-->>/ {
  # Start 2021-11-20 21:50:22        -->> 11.22.33.44:443 (11.22.33.44) <<--
  # 1     2          3               4    5               6
  match($5, /([^:]+):([0-9]+)/, matches)
  host = matches[1]
  port = matches[2]

  service = host ":" port

  printf "\n#### %s:%d\n\n", host, port
}

# old protocols: SSLv2, SSLv3, TLSv1, TLSv1.1

/^ SSLv2 + offered/ {
  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(protocol_ssl2, service)
  printf "* %s\n", desc_protocol_ssl2
  next
}

/^ SSLv3 + offered/ {
  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(protocol_ssl3, service)
  printf "* %s\n", desc_protocol_ssl3
  next
}

/^ TLS 1 + offered/ {
  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(protocol_tls10, service)
  printf "* %s\n", desc_protocol_tls10
  next
}

/^ TLS 1.1 + offered/ {
  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(protocol_tls11, service)
  printf "* %s\n", desc_protocol_tls11
  next
}

# TLSv1.3 not supported

/^ TLS 1.3 + not offered/  {
  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(protocol_tls13, service)
  printf "* %s\n", desc_protocol_tls13
  next
}

# insecure certificate signature algorithm

/^ Signature Algorithm/ && ! /SHA(256|384|512)/ {
  # Signature Algorithm          SHA256 with RSA
  # 1         2                  3 ...

  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(cert_sig_alg, service)
  printf "* %s:", desc_cert_sig_alg

  for (i = 3; i <= NF; i++) {
    printf " %s", $i
  }
  printf "\n"
  next
}

# short RSA public key

/^ Server key size/ && /RSA/ {
  # Server key size              RSA 2048 bits
  # 1      2   3                 4   5

  if ($5 < 3000) {
    append_to_array(hosts, host)
    append_to_array(services, service)
    append_to_array(cert_short_rsa_key, service)
    printf "* %s: %s\n", desc_cert_short_rsa_key, $5
  }
  next
}

# certificate chain of trust

/^ Chain of trust/ && ! /Ok/ {
  # Chain of trust               NOT ok (self signed CA in chain)
  # 1     2  3                   4   5  6 ...

  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(cert_trust, service)
  printf "* %s:", desc_cert_trust

  # remove braces
  gsub("[()]", "")

  for (i = 6; i <= NF; i++) {
    printf " %s", $i
  }
  printf "\n"
  next
}

# certificate expired

/Certificate Validity/ && /expired/ {
  # Certificate Validity (UTC)   expired (2019-09-29 15:34 --> 2020-11-28 18:53)
  # 1           2        3       4       5           6     7   8          9

  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(cert_expired, service)
  printf "* %s %s %s -- %s %s\n", desc_cert_expired, $5, $6, $8, $9
  next
}

# various vulnerabilities

/^ Secure Renegotiation \(RFC 5746\)/ && ! /supported/ {
  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(vuln_reneg_server, service)
  printf "* %s\n", desc_vuln_reneg_server
  next
}

/^ Secure Client-Initiated Renegotiation/ && ! /not vulnerable/ {
  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(vuln_reneg_client, service)
  printf "* %s\n", desc_vuln_reneg_client
  next
}

/^ TLS_FALLBACK_SCSV \(RFC 7507\)/ && /Downgrade attack prevention NOT supported/ {
  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(vuln_scsv, service)
  printf "* %s\n", desc_vuln_scsv
  next
}

# skipping BEAST, as we are already flagging the use of TLSv1.0
# https://en.wikipedia.org/wiki/Transport_Layer_Security#BEAST_attack

# https://en.wikipedia.org/wiki/CRIME
/^ CRIME, TLS \(CVE-2012-4929\)/ && ! /not vulnerable/ {
  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(vuln_crime, service)
  printf "* %s\n", desc_vuln_crime
  next
}

# https://en.wikipedia.org/wiki/Lucky_Thirteen_attack
# this is an attack against implementations of the TLS protocol that use the CBC mode of operation
/^ LUCKY13 \(CVE-2013-0169\)/ && ! /not vulnerable/ {
  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(vuln_lucky13, service)
  printf "* %s\n", desc_vuln_lucky13
  next
}

# https://heartbleed.com/
/^ Heartbleed \(CVE-2014-0160\)/ && ! /not vulnerable/ {
  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(vuln_heartbleed, service)
  printf "* %s\n", desc_vuln_heartbleed
  next
}

# skipping POODLE as we are already flagging SSLv3 and missing TLS Fallback SCSV support
# https://en.wikipedia.org/wiki/POODLE

# https://www.imperialviolet.org/2014/06/05/earlyccs.html
# this is an attack against implementations of the ChangeCipherSpec (CCS) in OpenSSL
/^ CCS \(CVE-2014-0224\)/ && ! /not vulnerable/ {
  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(vuln_ccs, service)
  printf "* %s\n", desc_vuln_ccs
  next
}

# https://freakattack.com/
/^ FREAK \(CVE-2015-0204\)/ && ! /not vulnerable/ {
  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(vuln_freak, service)
  printf "* %s\n", desc_vuln_freak
  next
}

# skipping Logjam (CVE-2015-4000), as we are already flagging DH keys with less the 2048 bits
# https://weakdh.org/

# https://drownattack.com/
/^ DROWN \(CVE-2016-0800, CVE-2016-0703\)/ && ! /not vulnerable/ {
  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(vuln_drown, service)
  printf "* %s\n", desc_vuln_drown
  next
}

# skipping Sweet32 (CVE-2016-2183, CVE-2016-6329), as we are already flagging the use of DES/3DES
# https://sweet32.info/

# https://filippo.io/Ticketbleed/
/^ Ticketbleed \(CVE-2016-9244\)/ && ! ( /applicable only for HTTPS/ || /not vulnerable/ ) {
  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(vuln_ticketbleed, service)
  printf "* %s\n", desc_vuln_ticketbleed
  next
}

# https://www.robotattack.org/
/^ ROBOT/ && ! ( /not vulnerable/ || /Server does not support any cipher suites that use RSA key transport/ ) {
  append_to_array(hosts, host)
  append_to_array(services, service)
  append_to_array(vuln_robot, service)
  printf "* %s\n", desc_vuln_robot
  next
}

# cipher suites

# with TLS 1.3 all public-key based key exchange mechanisms provide PFS.
# therefore, all DH key exchanges are ephemeral DH (https://datatracker.ietf.org/doc/html/rfc8446#section-1.2).
# the names of the newly added cipher suites no longer show which key exchange mechanism is used.
# these cipher suites are listed in appendix B.4 of RFC 8446:
# https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4
# the identifiers (i.e. hexcode) of these new cipher suites starts with 'x13'

/^ x/ && ( \
  /_MD5/ || /_SHA / || \
  /_3?DES_/ || /_RC(2|4)_/ || /_IDEA_/ || \
  /_CBC_/ || \
  /_GOST/ || /_NULL_/ || \
  /_PSK_/ || /DH_anon_/ || /DH (768|1024|2048)/ || \
  ! ( /(EC)?DHE/ || ( /^ x13/ && /(EC)?DH / ) ) \
) {
  #Hexcode  Cipher Suite Name (IANA/RFC)                      KeyExch.   Encryption  Bits     Cipher Suite Name (OpenSSL)
  # x1302   TLS_AES_256_GCM_SHA384                            ECDH 253   AESGCM      256      TLS_AES_256_GCM_SHA384
  # 1       2                                                 3    4     5           6        7...

  append_to_array(hosts, host)
  append_to_array(services, service)

  printf "* offered %s", $2

  # show DH parameters if present
  if ($3 ~ /DH/) {
    printf " (%s %s)", $3, $4
  }

  printf "\n"
}

/^ x/ && /_MD5/ {
  append_to_array(suite_hash_md5, service)
}

/^ x/ && /_SHA / {
  append_to_array(suite_hash_sha1, service)
}

/^ x/ && /_3?DES_/ {
  append_to_array(suite_cipher_des, service)
}

/^ x/ && /_RC2_/ {
  append_to_array(suite_cipher_rc2, service)
}

/^ x/ && /_RC4_/ {
  append_to_array(suite_cipher_rc4, service)
}

/^ x/ && /_IDEA_/ {
  append_to_array(suite_cipher_idea, service)
}

/^ x/ && /_CBC_/ {
  append_to_array(suite_cipher_mode_cbc, service)
}

/^ x/ && /DH_anon/ {
  append_to_array(suite_auth_anon, service)
}

/^ x/ && /_GOST/ {
  append_to_array(suite_gost, service)
}

/^ x/ && /_NULL_/ {
  append_to_array(suite_null, service)
}

/^ x/ && /_PSK_/ {
  append_to_array(suite_keyex_psk, service)
}

/^ x/ && /DH (768|1024|2048)/ {
  append_to_array(suite_keyex_dh_short, service)
}

/^ x/ && ! ( /(EC)?DHE/ || ( /^ x13/ && /(EC)?DH / ) ) {
  append_to_array(suite_keyex_pfs, service)
}

END {
  printf "\n# summary grouped by vulnerabilities\n\n"

  print_array(protocol_ssl2, desc_protocol_ssl2)
  print_array(protocol_ssl3, desc_protocol_ssl3)
  print_array(protocol_tls10, desc_protocol_tls10)
  print_array(protocol_tls11, desc_protocol_tls11)
  print_array(protocol_tls13, desc_protocol_tls13)

  print_array(cert_sig_alg, desc_cert_sig_alg)
  print_array(cert_short_rsa_key, desc_cert_short_rsa_key)
  print_array(cert_trust, desc_cert_trust)
  print_array(cert_expired, desc_cert_expired)

  print_array(vuln_reneg_server, desc_vuln_reneg_server)
  print_array(vuln_reneg_client, desc_vuln_reneg_client)
  print_array(vuln_scsv, desc_vuln_scsv)
  print_array(vuln_crime, desc_vuln_crime)
  print_array(vuln_lucky13, desc_vuln_lucky13)
  print_array(vuln_heartbleed, desc_vuln_heartbleed)
  print_array(vuln_ccs, desc_vuln_ccs)
  print_array(vuln_freak, desc_vuln_freak)
  print_array(vuln_drown, desc_vuln_drown)
  print_array(vuln_ticketbleed, desc_vuln_ticketbleed)
  print_array(vuln_robot, desc_vuln_robot)

  print_array(suite_hash_md5, desc_suite_hash_md5)
  print_array(suite_hash_sha1, desc_suite_hash_sha1)

  print_array(suite_cipher_des, desc_suite_cipher_des)
  print_array(suite_cipher_rc2, desc_suite_cipher_rc2)
  print_array(suite_cipher_rc4, desc_suite_cipher_rc4)
  print_array(suite_cipher_idea, desc_suite_cipher_idea)

  # see Lucky Thirteen
  #print_array(suite_cipher_mode_cbc, desc_suite_cipher_mode_cbc)

  print_array(suite_auth_anon, desc_suite_auth_anon)

  print_array(suite_gost, desc_suite_gost)

  print_array(suite_null, desc_suite_null)

  print_array(suite_keyex_psk, desc_suite_keyex_psk)
  print_array(suite_keyex_dh_short, desc_suite_keyex_dh_short)
  print_array(suite_keyex_pfs, desc_suite_keyex_pfs)

  printf "\n# affected hosts\n\n"
  for (i in hosts) {
    printf "* `%s`\n", hosts[i]
  }
}
