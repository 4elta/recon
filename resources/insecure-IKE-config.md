# insecure IKE configuration

this document's only purpose is to provide a guide on how to setup an **intentionally insecure** VPN server in order to test the `icke` (`ike-scan`) tool.

follow the guide on [how to set up an IKEv2 VPN server with strongSwan](https://www.digitalocean.com/community/tutorials/how-to-set-up-an-ikev2-vpn-server-with-strongswan-on-ubuntu-22-04) by DigitalOcean.

## adaptions

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
