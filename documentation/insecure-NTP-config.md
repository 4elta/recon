# insecure NTP configuration

this document's purpose is to provide a guide on how to setup an **intentionally insecure** NTP server on a ubuntu 22.04 LTS host.
this setup can then be used to test the Nmap script scan (`ntp-info` and `ntp-monlist`).

## installation

```text
$ sudo apt install ntp

...

The following packages will be REMOVED:
  systemd-timesyncd
The following NEW packages will be installed:
  libevent-pthreads-2.1-7 libopts25 ntp sntp
0 upgraded, 4 newly installed, 1 to remove and 2 not upgraded.
Need to get 855 kB of archives.
After this operation, 2296 kB of additional disk space will be used.
Do you want to continue? [Y/n]
```

verify installed version:

```text
$ sntp --version
sntp 4.2.8p15@1.3728-o Wed Feb 16 17:13:02 UTC 2022 (1)
```

## configuration

the main configuration file for NTP is located at `/etc/ntp.conf`.
if you need to, consult its [man page](https://man.archlinux.org/man/ntp.conf.5).

* modify the [pool zone](https://support.ntp.org/bin/view/Servers/NTPPoolServers):

```text
$ sudo sed -i'' -E 's:^pool (.)\..+$:server \1.europe.pool.ntp.org:g' /etc/ntp.conf
```

* restart the NTP server:

```text
$ sudo service ntp restart
```

* verify that the NTP server is running:

```text
$ sudo service ntp status
● ntp.service - Network Time Service
     Loaded: loaded (/lib/systemd/system/ntp.service; enabled; vendor preset: enabled)
     Active: active (running) since Wed 2023-03-22 07:27:46 UTC; 6s ago
       Docs: man:ntpd(8)
    Process: 3126 ExecStart=/usr/lib/ntp/ntp-systemd-wrapper (code=exited, status=0/SUCCESS)
   Main PID: 3132 (ntpd)
      Tasks: 2 (limit: 2234)
     Memory: 1.3M
        CPU: 39ms
     CGroup: /system.slice/ntp.service
             └─3132 /usr/sbin/ntpd -p /var/run/ntpd.pid -g -u 115:119

Mar 22 07:27:46 jammy ntpd[3132]: Listening on routing socket on fd #24 for interface updates
Mar 22 07:27:46 jammy ntpd[3132]: kernel reports TIME_ERROR: 0x2041: Clock Unsynchronized
Mar 22 07:27:46 jammy ntpd[3132]: kernel reports TIME_ERROR: 0x2041: Clock Unsynchronized
Mar 22 07:27:46 jammy systemd[1]: Started Network Time Service.
Mar 22 07:27:47 jammy ntpd[3132]: Soliciting pool server 91.189.91.157
Mar 22 07:27:48 jammy ntpd[3132]: Soliciting pool server 185.125.190.56
Mar 22 07:27:49 jammy ntpd[3132]: Soliciting pool server 91.189.94.4
Mar 22 07:27:50 jammy ntpd[3132]: Soliciting pool server 185.125.190.58
Mar 22 07:27:51 jammy ntpd[3132]: Soliciting pool server 185.125.190.57
Mar 22 07:27:52 jammy ntpd[3132]: Soliciting pool server 2620:2d:4000:1::40
```

* modify firewall:

```text
$ sudo ufw allow from any to any port 123 proto udp
```

* enable the firewall (if it isn't already):

```text
$ sudo ufw enable
```

* verify that the default configuration (excluding the modified pool zone) is in fact secure:

```text
$ sudo nmap -sU -sV -p 123 --script="banner,ntp-info,ntp-monlist" jammy

...

PORT    STATE SERVICE VERSION
123/udp open  ntp?
| ntp-info:
|_  receive time stamp: 2023-03-22T07:35:29

...
```

## misconfiguration

we can follow the [official documentation about access restrictions](https://support.ntp.org/Support/AccessRestrictions) to start misconfiguring our NTP server.

* remove any default restrictions:

```text
$ sudo sed -i'' 's:^restrict :#restrict :' /etc/ntp.conf
```

* restart the service

* verify that we can now read a lot more information about the system:

```text
$ sudo nmap -sU -sV -p 123 --script="banner,ntp-info,ntp-monlist" jammy
...

PORT    STATE SERVICE VERSION
123/udp open  ntp     NTP v4.2.8p15@1.3728-o (secondary server)
| ntp-info:
|   receive time stamp: 2023-03-22T08:47:22
|   version: ntpd 4.2.8p15@1.3728-o Wed Feb 16 17:13:02 UTC 2022 (1)
|   processor: x86_64
|   system: Linux/5.15.0-67-generic
|   leap: 0
|   stratum: 3
|   precision: -24
|   rootdelay: 51.133
|   rootdisp: 21.055
|   refid: 185.125.190.56
|   reftime: 0xe7c53e1a.7e1d7126
|   clock: 0xe7c53f14.86a7ea3a
|   peer: 16600
|   tc: 7
|   mintc: 3
|   offset: 9.906317
|   frequency: -32.990
|   sys_jitter: 7.979090
|   clk_jitter: 5.915
|   clk_wander: 1.818
|   tai: 37
|   leapsec: 201701010000
|_  expire: 202306280000\x0D

...
```

(un)fortunately, starting with version `4.2.7p26` an NTP server no longer responds to the `monlist` request:

```text
$ ntpdc -c monlist jammy
jammy.lan: timed out, nothing received
***Request timed out
```

if an NTP server does respond to this request, we know for sure that it is using an outdated and insecure version.
