# insecure NTP configuration

from [github.com/PauluzzNL/docker-ntp](https://github.com/PauluzzNL/docker-ntp)

## pull docker image

```text
% podman pull docker.io/pauluzznl/ntp
```

## start container

```text
% podman run \
  --name=ntp \
  --restart=always \
  --detach=true \
  --publish=4123:123/udp \
  --cap-add=SYS_NICE \
  --cap-add=SYS_RESOURCE \
  --cap-add=SYS_TIME \
  pauluzznl/ntp
```

## test NTP server

```text
% sudo nmap -sU -sV -p 4123 -Pn --script="banner,ntp-info,ntp-monlist" localhost
...

PORT     STATE SERVICE VERSION
4123/udp open  ntp     NTP v4.2.6p5@1.2349-o (unsynchronized)
| ntp-monlist: 
|   Alternative Target Interfaces:
|       ...
|   Private Clients (1)
|_      ... 
| ntp-info: 
|   receive time stamp: ...
|   version: ntpd 4.2.6p5@1.2349-o Fri Apr 13 12:52:27 UTC 2018 (1)
|   processor: x86_64
|   system: Linux/6.12.38+deb13-amd64
|   leap: 3
|   stratum: 16
|   precision: -24
|   rootdelay: 0.000
|   rootdisp: 0.690
|   refid: INIT
|   reftime: 0x00000000.00000000
|   clock: 0xec7454db.2a4912f6
|   peer: 0
|   tc: 3
|   mintc: 3
|   offset: 0.000
|   frequency: 0.000
|   sys_jitter: 0.000
|   clk_jitter: 0.000
|_  clk_wander: 0.000\x0D
Service Info: OS: Linux/6.12.38+deb13-amd64
```
