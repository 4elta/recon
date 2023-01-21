# recon tool suite

Based on the services identified on a network host, we often need to run specific tools to assess the security/configuration of these services.
The recon tool suite can help you automate that and analyze/summarize the results.

## motivation

Instead of manually running various tools (e.g. [sslyze](https://github.com/nabla-c0d3/sslyze), [Nikto](https://cirt.net/nikto2), [feroxbuster](https://github.com/epi052/feroxbuster), etc.) and having to remember all commands and the necessary options, we can configure the recon tool (see [`config.toml`](config.toml)) and have it run the required/appropriate tools based on what the Nmap service scan (e.g. `services.xml`) has found.
In addition to that, the suite also provides tools to analyze and summarize the results of some scans (e.g. HTTP security headers, TLS/SSH/IKE configuration, etc.).
This allows for an automated and consistent assessment of specific services (i.e. no longer are testers forced to analyze TLS/SSH configurations by hand).

## installation

Install the required tools:

```sh
git clone https://github.com/cddmp/enum4linux-ng.git; cd enum4linux-ng; sudo python3 setup.py install
sudo apt install curl dnsutils feroxbuster ike-scan nikto nmap onesixtyone seclists smbclient snmp sslyze testssl.sh whatweb
```

Install the tool suite:

```sh
cd /path/to/tools
git clone https://github.com/4elta/recon.git
cd recon
pip3 install -r requirements.txt
```

Be sure to have the scripts of the suite in your `PATH` variable; at least the `icke.sh` should be, as it is only referenced by name (in `config.toml`).
Also, make sure that the scripts have the *executable* flag set.

```sh
chmod +x analyzers/*
chmod +x icke.sh
chmod +x recon.py
ln -s $(realpath icke.sh) ~/bin/icke
ln -s $(realpath recon.py) ~/bin/recon
```

## usage

```txt
$ recon -h
usage: recon [-h] [-i INPUT] [-o OUTPUT] [-c CONFIG] [-t CONCURRENT_TARGETS] [-s CONCURRENT_SCANS] [-v] [-n] [-y]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        the result file of the Nmap service scan (default: 'services.xml')
  -o OUTPUT, --output OUTPUT
                        where the results are stored (default: './recon')
  -c CONFIG, --config CONFIG
                        path to the scan configuration file (default: '/path/to/recon-suite/config.toml')
  -t CONCURRENT_TARGETS, --concurrent_targets CONCURRENT_TARGETS
                        how many targets should be scanned concurrently (default: 3)
  -s CONCURRENT_SCANS, --concurrent_scans CONCURRENT_SCANS
                        how many scans should be running concurrently on a single target (default: 2)
  -v, --verbose         show additional info including all output of all scans
  -n, --dry_run         do not run any command; just create/update the 'commands.csv' file
  -y, --overwrite_results
                        overwrite existing result files
  -d DELIMITER, --delimiter DELIMITER
                        character used to delimit columns in the 'commands.csv' file (default: ',')
```

## analyze and summarize specific scans

**HTTP security header**

```shell
/path/to/recon-tool-suite/analyzers/http-headers-nmap.awk /path/to/project/recon/*/services/http*nmap.log
```

**TLS configuration**

```shell
/path/to/recon-tool-suite/analyzers/tls-sslyze.awk /path/to/project/recon/*/services/*-sslyze.log
```

**SSH configuration**

```shell
/path/to/recon-tool-suite/analyzers/ssh-nmap.awk /path/to/project/recon/*/services/ssh*nmap.log
```

**IKE configuration**

```shell
/path/to/recon-tool-suite/analyzers/ike-icke.awk /path/to/project/recon/*/services/*-icke.log
```


