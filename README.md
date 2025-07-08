# recon tool suite

Based on the services identified on a network host, we often need to run specific tools to assess the security/configuration of these services.
The recon tool suite can help you automate that and analyze/summarize the results.

## motivation

Instead of manually running various tools (e.g. [testssl.sh](https://testssl.sh/), [Nikto](https://cirt.net/nikto2), [feroxbuster](https://github.com/epi052/feroxbuster), etc.) and having to remember all commands and the necessary options, we can configure them once (see [`config/scanner.toml`](config/scanner.toml)) and have the scanner (i.e. `scan.py`) run the required/appropriate tools based on what the Nmap service scan (e.g. `services.xml`) has found.
In addition to that, the suite also provides a tool to analyze and summarize the results of some scans (e.g. HTTP response headers, various protocol-specific configurations, etc.).
This allows for an automated and consistent assessment of specific services (i.e. no longer are testers forced to analyze configurations by hand).

## installation

The tools in this suite (i.e. `analyze.py` and `scan.py`) require Python 3.11+.

Clone the git repository:

```shell
# this step is optional; change the directory name to your preference
mkdir --parents $HOME/tools && cd $_

git clone https://github.com/4elta/recon.git
cd recon
```

Install the required tools:

```shell
mkdir --parents $HOME/tools
./install-required-tools.sh $HOME/tools
```

The script will install the following tools:

* [BIND 9](https://www.isc.org/bind/)
* [curl](https://curl.se/)
* [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)
* [IKE scanner](https://github.com/royhills/ike-scan)
* [NFS support](https://linux-nfs.org/)
* [Nmap](https://nmap.org/)
* [Nikto](https://www.cirt.net/Nikto2)
* Python libraries
  * [defusedxml](https://github.com/tiran/defusedxml)
  * [dnspython](https://www.dnspython.org/)
  * [Impacket](https://github.com/fortra/impacket)
  * [Jinja](https://github.com/pallets/jinja/)
  * [Rich](https://github.com/Textualize/rich)
* [RPC support](http://sourceforge.net/projects/rpcbind/)
* [Samba client](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
* [SecLists](https://github.com/danielmiessler/SecLists)
* [SIPVicious](https://github.com/EnableSecurity/sipvicious)
* [testssl.sh](https://testssl.sh/)
* [WhatWeb](https://morningstarsecurity.com/research/whatweb)

Based on the scan config (i.e. [`config/scans.toml`](config/scans.toml)) you are using, you might have to install additional tools.

Add symbolic links to the scripts to `/usr/local/bin`.
Please make sure, that the names for `analyze` and `scan` don't [conflict](https://github.com/4elta/recon/issues/31) with any binaries already installed.

```shell
sudo ln --symbolic "$(realpath analyze.py)" /usr/local/bin/analyze
sudo ln --symbolic "$(realpath scan.py)" /usr/local/bin/scan
```

## usage

1. run your "standard" Nmap port and service scan(s); make sure to use `-sV` and `-oX services.xml` for the service scan
2. run the scanner on the results of the Nmap service scan; be aware that this (like the Nmap scan itself) will send requests to the target system(s)
3. run the analyzer on the results of the scanner; no network traffic will be generated during this step

You can customize the configuration for the scanner (i.e. what tools to run, etc.) by modifying the provided one (i.e. [`config/scans.toml`](config/scans.toml)), or you can specify your own with the `--config` argument.
Similarly, you can modify the recommendations based on what the analyzers will evaluate certain services.
Make sure to have a look at the [architecture documentation](documentation/architecture.md) and/or study the provided configuration files.

### scanner

```text
% scan -h
usage: scan [-h] [-i path [path ...]] [-o path] [-c path] [-t number] [-s number] [-m seconds] [-n] [-r <host>:<protocol>:<port>:<service> [<host>:<protocol>:<port>:<service> ...]] [-y] [-d character] [--ignore_uid]

Schedule and execute various tools based on the findings of an Nmap service scan.

options:
  -h, --help            show this help message and exit
  -i, --input path [path ...]
                        path to the result file(s) of the Nmap service scan (default: 'services.xml')
  -o, --output path     path to where the results are stored (default: './recon')
  -c, --config path     path to the scanner configuration file (default: '/path/to/recon/config/scanner.toml')
  -t, --concurrent_targets number
                        number of targets that should be scanned concurrently (default: 3)
  -s, --concurrent_scans number
                        number of scans that should be running concurrently on a single target (default: 2)
  -m, --max_time seconds
                        maximum time in seconds each scan is allowed to take (default: 3600)
  -n, --dry_run         do not run any command; just create/update the 'commands.csv' file
  -r, --rescan <host>:<protocol>:<port>:<service> [<host>:<protocol>:<port>:<service> ...]
                        re-scan certain hosts/protocols/ports/services and overwrite existing result files; you can use '*' if you cannot or don't want to specify a host/protocol/port/service part
  -y, --overwrite_results
                        overwrite existing result files
  -d, --delimiter character
                        character used to delimit columns in the 'commands.csv' and 'services.csv' files (default: ',')
  --ignore_uid          ignore the warning about potentially lacking permissions
```

After running the scanner, the results directory (e.g. `recon/`) will contain the following files/directories:

* `commands.csv`: contains information about the executed commands (incl. start time, end time and return code)
* `scan.log`: the debug/error log of the scanner
* `services.csv`: contains information about the identified services (incl. whether they have been scanned or not)
* `<IP address>/`: each host has its own directory where the result files of the various tools are stored
  * the result files follow a specific naming scheme: `<service>[,<transport protocol>,<port>,...],<tool>.<ext>`
* `<IP address>.md`: this file contains a list of services identified on this particular host

### analyzer

```text
% analyze -h
usage: analyze [-h] [-c path] [-s code] [-t name] [-r path] [-i path] [-l code] [-f code] [--template path] [-o path]

Analyze and summarize the results of specific tools previously run by the scanner of the recon tool suite (i.e. 'scan').

options:
  -h, --help            show this help message and exit
  -c, --config path     path to the analyzer configuration file (default: '/path/to/recon/config/analysis.toml')
  -s, --service code    service that should be analyzed
  -t, --tool name       tool whose results are to be parsed
  -r, --recommendations path
                        path to the recommendations document (default: '/path/to/recon/config/recommendations/<service>/default.toml')
  -i, --input path      path to the root directory that holds the results to be analysed (default: './recon')
  -l, --language code   language in which the analysis should be printed (default: 'en')
  -f, --format code     format of the analysis (choices: ['md', 'json', 'csv']; default: 'md')
  --template path       path to the Jinja2 template for the analysis; this option overrides '-f/--format'
  -o, --output path     path to the directory where the analysis result(s) will be saved
```

The following analyzers (and parsers) are currently implemented:

* DNS configuration (`nase`, `nmap`)
* FTP configuration (`nmap`)
* HTTP response headers (`nmap`, `curl`)
* ISAKMP/IKE configuration (`ike`)
* NTP configuration (`ntp`, `nmap`)
* RDP configuration (`nmap`)
* SMB configuration (`nmap`)
* SSH configuration (`nmap`)
* TLS configuration (`testssl`, `sslscan`, `sslyze`, `nmap`)

The following languages are currently available for the analysis:

* `en`: English
* `de`: Deutsch

The analyzer can print its results in Markdown, JSON or CSV.
If you need the analysis in a markup format other than Markdown, just [pipe](https://en.wikipedia.org/wiki/Pipeline_(Unix)) the output of the analyzer to [`pandoc`](https://pandoc.org/) and you are good to go.
Below is an example of a conversion to `docx`:

```text
$ analyze [...] | pandoc --from=markdown --to=docx --output="/path/to/analysis.docx"
```

## contribution

If we have piqued your interest in this project (e.g. to contribute some ideas or a new tool to be included, or even an analyzer), the [architecture documentation](documentation/architecture.md) might be a good place to start to learn how the different components of this tool suite work together.
