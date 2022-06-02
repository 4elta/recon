# recon tool suite

Based on the services identified on a network host, we need to run specific tools to assess the security/configuration of these services.
The recon tool suite can help you automate that an analyze/summarize the results.

## motivation

Instead of manually running various tools (e.g. [testSSL](https://testssl.sh/), [Nikto](https://cirt.net/nikto2), [feroxbuster](https://github.com/epi052/feroxbuster), etc.) and having to remember all commands and the necessary options, we can configure the recon tool (see [`services.toml`](services.toml)) and have it run the required/appropriate tools based on what the Nmap service scan (e.g. `services.xml`) has found.
In addition to that, the suite also provides tools to analyze and summarize the results of some scans (e.g. HTTP security headers, TLS/SSH/IKE configuration, etc.).
This allows for an automated and consistent assessment of specific services (i.e. no longer are testers forced to analyze TLS/SSH configurations by hand).

## installation

Install the required tools:

```sh
sudo apt install curl dnsutils enum4linux-ng feroxbuster nikto nmap onesixtyone seclists smbclient snmp testssl.sh whatweb
```

Install the tool suite:

```sh
cd /path/to/tools
git clone https://github.com/4elta/recon.git
```

Be sure to have the scripts of the suite in your `PATH` variable; at least the `icke_ike.sh` should be, as it is only referenced by name (in `services.toml`).
Also, make sure that the scripts have the *executable* flag set.

## usage 

```sh
# this is how you would have run your service scan
#sudo nmap -sS -sU -Pn -p $ports -sV --version-all -v -oA services -iL targets-online.txt 

# create the necessary directory
mkdir --parents /path/to/project/recon && cd $_

# run the service-specific scans
/path/to/recon-tool-suite/recon.py -i /path/to/project/nmap/services.xml -o .
```

## analyze ans summarize specific scans

**HTTP security header**

```sh
/path/to/recon-tool-suite/analyzers/http-headers.awk /path/to/project/recon/*/services/*-index.log
```

**TLS configuration**

```sh
/path/to/recon-tool-suite/analyzers/tls-testssl.awk /path/to/project/recon/*/services/*-testssl.log
```

**SSH configuration**

```sh
/path/to/recon-tool-suite/analyzers/ssh-nmap.awk /path/to/project/recon/*/services/ssh*nmap.log
```

**IKE configuration**

```sh
/path/to/recon-tool-suite/analyzers/ike-icke_ike.awk /path/to/project/recon/*/services/*-icke_ike.log
```


