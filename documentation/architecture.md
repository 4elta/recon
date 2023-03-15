# architecture

The recon tool suite consists of two main components: the scanner (i.e. `recon.py`) and the analyzer (i.e. `analyze.py`).
The scanner schedules and runs various tools, based on the results of an Nmap service scan.
The selection of tools, and the parameters used for each, can be specified in a configuration file.
The results of each of the used tools are saved to files.
In order to be parsed and analyzed by the analyzer, the filenames adhere to a specific pattern (e.g. `<protocol>,<host information>,<tool name>.<file extenstion>`).

## scanner

The scanner (i.e. `recon.py`) takes the result of an Nmap service scan as its input, and schedules and runs various tools, based on these services that were found on a particular host.

```text
PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
443/tcp   open   tls|http   Apache httpd 2.4.7 ((Ubuntu))
```

In the example shown above, Nmap reported both an SSH and an HTTP/TLS service on the host.
The scanner might then run an Nmap script scan targeting the SSH port, and the Nikto and Testssl tools targeting the HTTP/TLS service.
The selection of tools, and the parameters used for each, can be specified in a [TOML](https://toml.io/en/) configuration file.
Below is an example for such a file:

```toml
[http]
patterns = [ 'http' ]

  [http.scans.nikto]
  command = 'nikto -ask no -Cgidirs all -host {hostname} -port {port} -nointeractive -Format xml -output "{result_file}.xml" 2>&1 | tee "{result_file}.log"'

[ssh]
patterns = [ '^ssh' ]

  [ssh.scans.nmap]
  command = 'nmap -Pn -sV -p {port} --script="banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods" -oN "{result_file}.log" -oX "{result_file}.xml" {address}'

[tls]
patterns = [ 'https', '^ssl\|', '^tls\|' ]

  [tls.scans.testssl]
  command = 'testssl --ip one --nodns min --mapping no-openssl --warnings off --connect-timeout 60 --openssl-timeout 60 --logfile "{result_file}.log" --jsonfile "{result_file}.json" {hostname}:{port}'
```

A root [table](https://toml.io/en/v1.0.0#table) (e.g. `[http]`, `[ssh]` or `[tls]`) specifies the name of a scan class (i.e. the name of the protocol).
The `patterns` array (of each root table) specifies the regular expressions on which the Nmap-identified service name is matched against.

Each scan class can hold multiple scan commands (each can be fulfilled by a different tool), identified by the sub-table `[<scan class>.scans.<tool name>]`.
A scan command can utilize the following variables (i.e. `{variable}`):

* `address`: this holds the host's IP address
* `port`: this holds the port number where a specific service was found
* `result_file`: this is the path to where the results are stored (i.e. `/path/to/project/recon/<address>/services/<protocol>,<host information>,<tool name>`)
* `application_protocol`: this holds the identified application protocol (e.g. `http`, `ssh`, `smtp`, etc.)

In case the service was identified as a web service, the following additional variables are available:

* `hostname`: this holds the host's DNS name, or its IP address
* `scheme`: this is either `http` or `https`

In theory, it's also possible to inject (small) Python code inside curly brackets, which will get interpreted before the command is scheduled.

## analyzer

The analyzer component (i.e. `analyze.py`) provides functionality to analyze and summarize results of specific tools.
The actual analysis is based on some recommendations which are specified as TOML files.
TOML (or more generally: a markup language) was chosen because this guarantees that the recommendations are human-readable and hence easier to maintain than program code.
Example recommendations can be found in `config/recommendations/<protocol>/`.

The analyzer component consists of at least one analyzer sub-component (one for each protocol).
Each analyzer sub-component requires a parser sub-component that is responsible for mapping/parsing the result of a particular tool to an internal (tool-agnostic) representation of a service's configuration/vulnerabilities.
