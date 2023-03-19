import json
import pathlib
import os.path

from . import SERVICE_SCHEMA
  
class Parser:
    '''
    parse results of the web scan.
    $ nikto -ask no -Cgidirs all -host {hostname} -port {port} -nointeractive -Format xml -output "{result_file}.xml" 2>&1 | tee "{result_file}.log"
    '''

    name = 'nikto'
    file_type = 'json'

    def __init__(self):
        self.services = {}

    def parse_files(self, files):
        for path in files[self.file_type]:
            self.parse_file(path)

        return self.services

    def parse_file(self, path):
        '''
        process the json formatted output of nikto for further processing. 
        All vulnerabilities are stored with their "id" and "msg".
        The id as a unique identifier from niktos vulnerability database.
        The message contains the description of the vulnerability

        '''
        service = copy.deepcopy(SERVICE_SCHEMA)

        try:
            if os.path.isfile(path):
                pass
            else:
                print(f"File: {path} does not exist")
                return
        except as e:
            print(f"An error occurred: {e}")
            return
            
        with open(path) as nikto_result_file:
            nikto_data = json.load(nikto_result_file)
            port = nikto_data['port']
            host = nikto_data['host']
            service['host'] = host
            service['port'] = port
            issues = service['issues']
            identifier = f"{host}:{port}"
            self.services[identifier] = service
            
            if port in [443,8443]:
                services['scheme'] = 'https'
            else
                services['scheme'] = 'http'
 
            for vuln in nikto_data['vulnerabilities']:
                vid = vuln['id']
                descr = vuln['msg']
                issues.



