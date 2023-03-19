import json
try:
    from . import SERVICE_SCHEMA
except:
    pass
  
# Opening JSON file
f = open('nikto-json-test.json')
  
# returns JSON object as 
# a dictionary
data = json.load(f)
  
# Iterating through the json
# list
#print((json.dumps(data, indent=2)))
for vuln in data['vulnerabilities']:
    print(json.dumps(vuln, indent=2))
#for i in data['emp_details']:
#    print(i)
f.close()

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
        pass
