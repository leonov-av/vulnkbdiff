import requests

def get_cisa_known_exploited_vulnerabilities_json():
    r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    return r.json()

def get_cisa_known_exploited_vulnerabilitie_cve_list(vulnerabilities_json):
    cve_ids = set()
    for vulnerability in vulnerabilities_json['vulnerabilities']:
        cve_ids.add(vulnerability['cveID'])
    return cve_ids

import json
import functions_nvd
def get_cves_published_year(year):
    f = open("data/report_data/nvd_objects.json", "r")
    vulnerability_objects = json.loads(f.read())
    f.close()
    cve_ids = set()
    start = functions_nvd.get_ts_from_cve_date(year+"-01-01")
    end = functions_nvd.get_ts_from_cve_date(year+"-12-31")
    for vulnerability in vulnerability_objects:
        if int(vulnerability_objects[vulnerability]['published_ts']) >= int(start) and \
            int(vulnerability_objects[vulnerability]['published_ts']) <= int(end):
                cve_ids.add(vulnerability)
    return cve_ids
# vulnerabilities_json = get_cisa_known_exploited_vulnerabilities_json()
# print(get_cisa_known_exploited_vulnerabilitie_cve_list(vulnerabilities_json))