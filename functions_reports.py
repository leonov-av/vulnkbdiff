# -*- coding: utf-8 -*-
import functions_vulners
import functions_nvd
import functions_openvas
import functions_cve_sets
from pylab import *
import re
import json
import time


##############  Raw data  ###################

def update_raw_data():
    # Run this when you need to update the data
    print("OpenVAS")
    functions_openvas.update_openvas_plugins()
    print("Vulners")
    functions_vulners.update_vulners_collections_for_cve_report()
    print("NVD")
    functions_nvd.update_nvd_cve_feeds()

##############  Preprocessed files  ###################

# Update report CVE data files to make the illustrations
def update_cve_report_data_files():
    # To make a report I need CVE sets for NVD, Nessus and OpenVAS

    # OpenVAS data I get directly from OpenVAS plugins
    print("Processing OpenVAS data...")
    start = time.time()
    openvas_cves = functions_openvas.get_openvas_cves_from_openvas_plugins()
    end = time.time()
    print(len(openvas_cves))
    print(str(int(end)-int(start)) + " s")
    f = open("data/report_data/openvas_cves.json", "w")
    f.write(json.dumps(list(openvas_cves)))
    f.close()

    # I can't use NVD data from Vulners, because processing > 1 Gb json files is not practical
    # Probably it can be done with stream json parser; Util then I left this commented
    # nvd_cves = get_cve_list_from_vulners_collection("cve", cve_year_regex)
    print("Processing NVD data...")
    start = time.time()
    nvd_cves, nvd_objects = functions_nvd.get_nvd_cves_from_nvd_site()
    end = time.time()
    f = open("data/report_data/nvd_cves.json", "w")
    f.write(json.dumps(list(nvd_cves)))
    f.close()
    f = open("data/report_data/nvd_objects.json", "w")
    f.write(json.dumps(nvd_objects))
    f.close()
    print(len(nvd_cves))
    print(str(int(end)-int(start)) + " s")


    # Nessus data I get from Vulners collection
    print("Processing Nessus data...")
    start = time.time()
    nessus_cves = functions_vulners.get_cve_list_from_vulners_collection_raw_text("nessus")
    end = time.time()
    print(len(nessus_cves))
    print(str(int(end)-int(start)) + " s")
    f = open("data/report_data/nessus_cves.json", "w")
    f.write(json.dumps(list(nessus_cves)))
    f.close()

def get_filtered_cves(report_data_name, cve_set):
    f = open("data/report_data/" + report_data_name, "r")
    all_cves = json.loads(f.read())
    f.close()
    cves = set()
    for cve_id in all_cves:
        if cve_id in cve_set:
            cves.add(cve_id)
    return(cves)

def get_cve_set(profile):
    if profile['name'] == "CISA Known Exploited":
        cves = functions_cve_sets.get_cisa_known_exploited_vulnerabilitie_cve_list(profile['vulnerabilities_json'])
    if profile['name'] == "Published in 2021":
        cves = functions_cve_sets.get_cves_published_year("2021")
    return(cves)

def get_cve_comment(cve_id, profile):
    if profile['name'] == "CISA Known Exploited":
        for line in profile['vulnerabilities_json']['vulnerabilities']:
            if line['cveID'] == cve_id:
                return(cve_id + " - " + line['vulnerabilityName'])
    else:
        return (cve_id)