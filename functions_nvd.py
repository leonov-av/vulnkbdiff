# -*- coding: utf-8 -*-
import requests
import re
import os
import zipfile
import json

##############  NVD  ###################

# Download all CVE feeds
def update_nvd_cve_feeds():
    r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
    for filename in re.findall("nvdcve-1.1-[0-9]*\.json\.zip",r.text):
        print(filename)
        # https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.zip
        r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
        with open("data/nvd_feeds/" + filename, 'wb') as f:
            for chunk in r_file:
                f.write(chunk)

# Process NVD CVE files and get object dicts
def get_cve_objects_dict(filename_regex="UNKNOWN", filenames = [], ignore_rejected = True):
    cve_objects = dict()
    for file_name in os.listdir("data/nvd_feeds/"):
        if os.path.isfile(os.path.join("data/nvd_feeds/", file_name)):
            if re.findall(filename_regex, file_name) or file_name in filenames:
                if file_name != ".gitignore":
                    print(os.path.join("data/nvd_feeds/", file_name))
                    archive = zipfile.ZipFile(os.path.join("data/nvd_feeds/", file_name), 'r')
                    jsonfile = archive.open(archive.namelist()[0])
                    cve_dict = json.loads(jsonfile.read())
                    jsonfile.close()
                    for cve in cve_dict['CVE_Items']:
                        if ignore_rejected:
                            if not "** REJECT **" in  cve['cve']['description']['description_data'][0]['value']:
                                cve_objects[cve['cve']['CVE_data_meta']['ID']] = cve
                        else:
                            cve_objects[cve['cve']['CVE_data_meta']['ID']] = cve
    return cve_objects

# Get CVE IDs from the NVD files
def get_nvd_cves_from_nvd_site(cve_year_regex=".*"):
    nvd_cves = set()
    file_list = os.listdir("data/nvd_feeds/")
    file_list.sort()
    for file_name in file_list:
        if os.path.isfile(os.path.join("data/nvd_feeds/", file_name)):
            objects = get_cve_objects_dict(filenames=[file_name], ignore_rejected=True)
            for cve_id in objects:
                # print(cve_id)
                if re.findall(cve_year_regex, cve_id):
                    nvd_cves.add(cve_id)
    return(nvd_cves)