# -*- coding: utf-8 -*-
import credentials
import eventlet
import requests
import os
import json
import zipfile
import bigjson
import re

##############  Vulners  ###################

api_key = credentials.vulners_api_key

# Get available Vulners collections
def get_stat_objects():
    response = requests.get('https://vulners.com/api/v3/search/stats/')
    objects = json.loads(response.text)
    return (objects)

# Download specific Vulners collection (asinchroniously)
def download_vulners(object_names):
    def fetch(name):
        response = requests.get('https://vulners.com/api/v3/archive/collection/?type=' + name + '&apiKey=' + api_key)
        print(response.status_code)
        with open('data/vulners_collections/' + name + '.zip', 'wb') as f:
            f.write(response.content)
            f.close()
        return name + " - " + str(os.path.getsize('data/vulners_collections/' + name + '.zip'))

    pool = eventlet.GreenPool()
    for name in pool.imap(fetch, object_names):
        print(name)

# Download specific Vulners collection for CVE-based report
def update_vulners_collections_for_cve_report():
    objects = get_stat_objects()
    object_names = set()
    for name in objects['data']['type_results']:
        if "nessus" in name or "openvas" in name or "cve" in name:
            object_names.add(name)
    print(object_names)
    download_vulners(object_names)

# Getting CVE ID from the Vulners collection
def get_cve_list_from_vulners_collection(collection_name, cve_year_regex=".*"):
    archive = zipfile.ZipFile("data/vulners_collections/" + collection_name + ".zip")
    archived_file = archive.open(archive.namelist()[0])
    archive_content = json.loads(archived_file.read())
    archived_file.close()
    cves = set()
    for object in archive_content:
        for cve in object['_source']['cvelist']:
            if re.findall(cve_year_regex, cve):
                cves.add(cve)
    return (cves)

# Getting CVE ID from the Vulners collection
def get_cve_list_from_vulners_collection_raw_text(collection_name, cve_year_regex=".*"):
    # print("Extractacting data/vulners_collections/" + collection_name + ".zip")
    # with zipfile.ZipFile("data/vulners_collections/" + collection_name + ".zip", "r") as zip_ref:
    #     zip_ref.extractall("data/" + collection_name + "_plugins/")
    f = open("data/" + collection_name + "_plugins/" + collection_name + ".json" , "r")
    line = f.readline()
    all_cves = set()
    n = 0
    while line:
        if n % 20000 == 0 and n != 0:
            print(str(n))
        if re.findall("^\{", line):
            line = re.sub(",$","",line)
            for cve in json.loads(line)['_source']['cvelist']:
                all_cves.add(cve)
            n += 1
        line = f.readline()
    f.close()
    return all_cves



