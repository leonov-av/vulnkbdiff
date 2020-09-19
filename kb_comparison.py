# -*- coding: utf-8 -*-
from matplotlib import pyplot as plt
from matplotlib_venn import venn2, venn3
from zipfile import ZipFile
from pylab import *
import eventlet
import requests
import re
import os
import zipfile
import json
import time

## Install Dependencies
# eventlet
# pylab
# matplotlib
# matplotlib-venn

api_key = ""

##############  Vulners  ###################

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

##############  OpenVAS  ###################

# Bash command to update OpenVAS plugins
# cd data/openvas_plugins
# rsync -a rsync://feed.community.greenbone.net:/nvt-feed nvt-feed

# Get the list of OpenVAS plugins
def get_openvas_plugin_list():
    path = "data/openvas_plugins"
    plugin_list = [os.path.join(dp, f) for dp, dn, filenames in os.walk(path) for f in filenames if
                   os.path.splitext(f)[1] == '.nasl']
    return (plugin_list)

def get_cves_from_openvas_plugin(plugin_path):
    f = open(plugin_path, "r", encoding="ISO-8859-1")
    content = f.read()
    f.close()
    content = re.sub("\n", "", content)
    content = re.sub("  *", " ", content)
    tag_found = False
    cves = set()
    for line in re.findall("script_cve_id *\([^\)]*\)", content):
        tag_found = True
        for cve_id in re.findall('CVE-[0-9]*-[0-9]*', line.upper()):
            cves.add(cve_id)

    if "script_cve_id" in content and tag_found == False:
        print("Error: plugin_path")
    return(cves)

# Get CVE IDs from the OpenVAS plugins files
def get_openvas_cves_from_openvas_plugins(cve_year_regex=".*"):
    all_cve_ids = set()
    filtered_cves = set()
    print("Processing the plugins..")
    n = 0
    list_of_sets = list()
    plugin_list = get_openvas_plugin_list()
    n_plugin_list = len(plugin_list)
    for plugin_path in plugin_list:
        if n % 5000 == 0:
            print(str(n) + "/" + str(n_plugin_list))
        list_of_sets.append(all_cve_ids.union(get_cves_from_openvas_plugin(plugin_path)))
        n += 1
    all_cve_ids = set().union(*list_of_sets)
    print("Filtering the CVEs..")
    for cve_id in all_cve_ids:
        if re.findall(cve_year_regex, cve_id):
            filtered_cves.add(cve_id)
    return(filtered_cves)


##############  Nessus  ###################
# Bash command to update Nessus plugins
# Download manually plugins at https://www.tenable.com/downloads/nessus?loginAttempted=true
# Todo make parsing of nessus-updates-8.11.1.tar.gz
# Note that there is latency: file is Aug 20, 2020; Now it's Sep 05, 2020;
# It's better to use Vulners data


##############  Vulners  ###################
def get_cve_list_from_vulners_collection(collection_name, cve_year_regex=".*"):
    archive = ZipFile("data/vulners_collections/" + collection_name + ".zip")
    archived_file = archive.open(archive.namelist()[0])
    archive_content = json.loads(archived_file.read())
    archived_file.close()
    cves = set()
    for object in archive_content:
        for cve in object['_source']['cvelist']:
            if re.findall(cve_year_regex, cve):
                cves.add(cve)
    return (cves)

##############  Reports  ###################

# Update report CVE data files to make the illustrations
def update_cve_report_data_files():
    # To make a report I need CVE sets for NVD, Nessus and OpenVAS

    # OpenVAS data I get directly from OpenVAS plugins
    print("Processing OpenVAS data...")
    start = time.time()
    openvas_cves = get_openvas_cves_from_openvas_plugins()
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
    nvd_cves = get_nvd_cves_from_nvd_site()
    end = time.time()
    print(len(nvd_cves))
    print(str(int(end)-int(start)) + " s")
    f = open("data/report_data/nvd_cves.json", "w")
    f.write(json.dumps(list(nvd_cves)))
    f.close()

    # Nessus data I get from Vulners collection
    print("Processing Nessus data...")
    start = time.time()
    nessus_cves = get_cve_list_from_vulners_collection("nessus")
    end = time.time()
    print(len(nessus_cves))
    print(str(int(end)-int(start)) + " s")
    f = open("data/report_data/nessus_cves.json", "w")
    f.write(json.dumps(list(nessus_cves)))
    f.close()

def get_filtered_cves(report_data_name, cve_regexp):
    f = open("data/report_data/" + report_data_name, "r")
    all_cves = json.loads(f.read())
    f.close()

    cves = set()
    for cve_id in all_cves:
        if re.findall(cve_regexp, cve_id):
            cves.add(cve_id)

    return(cves)


### Update Raw data
# Run this when you need to update the data
update_vulners_collections_for_cve_report()
update_nvd_cve_feeds()
# Perform this bash command manually to update OpenVAS plugins
# cd data/openvas_plugins; rsync -a rsync://feed.community.greenbone.net:/nvt-feed nvt-feed

### Update CVE Vulners Collection
update_cve_report_data_files();

cve_regexp = "CVE-2020-*"
#cve_regexp = "CVE-*-*"

openvas_cves = get_filtered_cves(report_data_name="openvas_cves.json", cve_regexp=cve_regexp)
print(len(openvas_cves))
nessus_cves = get_filtered_cves(report_data_name="nessus_cves.json", cve_regexp=cve_regexp)
print(len(nessus_cves))
nvd_cves = get_filtered_cves(report_data_name="nvd_cves.json", cve_regexp=cve_regexp)
print(len(nvd_cves))

# Drawing Nessus and OpenVAS report
print("Drawing Nessus and OpenVAS report")

set_one = nessus_cves
set_one_name = "Nessus"
set_one_color = '#00829b'

set_two = openvas_cves
set_two_name = "OpenVAS"
set_two_color = '#66c430'

set_three = nvd_cves
set_three_name = "NVD"
set_three_color = '#FF8000'

start = time.time()
plt.figure(figsize=(6, 6))
v = venn2(subsets=[set_one, set_two],
          set_labels=(set_one_name, set_two_name),
          set_colors=(set_one_color, set_two_color))
plt.title(set_one_name + " and " + set_two_name + " (" + cve_regexp + ")")
plt.show()
end = time.time()
print(len(nessus_cves))
print(str(int(end)-int(start)) + " s")


start = time.time()
plt.figure(figsize=(6, 6))
v = venn3(subsets=[set_one, set_two, set_three],
          set_labels=(set_one_name, set_two_name, set_three_name),
          set_colors=(set_one_color, set_two_color, set_three_color))
plt.title(set_one_name + ", " + set_two_name + " and " + set_three_name + " (" + cve_regexp + ")")
plt.show()
end = time.time()
print(len(nessus_cves))
print(str(int(end)-int(start)) + " s")

cve2020 = get_cve_objects_dict(filenames=['nvdcve-1.1-2020.json.zip'])
for cve_id in openvas_cves - nessus_cves:
    if cve_id in cve2020:
        try:
            baseScore = int(cve2020[cve_id]['impact']['baseMetricV2']['cvssV2']['baseScore'])
        except:
            baseScore = 0
        if baseScore > 9.5:
            print(cve_id + " - " + cve2020[cve_id]['cve']['description']['description_data'][0]['value'])