# -*- coding: utf-8 -*-
from pylab import *
import subprocess
import re
import os

##############  OpenVAS  ###################

# Update OpenVAS plugins
def update_openvas_plugins():
    # Bash command to update OpenVAS plugins
    # cd data/openvas_plugins
    # rsync -av rsync://feed.community.greenbone.net:/nvt-feed nvt-feed
    return_code = subprocess.call("cd data/openvas_plugins; rsync -av rsync://feed.community.greenbone.net:/nvt-feed nvt-feed", shell=True)
    print(return_code)

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
