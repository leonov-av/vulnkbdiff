# -*- coding: utf-8 -*-
import time
import datetime
import functions_cve_sets
import base64
from matplotlib_venn import venn2, venn3, venn3_unweighted

from pylab import *
import functions_nvd
import functions_reports

def get_base_64_from_file(file_path):
    encoded_string = ""
    with open(file_path, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
    return(encoded_string)

def get_img_tag_from_file(file_path, alt =""):
    return('<img src="data:image/png;base64, ' + get_base_64_from_file(file_path) +
           '" alt="' + alt + '" />')

def make_nvd_nessus_openvas_report(profile):
    today = datetime.date.today()
    date_value = today.strftime("%Y-%m-%d")
    if profile['name'] == "CISA Known Exploited":
        profile['vulnerabilities_json'] = functions_cve_sets.get_cisa_known_exploited_vulnerabilities_json()

    report_name = date_value + "_" + profile['file_name'] + ".html"
    report = list()
    report.append(get_img_tag_from_file("images/logo.png"))

    report.append("<p>Profile: " + profile['name'] + "</p>")
    cve_set = functions_reports.get_cve_set(profile)
    report.append("<p>Filtered CVEs: " +  str(len(cve_set)) + "</p>")

    openvas_cves = functions_reports.get_filtered_cves(report_data_name="openvas_cves.json", cve_set=cve_set)
    report.append("<p>OpenVAS CVEs: " + str(len(openvas_cves)) + "</p>")
    nessus_cves = functions_reports.get_filtered_cves(report_data_name="nessus_cves.json", cve_set=cve_set)
    report.append("<p>Nessus CVEs: " + str(len(nessus_cves)) + "</p>")
    nvd_cves = functions_reports.get_filtered_cves(report_data_name="nvd_cves.json", cve_set=cve_set)
    report.append("<p>NVD CVEs: " + str(len(nvd_cves)) + "</p>")

    # Drawing Nessus and OpenVAS report

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
    plt.title(set_one_name + " and " + set_two_name + " (" + profile['name'] + ")")
    # plt.show()
    plt.savefig("data/report_data/temp_venn2.png")
    report.append(get_img_tag_from_file("data/report_data/temp_venn2.png"))

    end = time.time()
    print(len(nessus_cves))
    print(str(int(end) - int(start)) + " s")

    start = time.time()
    plt.figure(figsize=(6, 6))
    print(len(set_one))
    print(len(set_two))
    print(len(set_three))

    v = venn3(subsets=[set(set_one), set(set_two), set(set_three)],
              set_labels=(set_one_name, set_two_name, set_three_name),
              set_colors=(set_one_color, set_two_color, set_three_color))


    plt.title(set_one_name + ", " + set_two_name + " and " + set_three_name + " (" + profile['name'] + "), weighted")
    plt.savefig("data/report_data/temp_venn3.png")
    report.append(get_img_tag_from_file("data/report_data/temp_venn3.png"))

    end = time.time()
    print(len(nessus_cves))
    print(str(int(end) - int(start)) + " s")


    start = time.time()
    plt.figure(figsize=(6, 6))
    print(len(set_one))
    print(len(set_two))
    print(len(set_three))

    v = venn3_unweighted(subsets=[set(set_one), set(set_two), set(set_three)],
              set_labels=(set_one_name, set_two_name, set_three_name),
              set_colors=(set_one_color, set_two_color, set_three_color))


    plt.title(set_one_name + ", " + set_two_name + " and " + set_three_name + " (" + profile['name'] + "), unweighted")
    plt.savefig("data/report_data/temp_venn3.png")
    report.append(get_img_tag_from_file("data/report_data/temp_venn3.png"))

    end = time.time()
    print(len(nessus_cves))
    print(str(int(end) - int(start)) + " s")

    #Lists
    only_openvas = list(openvas_cves - nessus_cves)
    only_openvas.sort()
    report.append("<h3>Only OpenVAS (" + str(len(only_openvas)) + ") </h3>")
    report.append("<ul>")
    for cve_id in only_openvas:
        report.append("<li>" + functions_reports.get_cve_comment(cve_id, profile) + "</li>")
    report.append("</ul>")

    only_nessus = list(nessus_cves - openvas_cves)
    only_nessus.sort()
    report.append("<h3>Only Nessus (" + str(len(only_nessus)) + ") </h3>")
    report.append("<ul>")
    for cve_id in only_nessus:
        report.append("<li>" + functions_reports.get_cve_comment(cve_id, profile) + "</li>")
    report.append("</ul>")

    not_nessus_and_openvas = list(nvd_cves - openvas_cves - nessus_cves)
    not_nessus_and_openvas.sort()
    report.append("<h3>CVEs not detected by Nessus and OpenVAS (" + str(len(not_nessus_and_openvas)) + ") </h3>")
    report.append("<ul>")
    for cve_id in not_nessus_and_openvas:
        report.append("<li>" + functions_reports.get_cve_comment(cve_id, profile) +  "</li>")
    report.append("</ul>")

    nessus_invalid_cves = list(nessus_cves - nvd_cves)
    if nessus_invalid_cves:
        nessus_invalid_cves.sort()
        report.append("<h3>Nessus invalid CVEs (" + str(len(nessus_invalid_cves)) + ") </h3>")
        report.append("<ul>")
        for cve_id in nessus_invalid_cves:
            report.append("<li>" + functions_reports.get_cve_comment(cve_id, profile) +  "</li>")
        report.append("</ul>")

    openvas_invalid_cves = list(openvas_cves - nvd_cves)
    if openvas_invalid_cves:
        openvas_invalid_cves.sort()
        report.append("<h3>OpenVAS invalid CVEs (" + str(len(openvas_invalid_cves)) + ") </h3>")
        report.append("<ul>")
        for cve_id in openvas_invalid_cves:
            report.append("<li>" + functions_reports.get_cve_comment(cve_id, profile) +  "</li>")
        report.append("</ul>")


    report_text = "\n".join(report)
    f = open("reports/" + report_name, "w")
    f.write(report_text)
    f.close()

# ## Update Raw data
# functions_reports.update_raw_data()
#
# # Update CVE Vulners Collection
# functions_reports.update_cve_report_data_files();


profile = dict()
profile['name'] = "CISA Known Exploited"
profile['file_name'] = "cisa_exploited"
make_nvd_nessus_openvas_report(profile)

profile = dict()
profile['name'] = "Published in 2021"
profile['file_name'] = "nvd_published2021"
make_nvd_nessus_openvas_report(profile)


