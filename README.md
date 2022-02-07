# VulnKBdiff - Vulnerability Knowledge Base comparison tool

VulnKBdiff makes CVE-based comparison for Nessus, OpenVAS and NVD Knowledge Bases. You can see the results in my [telegram channel](https://t.me/avleonovcom/777). 

**WARNING!!!** The only catch is that I am getting Nessus CVEs from [Vulners collection](https://vulners.com/stats), NOT from NASL plugins. This means that you will need to have your own commercial/researcher Vulners license for this and set in **api_key** variable. ¯\\\_(ツ)_/¯ If you are interested in such license contact sales@vulners.com.

Well, it should be possible to get Nessus plugins for analysis from an existing Nessus installation or by using [all-2.0.tar.gz](https://community.tenable.com/s/article/Update-Nessus-Plugins-Using-tar-gz-File) file, but I haven't tried it yet. The publicly available [nessus-updates](https://www.tenable.com/downloads/nessus?loginAttempted=true) files are not good for this because Tenable releases them with more than a month delay and they are not in fact in valid tar.gz. 😕