#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Utilizing code from the cvedb.py file from Intel's cve-bin-tool
"""
import sqlite3
import sys


from cve_bin_tool.cvedb import  CVEDB


class CVEtoCWE:
    """
    This class is for querying the cve-bin-tool for the CWE associated with a CVE.
    """

    def getCWEs(self, cveIDs):
        cwes = []
        cveBinTooldb = CVEDB()
        years = cveBinTooldb.nvd_years()
        
        for year in years:
            cve_data = cveBinTooldb.load_nvd_year(year)
            for cve_item in cve_data["CVE_Items"]:
                if cve_item["cve"]["CVE_data_meta"]["ID"] in cveIDs:
                    cwe = cve_item["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]
                    cwes.append(cwe)

        return cwes


if len(sys.argv) < 2:
    print("No CVE given")
else:
    a = CVEtoCWE()
    cves = sys.argv[1:]
    cwes = a.getCWEs(cves)
    if cwes:
        for x in cwes:
            print(x)
            print(" ")
    else:
        print("CVE not found")

    


