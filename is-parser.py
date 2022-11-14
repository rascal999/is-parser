#!/usr/bin/env python3

from os.path import exists
from pathlib import Path
from string import Template

import argparse
import json
import os
import sys

class bcolours:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Range(object):
    def __init__(self, start, end):
        self.start = start
        self.end = end
    def __eq__(self, other):
        return self.start <= other <= self.end

def welcome():
  print("Parse IS JS file (containing JSON object) issues based on template file.")
  print()

def main():
    parser = argparse.ArgumentParser(description="Parse IS JS file (containing JSON object) to output issues based on template file.")
    parser.add_argument("--min-cvss", required=False, type=float, default=0, choices=[Range(0.0, 10.0)],
                        help="Only include issues with at least this rating or above (default: 0)")
    parser.add_argument("--max-cvss", required=False, type=float, default=10, choices=[Range(0.0, 10.0)],
                        help="Only include issues with less than or equal to this rating (default: 10)")
    parser.add_argument("--js", required=False, default="AssessmentResults.js",
                        help="IS JS file")
    parser.add_argument("--template", required=False, default="issue.tex.template",
                        help="Template to build issues from")
    parser.add_argument("--output", required=False, default="is-output",
                        help="Output directory to create issues (default: is-output)")

    parsed = parser.parse_args()

    # Open template
    template_string = Path(parsed.template).read_text()

    # Open JS file
    with open(parsed.js, 'r') as file:
      data = file.read().replace('"','\"').replace("'",'"').replace("ASSESSMENT_RESULTS = ","").replace("};","}").replace("<br>"," ")

    json_obj = json.loads(data)

    # Check / create output directory
    if os.path.exists(parsed.output):
      print("ERROR: Output directory exists, bailing..")
      sys.exit(1)
    os.mkdir(parsed.output)

    # Server address
    host = json_obj['serverAddress']

    # For each issue
    for issue in json_obj['assessments']:
      # Don't include issues which have passed or errored
      if issue['result'] == "Passed" or issue['result'] == "Error":
        continue
      out_of_range = True
      # Only include issues in range
      if issue['score'] >= parsed.min_cvss and issue['score'] <= parsed.max_cvss:
        out_of_range = False
      if out_of_range:
        continue

      temp_obj = Template(template_string)
      if len(issue['cveLink']) == 0:
        issue['cveLink'] = "N/A"
      issue_file = open(parsed.output + "/" + issue['test'].replace("/","_") + ".tex", "w")
      issue_file.write(
        temp_obj.substitute(
          cvss3=issue['score'],
          name=issue['test'],
          plugin_output=issue['regulations'],
          synopsis=issue['description'],
          # There must be a better way..
          cve="        \item \\href{{https://cve.mitre.org/cgi-bin/cvename.cgi?name={0}}}{{{0}}}\n".format("".join(cve for cve in issue['cveLink'].split())),
          host=host,
          solution=issue['remediation'],
          see_also = "N/A"
        )
      )
      issue_file.close()

if __name__ == "__main__":
  main()
