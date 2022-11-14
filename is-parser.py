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
      data = file.read().replace('"','\"').replace("'",'"').replace("ASSESSMENT_RESULTS = ","").replace("};","}").replace('_',"\\\_")

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
      if len(issue['score']) == 0:
        issue['score'] = 0
      if float(issue['score']) >= parsed.min_cvss and float(issue['score']) <= parsed.max_cvss:
        out_of_range = False
      if out_of_range:
        continue

      temp_obj = Template(template_string)
      issue_file = open(parsed.output + "/" + issue['test'].replace("/","_").replace('"',"").replace('\_','_') + ".tex", "w")
      issue_file.write(
        temp_obj.substitute(
          cvss3=issue['score'],
          name=issue['test'],
          plugin_output=issue['regulations'],
          synopsis=issue['details'].replace("<br>","\n\n"),
          # There must be a better way..
          host=host,
          solution=issue['remediation'].replace("<br>","\n\n"),
          see_also = "N/A"
        )
      )
      issue_file.close()

if __name__ == "__main__":
  main()
