#! /usr/bin/python
import os
import subprocess
import sys
import re
import datetime

def main():
  noaffect = []
  report_name = []
  y = datetime.datetime.now()
  this_year = y.year
  if sys.argv[1] == "-p" and sys.argv[3] == "-i":
    gen_log(sys.argv[2], sys.argv[4])
  noaffect = find_cveid('logs/no-affect.log', this_year, 1999)
  add_to_no_affect(noaffect)
  report_name.append(re.split('/', sys.argv[4]))
  gen_report(report_name[0][0], report_name[0][1], this_year, 1999)
  clear()

def find_cveid(path, this_year, cve_start_year):
  result = open(path, 'r')
  cve = result.readlines()
  year = []
  cvename = []
  cvexist = []
  cveinex = ''
  period = this_year - 1998
  for cveid in range(len(cve)):
    cvexist.append(re.split('CVE|]]| |-|'+ str(this_year)  + '/', cve[cveid]))
  for y in range(period):
    year.append(str(cve_start_year + y))
    for (i, data) in enumerate(cvexist):
      if year[y] in data:
        cveinex = i
        for (j, cvedata) in enumerate(cvexist[cveinex]):
          if year[y] in cvedata and cvexist[cveinex][j-1] == '':
            cvename.append('CVE-' + cvexist[cveinex][j] + '-' + cvexist[cveinex][j+1])
  return cvename

def add_to_no_affect(no_aff_cve):
  fo = open('filter/past.yaml', 'r')
  past_cve = fo.readlines()
  new_past_cve = []
  past = open('filter/past.yaml', 'a')
  for x in range(len(past_cve)):
    new_past_cve.append(re.split('  |: |\n', past_cve[x]))
  if len(new_past_cve)>=0:
    for i in range(len(no_aff_cve)):
      same = False
      s = "  "+ no_aff_cve[i] +": zlib\n"
      for j in range(len(new_past_cve)):
        if no_aff_cve[i] == new_past_cve[j][1]:
          same = True
      if same == False:
        past.write(s)
        add_to_all(s)  
  fo.close()
  past.close()

def add_to_all(s):
  low = open('filter/low.yaml', 'a')
  moderate = open('filter/moderate.yaml', 'a')
  important= open('filter/important.yaml.yaml', 'a')
  critical = open('filter/critical.yaml', 'a')
  low.write(s)
  moderate.write(s)
  important.write(s)
  critical.write(s)
  low.close()
  moderate.close()
  important.close()
  critical.close()

def gen_log(ip, img):
  cmd = "./clair-scanner -w filter/others.yaml -l logs/no-affect.log" + " --ip " + ip + " " + img
  subprocess.call(cmd.split())
  cmd = "./clair-scanner -w filter/only-low.yaml -l logs/low.log" + " --ip " + ip + " " + img
  subprocess.call(cmd.split())
  cmd = "./clair-scanner -w filter/only-moderate.yaml -l logs/moderate.log" + " --ip " + ip + " " + img
  subprocess.call(cmd.split())
  cmd = "./clair-scanner -w filter/only-important.yaml -l logs/important.log" + " --ip " + ip + " " + img
  subprocess.call(cmd.split())
  cmd = "./clair-scanner -w filter/only-critical.yaml -l logs/critical.log" + " --ip " + ip + " " + img
  subprocess.call(cmd.split())

def gen_report(img_name, tag, this_year, cve_start_year):
  s = 'report/' + img_name + '/' + tag + '/report.txt'
  if os.path.isfile(s) == False:
    low = find_cveid('logs/low.log', this_year, cve_start_year)
    moderate = find_cveid('logs/moderate.log', this_year, cve_start_year)
    important = find_cveid('logs/important.log', this_year, cve_start_year)
    critical = find_cveid('logs/critical.log', this_year, cve_start_year)
    cmd = 'sudo mkdir -p report/' + img_name + '/' + tag
    subprocess.call(cmd.split())
    report = open(s, 'a')
    report.write('Image: ' + img_name + '/' + tag + '\n')
    report_content(s, 'Low Vulnerabilities:\n', low)
    report_content(s, 'Moderate Vulnerabilities:\n', moderate) 
    report_content(s, 'Important Vulnerabilities:\n', important)
    report_content(s, 'critical Vulnerabilities:\n', critical)
    report.close()

def report_content(path, vuls, level):
  tmp = ''
  report = open(path, 'a')
  report.write(vuls)
  for i in range(len(level)):
    tmp = tmp + level[i] + ' '
  if tmp == '':
    report.write('not vulnerable\n\n')
  else:
    tmp = tmp + '\n\n'
    report.write(tmp)

def clear():
  cmd = "rm logs/low.log logs/moderate.log logs/important.log logs/critical.log logs/no-affect.log"
  subprocess.call(cmd.split())

if __name__ == "__main__":
  main()  