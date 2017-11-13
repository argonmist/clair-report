#! /usr/bin/python
import os
import subprocess
import sys
import re
import datetime

def main():
  noaffect = []
  report_name = []
  past = []
  y = datetime.datetime.now()
  this_year = y.year
  if os.path.isdir("./logs") == False:
    cmd = "mkdir logs"
    subprocess.call(cmd.split())
  if sys.argv[1] == "--image":
    local_ip = "127.0.0.1"
    gen_log(local_ip, sys.argv[2])
    all_cve = find_cveid('logs/tmp.log', this_year, 1999)
    low = filters(all_cve, "filters/low.yaml")
    moderate = filters(all_cve, "filters/moderate.yaml")
    important = filters(all_cve, "filters/important.yaml")
    critical = filters(all_cve, "filters/critical.yaml")
    gen_report(sys.argv[2], this_year, 1999, low, moderate, important, critical)
    clear()
  else:
    print "Invalid Arguments"

def filters(all_cve, path):
  fo = open(path, 'r')
  fils = fo.readlines()
  for j in range(len(fils)):
    fils[j] = fils[j].rstrip()
  result = []
  for i in range(len(all_cve)):
    if all_cve[i] in fils:
       result.append(all_cve[i])
  return result

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

def gen_log(ip, img):
  cmd = "./clair-scanner -w filters/others.yaml -l logs/tmp.log" + " --ip " + ip + " " + img
  subprocess.call(cmd.split())

def gen_report(img_name, this_year, cve_start_year, low, moderate, important, critical):
  s = 'www/content/clair.rst'
  title_sharp = ''
  clear = open(s, 'r+')
  clear.truncate()
  report = open(s, 'a')
  time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
  for i in range(len(img_name)):
    title_sharp = title_sharp + "#"
  report.write(img_name + "\n" + title_sharp + "\n\n:date: "+ time + "\n:category: Report\n\n")
  report.write('Image: ' + img_name + '\n\n')
  report.close()
  report_content(s, 'Low Vulnerabilities:\n', low)
  report_content(s, 'Moderate Vulnerabilities:\n', moderate) 
  report_content(s, 'Important Vulnerabilities:\n', important)
  report_content(s, 'Critical Vulnerabilities:\n', critical)
  report.close()
  os.chdir('www')
  cmd = "pelican content"
  subprocess.call(cmd.split())

def report_content(path, vuls, level):
  tmp = ''
  hyperlink = []
  report = open(path, 'a')
  report.write(vuls)
  for i in range(len(level)):
    tmp = tmp + level[i] + '_ '
    hyperlink.append('.. _' + level[i] + ': http://www.cvedetails.com/cve/' + level[i] + '/?q=' + level[i] + '\n')
  if tmp == '':
    report.write('not vulnerable\n\n')
  else:
    tmp = tmp + '\n\n'
    report.write(tmp)
    for j in range(len(hyperlink)):
      report.write(hyperlink[j])
    report.write('\n')
    report.close()
	
def clear():
  cmd = "rm ../logs/tmp.log"
  subprocess.call(cmd.split())

if __name__ == "__main__":
  main()
