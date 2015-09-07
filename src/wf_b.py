#!/usr/bin/python
# -*- coding: utf-8 -*-

from os import walk
import sys, os.path, glob, HTMLParser, re
import csv

# GROBAL PUBLIC
WAP = {}

# ###
def update_completed(filename) :
  fp = open(complete_list, 'a')
  fp.write(filename+'\n')
  fp.close()

def csv_to_WAF_array(csvfile):
  fp = open(csvfile, 'r')
  print '%s ... processing' % (csvfile)
  c = 0
  first_time = ''
  until_time = ''

  for line in fp :
    l = line[:-1].split(',')
    if l[0] == '""' or l[0] == '"No"' : continue
    # "No","시간","장비","애플리케이션","도메인","공격명","서버","클라이언트","차단여부","증거ID","로그ID","애플리케이션ID","입력인터페이스","URL","URL인수","데이터","기타"
    key = (l[1]+'.'+l[0]).replace('"','')
    if c == 0 :
      until_time = l[1]
    try:
      wa_name = l[5].replace('"','')
    except:
      print "Parse Error: " + line
      continue

    if wa_name not in WAP :
        WAP[wa_name] = {}

    WAP[wa_name][key] = line
    #print key, wa_name, l[8], l[16:]

    #c += 1
    #if c % 500 == 0 :
    #  sys.stdout.write('.')
    #  sys.stdout.flush()
    first_time = l[1]

  print "%s ~ %s" % (first_time, until_time)

def write_WAF_to_file() :
  path = '../results'
  for k in WAP.keys() :
    filename = path + "/wf_" + k + ".csv"
    print '%s ... processing' % (filename)
    fp = open(filename, 'w')
    c = 0

    for timeline in WAP[k] :
      fp.write(WAP[k][timeline])
      c += 1
      if c % 250 == 0 :
        sys.stdout.write('+')
        sys.stdout.flush()
    sys.stdout.write('\n')
    fp.close()


# main
mypath = "../datas"
complete_list = mypath + "/.csv.completed"
c_fp = open(complete_list,'r')
c_files = c_fp.readlines()

for (dirpath, dirnames, filenames) in walk(mypath) :
  combined_csv_filename = dirpath + '/' + 'wflog_web.csv'
  for filename in filenames :
    if not filename.endswith(".csv"):
        continue
    csv_filename = dirpath + '/' + filename
    if csv_filename+'\n' in c_files :
      continue
    csv_to_WAF_array(csv_filename)
    sys.stdout.write('\n')

    #update_completed(csv_filename)

# report
fp = open("../results/summery.txt", 'w')
for k in WAP.keys() :
  fp.write( "%s %d\n" % (k, len(WAP[k])) )
fp.close()

write_WAF_to_file()
