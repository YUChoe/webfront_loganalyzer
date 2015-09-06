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
  c = 0
  for line in fp :
    l = line[:-1].split(',')
    if l[0] == '""' or l[0] == '"No"' : continue
    # "No","시간","장비","애플리케이션","도메인","공격명","서버","클라이언트","차단여부","증거ID","로그ID","애플리케이션ID","입력인터페이스","URL","URL인수","데이터","기타"
    key = (l[1]+'.'+l[0]).replace('"','')
    wa_name = l[5].replace('"','')

    if wa_name not in WAP :
        WAP[wa_name] = {}

    WAP[wa_name][key] = l
    #print key, wa_name, l[8], l[16:]

    c += 1
    if c % 250 == 0 :
      sys.stdout.write('.')
      sys.stdout.flush()

def write_WAF_to_file() :
  path = '../result'
  pass

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

    for k in WAP.keys() :
      print k, len(WAP[k])

    #sys.exit()
    #update_completed(csv_filename)