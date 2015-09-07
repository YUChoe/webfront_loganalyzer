#!/usr/bin/python
# -*- coding: utf-8 -*-

from os import walk
import sys, os.path, glob, HTMLParser, re
import csv

# GROBAL PUBLIC
WAP = {}


def analize_csv(csvfile, txtfile):
  fp = open(csvfile, 'r')
  print '%s ... processing' % (csvfile)
  c = 0
  for line in fp :
    l = line[:-1].split(',')
    if l[0] == '""' or l[0] == '"No"' : continue
    # 0  "No","시간","장비","애플리케이션","도메인",
    # 5  "공격명","서버","클라이언트","차단여부","증거ID",
    # 10 "로그ID","애플리케이션ID","입력인터페이스","URL","URL인수",
    # 15 "데이터","기타"
    key = (l[1]+'.'+l[0]).replace('"', '')
    etc = ','.join(l[16:]).replace('"', '')

    for _l in etc.split(',') :
      _tmp = _l.split('=', 2)
      if len(_tmp) != 2 : continue
      (_k, _v) = _tmp
      if _k == "sigid" :
        sigid = _v
        break
    #print key, sigid #, l[8], etc
    if sigid not in WAP :
        WAP[sigid] = {}

    WAP[sigid][key] = line

    c += 1
    if c % 500 == 0 :
      sys.stdout.write('.')
      sys.stdout.flush()
  fp.close()
  sys.stdout.write('\n')
  # report
  print '%s ... reporting' % (txtfile)
  fp = open(txtfile, 'w')
  for sigid in WAP.keys() :
    fp.write( "%s %d\n" % (sigid, len(WAP[sigid])) )
  fp.close()


# main
mypath = "../results"

"""
for (dirpath, dirnames, filenames) in walk(mypath) :
  for filename in filenames :
    if not filename.endswith(".csv"):
        continue
    csv_filename = dirpath + '/' + filename
    outputfilename = dirpath + '/' + os.path.splitext(filename)[0]+'.txt'

    analize_csv(csv_filename, outputfilename)
"""

# test
analize_csv("../results/wf_검사회피(더블인코딩).csv", "../results/wf_검사회피(더블인코딩).txt")
