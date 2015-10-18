
# -*- coding: UTF-8 -*-
import sys
from PySide import QtGui
from PySide import QtCore
import os
import urllib.parse
import urllib.request
import ssl
import shutil
from src.wf_a import html2csv
from bs4 import BeautifulSoup

#import subprocess
#from threading import Thread
#from datetime import datetime

class MainWindow( QtGui.QWidget ) :


  def __init__(self) :
    super(MainWindow, self).__init__()
    self.codec = QtCore.QTextCodec.codecForName("UTF-8")
    self.WAF_ipaddr = "121.156.124.197"
    self.processing_files = []

    self.WAFarray = {} # global key/value dataset

    self.initUI()
    self.overrideUI_for_dev()

  def overrideUI_for_dev(self):
    return

  def initUI(self) :
    self.UIset = []

    #self.setWindowIcon(QtGui.QIcon(r"asset/red.png"))
    self.setWindowFlags(QtCore.Qt.WindowMinimizeButtonHint) # cannot use maximun button
    self.setWindowTitle( 'WF LOG Analyzer-v0.9' )

    # align UI
    _x = 20
    _y = 70
    _vgap = 0
    _height = 25+8
    _row = 1
    _width = 140

    lbl_ipaddr = QtGui.QLabel('PIOLINK AV2 IP:', self)
    lbl_ipaddr.setStyleSheet('QLabel { font-family:Arial;}')
    lbl_ipaddr.move(_x, _y + (_height * _row))
    self.txt_ipaddr = QtGui.QLineEdit(self)
    self.txt_ipaddr.move( (_x+lbl_ipaddr.width()+_vgap), _y + (_height * _row) - 5)
    self.txt_ipaddr.setStyleSheet("QLineEdit {background: lightgray; font-family:Arial;}")
    self.txt_ipaddr.setFixedWidth(_width)
    self.UIset.append(self.txt_ipaddr)

    _row += 1
    lbl2 = QtGui.QLabel('관리자 ID:', self)
    lbl2.move(_x, _y + (_height * _row))
    lbl2.setStyleSheet('QLabel { font-family:Arial;}')
    self.txt_username = QtGui.QLineEdit(self)
    self.txt_username.move(_x+lbl2.width()+_vgap, _y + (_height * _row) - 5 )
    self.txt_username.setStyleSheet("QLineEdit {background: lightgray; font-family:Arial;}")
    self.txt_username.setFixedWidth(_width)
    self.UIset.append(self.txt_username)

    _row += 1
    lbl3 = QtGui.QLabel('패스워드:', self)
    lbl3.move(_x, _y + (_height * _row))
    lbl3.setStyleSheet('QLabel { font-family:Arial;}')
    self.txt_passwd = QtGui.QLineEdit(self)
    self.txt_passwd.setEchoMode(QtGui.QLineEdit.Password)
    self.txt_passwd.move(_x + lbl3.width() + _vgap, _y + (_height * _row) -5)
    self.txt_passwd.setStyleSheet("QLineEdit {background: lightgray; font-family:Arial;}")
    self.txt_passwd.setFixedWidth(_width)
    self.UIset.append(self.txt_passwd)

    _row += 1
    lbl4 = QtGui.QLabel('시작일:', self)
    lbl4.move(_x, _y + (_height * _row))
    lbl4.setStyleSheet('QLabel { font-family:Arial;}')
    self.txt_sdate = QtGui.QLineEdit(self)
    self.txt_sdate.setInputMask('0000-00-00')
    self.txt_sdate.move(_x+lbl2.width()+_vgap, _y + (_height * _row) - 5 )
    self.txt_sdate.setStyleSheet("QLineEdit {background: lightgray; font-family:Arial;}")
    self.txt_sdate.setFixedWidth(_width)
    self.UIset.append(self.txt_sdate)
    _row += 1
    lbl4 = QtGui.QLabel('종료일:', self)
    lbl4.move(_x, _y + (_height * _row))
    lbl4.setStyleSheet('QLabel { font-family:Arial;}')
    self.txt_edate = QtGui.QLineEdit(self)
    self.txt_edate.setInputMask('0000-00-00')
    self.txt_edate.move(_x+lbl2.width()+_vgap, _y + (_height * _row) - 5 )
    self.txt_edate.setStyleSheet("QLineEdit {background: lightgray; font-family:Arial;}")
    self.txt_edate.setFixedWidth(_width)
    self.UIset.append(self.txt_edate)

    _row += 1
    self.console_lbl = QtGui.QLabel('', self)
    self.console_lbl.move(_x, _y + (_height * _row))
    self.console_lbl.setStyleSheet('QLabel { font-family:Arial;}')

    self.progressbar = QtGui.QProgressBar(self)
    self.progressbar.setGeometry(100, _y + (_height * _row) - 5, 170, 20)

    _row += 0.8
    self.okButton = QtGui.QPushButton("시작", self)
    #okButton.setGeometry(20, 70, 60, 30)
    self.okButton.setStyleSheet('QPushButton {font-family:Arial;}')
    #self.okButton.move(_x+20, _y + (_height * _row))
    self.okButton.setGeometry(_x, _y + (_height * _row), 120, 50)
    self.okButton.clicked.connect( self.ok )
    self.UIset.append(self.okButton)

    self.cancelButton = QtGui.QPushButton("중단", self)
    #cancelButton.setGeometry(90, 70, 60, 30)
    self.cancelButton.setStyleSheet('QPushButton {font-family:Arial;}')
    #self.cancelButton.move(_x+20+self.okButton.width()+_vgap, _y + (_height * _row))
    self.cancelButton.setGeometry(_x+self.okButton.width()+_vgap, _y + (_height * _row), 120, 50)
    self.cancelButton.clicked.connect( self.cancel )
    self.UIset.append(self.cancelButton)

    # window position x, y , width, height
    self.setGeometry(300, 200, 275, 350)

    img_remotesig = QtGui.QLabel(self)
    img_remotesig.setPixmap(QtGui.QPixmap("assets/logo1.jpg").scaled(228, 78))
    img_remotesig.move((275-228)/2, 15)

    self.move(QtGui.QApplication.desktop().screen().rect().center()- self.rect().center())
    self.setFixedSize(self.size())
    palette = self.palette()
    #palette.setColor( self.backgroundRole(), QtGui.QColor(128,128,128))
    palette.setColor( self.backgroundRole(), QtGui.QColor(255,255,255))
    self.setPalette(palette)

    self.show()
    self.enableUIset()

  def disableUIset(self):
    for w in self.UIset:
      w.setEnabled(False)
    self.cancelButton.setEnabled(True)

  def enableUIset(self):
    for w in self.UIset:
      w.setEnabled(True)
    self.cancelButton.setEnabled(False)
    self.txt_ipaddr.setFocus()

  def popAlert(self, str):
    msgBox = QtGui.QMessageBox()
    msgBox.setText(str)
    msgBox.exec_()

  def ok(self) :
    sender = self.sender()
    self.disableUIset()

    if not self.prepare_downloading() :
      self.popAlert(u'환경 설정에 실패 했습니다.')
      self.cancel()
      return

    cookie = self.login_av2()
    self.download_xls_files(cookie)
    return

    #self.prepare_converting()

  def download_xls_files(self, cookie):
    if not cookie :
      self.popAlert(u'로그인에 실패 했습니다.')
      self.cancel()
      return

    self.console_lbl.setText(u'다운로드 중입니다.')
    self.console_lbl.adjustSize()

    _sdate = int(self.txt_sdate.text().replace("-", "")[6:8])
    _edate = int(self.txt_edate.text().replace("-", "")[6:8])

    self.progressbar.setRange (_sdate, _edate)

    csv_files = []
    for d in range(_sdate, _edate + 1) :
      self.progressbar.setValue(d)

      base_url = 'https://' + self.txt_ipaddr.text()
      _thisdate = self.txt_sdate.text()[:8] + ("%02d" % d)
      _get = "/log/logpop.php?mode=excel&log=p_menu_log_web&sfld=&akey=&"                \
           + "pval=" + _thisdate + ";00;00;00" + ";" + _thisdate + ";23;59;59" \
           + "&p_where=%20AND%20(%20l_equipment%20=%20%27" + self.WAF_ipaddr + "%27)&ma_sf_no=0"

      print(_get)
      req = urllib.request.Request(base_url + _get)
      req.add_header('cookie', cookie)

      file_name_only = u"av2_{0:s}.html".format(_thisdate).replace("-", "").replace(";", "")
      file_name = ".\\raw_datas\\" + file_name_only

      if not os.path.isfile(file_name) :
        with urllib.request.urlopen(req, context=ssl._create_unverified_context()) as response, open(file_name, 'wb') as out_file:
          shutil.copyfileobj(response, out_file)

      csv_files.append(self.html_to_csv_file(file_name_only))

      """
      urllib.error.HTTPError: HTTP Error 500: Internal Server Error
      """

    print("downloading and converting to csv format - finished")

    self.progressbar.setRange (1, len(csv_files))
    for cfile in csv_files :
      self.csv_to_WAF_array(cfile)
      self.progressbar.setValue( self.progressbar.value() + 1 )

    print("loading on Memory - finished")

    # report
    fp = open("summery.txt", 'w', encoding='utf-8')
    for k in self.WAFarray.keys() :
      fp.write( "%s %d\n" % (k, len(self.WAFarray[k])) )
    fp.close()

    waname_files = self.write_WAF_to_file()
    print("writing result file - finished")

    self.make_report(waname_files)
    print("making report - finished")

    self.console_lbl.setText(u'완료되었습니다.')
    self.WAFarray = {} # init again
    self.console_lbl.adjustSize()
    self.enableUIset()

  def make_report(self, waname_files):
    path = r'./result/'
    if not os.path.isdir(path):
      os.mkdir(path)

    for waname_file in waname_files:
      input_filename = os.path.basename(waname_file)
      output_filename = path + os.path.splitext(input_filename)[0]+'.txt'

      self.analize_csv(waname_file, output_filename)

  def parsing_method_1(self, l) :
    key = (l[1]+'.'+l[0]).replace('"', '')
    etc = ','.join(l[16:]).replace('"', '')
    sigid = ""

    for _l in etc.split(',') :
      _tmp = _l.split('=', 2)
      if len(_tmp) != 2 : continue
      (_k, _v) = _tmp
      if _k == "sigid" :
        sigid = _v
        break
    if l[5] == '"웹공격"' and sigid == "" :
      sigid = "User-Agent header 없음"

    return (key, sigid)

  def parsing_method_2(self, l) :
    key = (l[1]+'.'+l[0]).replace('"', '')
    return (key, l[13].replace('"',''))

  def parsing_method_3(self, l) :
    key = (l[1]+'.'+l[0]).replace('"', '')
    return (key, l[7].replace('"','').split(':')[0])

  def parsing_method_4(self, l) :
    key = (l[1]+'.'+l[0]).replace('"', '')
    etc = ','.join(l[16:]).replace('"', '')
    sigid = ""
    for _l in etc.split(',') :
      _tmp = _l.split('=', 2)
      if len(_tmp) != 2 : continue
      (_k, _v) = _tmp
      if _k == "method" :
        sigid = _v
        break
    return (key, sigid)

  def analize_csv(self, csvfile, txtfile):
    _WAP = {}
    fp = open(csvfile, 'r', encoding='utf-8', errors='ignore')
    for line in fp :
      l = line[:-1].split(',')
      if l[0] == '""' or l[0] == '"No"' : continue
      if l[5] in ('"웹공격"', '"접근제어(차단URL)"', '"SQL삽입차단"', '"버퍼오버플로우(쉘코드)"', '"XSS"') :
        (key, sigid) = self.parsing_method_1(l)
      elif l[5] in ('"디렉토리리스팅"') :
        (key, sigid) = self.parsing_method_2(l)
      elif l[5] in ('"블랙리스트(IP)"', '"과다요청제어(URL)"', '"과다요청제어(세션)"') :
        (key, sigid) = self.parsing_method_3(l)
      elif l[5] in ('"요청형식검사(메소드)"') :
        (key, sigid) = self.parsing_method_4(l)
      else :
        break

      #print key, sigid #, l[8], etc
      if sigid not in _WAP :
        _WAP[sigid] = {}

      _WAP[sigid][key] = line

    fp.close()
    if len(_WAP) == 0 : return

    # report
    fp = open(txtfile, 'w', encoding='utf-8')
    for sigid in _WAP.keys() :
      fp.write( "%s %d\n" % (self.parse_sigid(sigid), len(_WAP[sigid])) )
    fp.close()

  def parse_sigid(self, n) :
    cat = n[:4]
    sigid = n[4:]
    if cat == "1115" : cat = "WAP-"
    elif cat == "1107" : cat = "XSS-"
    elif cat == "1106" : cat = "SQL-"
    elif cat == "1105" : cat = "BOF-"
    elif cat == "1101" : cat = "ACC-"
    return cat + sigid

  def write_WAF_to_file(self) :
    path = r'./categorized_csv'
    if not os.path.isdir(path) :
      os.mkdir(path)
    waname_files = []
    for wa_name in self.WAFarray.keys() :
      filename = path + "/wf_" + wa_name + ".csv"
      waname_files.append(filename)
      fp = open(filename, 'w', encoding='utf-8')
      for timeline in self.WAFarray[wa_name] :
        fp.write(self.WAFarray[wa_name][timeline])
      fp.close()
    return waname_files

  def csv_to_WAF_array(self, csvfile):
    fp = open(csvfile, 'r', encoding='utf-8')
    #print ('loading %s on Memory ' % (csvfile))
    first_time = ''
    until_time = ''

    for line in fp.readlines() :
      l = line[:-1].split(',')
      if l[0] == '""' or l[0] == '"No"' : continue
      # "No","시간","장비","애플리케이션","도메인","공격명","서버","클라이언트","차단여부","증거ID","로그ID","애플리케이션ID","입력인터페이스","URL","URL인수","데이터","기타"
      key = (l[1]+'.'+l[0]).replace('"','')
      if until_time == '' :
        until_time = l[1]
      try:
        wa_name = l[5].replace('"','')
      except:
        print("Parse Error: " + line)
        continue

      if wa_name not in self.WAFarray :
          self.WAFarray[wa_name] = {}

      self.WAFarray[wa_name][key] = line
      first_time = l[1]

    print("%s ~ %s" % (first_time, until_time))

  def html_to_csv_file(self, html_filename):
    input_dir = r"./raw_datas/"
    output_dir = r"./csv_datas/"
    if not os.path.isdir(output_dir):
      os.mkdir(output_dir)
    output_filename = os.path.splitext(html_filename)[0]+'.csv'
    print ('%s to %s ... processing' % (html_filename, output_filename))

    if os.path.isfile( output_dir + output_filename) :
      return  output_dir + output_filename

    parser = html2csv()
    htmlfile = open(input_dir + html_filename, 'r', encoding='utf-8', errors="ignore") #, 'rb')
    csvfile = open( output_dir + output_filename, 'w', encoding='utf-8') #, 'w+b')
    data = htmlfile.read(8192)
    while data:
      parser.feed( data )
      csvfile.write( parser.getCSV() )
      #sys.stdout.write('%d CSV rows written.\r' % parser.rowCount)
      #try:
      data = htmlfile.read(8192)
      #except:
      #  print("Error on reading : %s / %s" % (html_filename, data))

    csvfile.write( parser.getCSV(True) )
    csvfile.close()
    htmlfile.close()

    return  output_dir + output_filename

  def login_av2(self):
    base_url = 'https://' + self.txt_ipaddr.text()

    login_url = base_url + '/index.php?mode=in&url='
    login_values = { 'id' : self.txt_username.text(), 'password' : self.txt_passwd.text() }

    data = urllib.parse.urlencode(login_values)
    data = data.encode('utf-8') # data should be bytes
    req = urllib.request.Request(login_url, data)
    response = urllib.request.urlopen(req, context=ssl._create_unverified_context())
    return response.headers.get('Set-Cookie')

  def prepare_downloading(self):
    if not os.path.isdir(r".\raw_datas"):
      os.mkdir("raw_datas")
    try:
      _sdate = self.txt_sdate.text().replace("-", "")
      _edate = self.txt_edate.text().replace("-", "")

      if _sdate[:4] != _edate[:4] :
        self.popAlert(u'해가 다른 자료는 가져올 수 없습니다.')
        return False
      if _sdate[4:6] != _edate[4:6] :
        self.popAlert(u'다른 달은 가져올 수 없습니다.')
        return False
      if int(_sdate[6:8]) > int(_edate[6:8]) :
        self.popAlert(u'날짜를 올바르게 입력해야 합니다.')
        return False
      return True
    except:
      return False

  def prepare_converting(self):
    if not os.path.isdir(r".\conv_datas"):
      os.mkdir("conv_datas")

  def cancel(self) :
    self.enableUIset()

# end of MainWindow class

def main() :
  app = QtGui.QApplication(sys.argv)
  thisapp = MainWindow()
  sys.exit(app.exec_())

if __name__ == '__main__' :
  main()