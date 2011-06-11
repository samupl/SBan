#!/usr/bin/env python

#  ----------------------------------------------------------
#  
#   SBan v 0.1
#   Author: samu (s@samu.pl)
#           irc: #main @ irc.pirc.pl
#
#  Licence:
#           Creative Commons Uznanie autorstwa 3.0 Polska
#           http://creativecommons.org/licenses/by/3.0/pl/
#
#  ----------------------------------------------------------
#
#  This is my version of automated log parsing and banning 
#  script. It does mostly the same as familiar fail2ban
#  script, but has some major advantages.
#
#  It uses a separate rules file, in which you can declare
#  the file, the regexp, the time (count) settings, and the
#  command used to ban the IP, person, or whatever.
#
#  You can read more about the rules file in the sample
#  rules file, sban-rules.example.conf
# 
#  You can change the location of the rules file by changing 
#  the _rulesfile variable below
#

_rulesfile = "/usr/local/etc/sban-rules.conf"

#
#  The script is still at developement, so any suggestions
#  and bug commisions will be appreciated.
#

# -- Do not edit anything below -- #
_ver = "0.1"

import ConfigParser
import time
import os
import re
import datetime
from threading import Thread

# Reading the config gile using ConfigParser
_config = ConfigParser.RawConfigParser()
_config.read(_rulesfile)

# Saving some commonly used config variables, so that they won't have to be parsed again in the future
_clist = {}
_csections = _config.sections()

def allConfigIsInList(_list, _lname):
	_return = 1
	for _directive in ['file', 'regexp', 'time', 'command', 'ucommand']:
		if not _directive in _list:
			print "ERROR: No '"+_directive+"' directive specified in '"+_lname+"' section"
			_return = 0
		
	return _return
	
for _section in _csections:
	_tlist = []
	for _element in _config.items(_section):
		_tlist.append(_element[0])
		_clist[_section] = _tlist
	
print datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")+" SBan "+_ver+" started."

_error = 0
for _element in _clist:
	if not allConfigIsInList(_clist[_element], _element):
		_error = 1
		
if _error == 1:
	print datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")+ "NOTICE: There were some errors while reading your configuration file - sban is terminating."
	exit

class testit(Thread):
	def __init__ (self, _name, _file, _regexp, _time, _command, _ucommand):
		Thread.__init__(self)
		self._name = _name
		self._file = _file
		self._regexp = _regexp
		self._time = _time
		self._command = _command
		self._ucommand = _ucommand
	
	def run(self):
		pingaling = current = parsefile(self._name, self._file, self._regexp, self._time, self._command, self._ucommand)
		self.status = pingaling


# The actual parsing
def parsefile (_name, _file, _regexp, _time, _command, _ucommand):
	_banned = {}
	filename = _file
	file = open(filename,'r')
	st_results = os.stat(filename)
	st_size = st_results[6]
	file.seek(st_size)
	_lact = {}
	_trigger = {}
	_count = {}
	_time = _time.rsplit(" ")
	while 1:
		where = file.tell()
		line = file.readline()
		if not line:
			time.sleep(1)
			file.seek(where)
			_blist = []
			if _time[2] != 0:
				for _bname in _banned:
					if int(time.time()) - int(_banned[_bname]) >= int(_time[2]):
						print datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")+" Unanning in section ["+_name+"] using command: "+_ucommand.replace("%s", _bname)
						os.system(_ucommand.replace("%s", _bname))
						_blist.append(_bname)
						
				for _belem in _blist:
					del _banned[_belem]
		else:
			if re.search(_regexp, line):
				_match = re.search(_regexp, line)
				if not _match.group(1) in _trigger:
					_trigger[_match.group(1)] = 0
				if not _match.group(1) in _count:
					_count[_match.group(1)] = 0	
				if not _match.group(1) in _lact:
					_lact[_match.group(1)] = 0	
				if _trigger[_match.group(1)] == 0:
					_trigger[_match.group(1)] = 1
					_count[_match.group(1)] = _count[_match.group(1)] + 1
					_lact[_match.group(1)] = int(time.time())
				else:
					_cur = int(time.time()) - _lact[_match.group(1)]
					if int(_cur) <= int(_time[1]):
						_count[_match.group(1)] = _count[_match.group(1)] + 1
					else:
						_count[_match.group(1)] = 1
						_trigger[_match.group(1)] = 0
				if int(_count[_match.group(1)]) == int(_time[0]):
					_banned[_match.group(1)] = int(time.time())
					print datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")+" Banning in section ["+_name+"] using command: "+_command.replace("%s", _match.group(1))
					os.system(_command.replace("%s", _match.group(1)))
	
_chklist = []	
for _section in _csections:
	current = testit(_section, _config.get(_section, 'file'), _config.get(_section, 'regexp'), _config.get(_section, 'time'), _config.get(_section, 'command'), _config.get(_section, 'ucommand'))
	_chklist.append(current)
	current.start()
