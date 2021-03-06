import os, platform
import sys
from socket import gethostname;
from signal import signal, SIGINT
#import daemon
from pymouse import PyMouse
from pykeyboard import PyKeyboard
import re
import logging
import time
import math
import subprocess
import requests
import random

class Main(object):
	"""docstring for ClassName"""
	def __init__(self):
		super(Main, self).__init__()
		#self.arg = arg
try:
	from pymouse import PyMouseEvent
	
	class event(PyMouseEvent):
		
		def __init__(self):
			super(event, self).__init__()
			FORMAT = '%(asctime)-15s ' + gethostname() + ' touchlogger %(levelname)s %(message)s'
			#logging.basicConfig(filename='\\test', level=logging.DEBUG, format=FORMAT)

		def move(self, x, y):
			pass

		def click(self, x, y, button, press):
			if press:
				if button==2:
					# right click
					detect = Ct_Detector()
					detect.mouse_clicked(x, y, button)
				logging.info('{ "event": "click", "type": "press", "x": "' + str(x) + '", "y": "' + str(y) + '"}') 
			else:
				logging.info('{ "event": "click", "type": "release", "x": "' + str(x) + '", "y": "' + str(y) + '"}') 

except ImportError:
	logging.info('{ "event": "exception", "type": "ImportError", "value": "Mouse events unsupported"}') 
	sys.exit()


	#class IOEvents(PyKeyboardEvent):
	#	def keyboard_types(self):
	#		keystroke = PyKeyboard()
		

class Ct_Analyzer(object):
	"""Analyzer class determines whether to block or alert responsible personnel"""
	def __init__(self, arg):
		super(Ct_Analyzer, self).__init__()
		#self.arg = arg

class Ct_Blocker(object):
	"""Blocker class is responsible to get accurate infomration from the detector and block the operation"""
	def __init__(self, arg):
		super(Ct_Blocker, self).__init__()
		#self.arg = arg

class Ct_Alerter(object):
	"""Alerter class is responsible for getting accurate data from the detector and alert personnel"""
	def __init__(self, arg):
		super(Ct_Alerter, self).__init__()
		#self.arg = arg

class Ct_Manager(object):
	"""The manager class manages incident for further analysis, creating analytic reports"""
	def __init__(self, arg):
		super(Ct_Manager, self).__init__()
		#self.arg = arg

class Ct_Updater(object):
	"""The updater class is responsible for pushing updates"""
	def __init__(self, arg):
		super(Ct_Updater, self).__init__()
		#self.arg = arg		


if __name__ == '__main__':
	#main = Main()
	det = Ct_Detector()
	### Weakly scan
		#scan for large changed in file system

	### Daily scan
		# scan for small changes in daily usage

	### Hourly scan
		# scan for immediate risks
	
	print det.is_other_devices_connected()
	
	### Cron monitor in real-time
		# scan and log externally supplied actions
	#e = event()
	#e.capture = False
	#e.daemon = False
	#e.start()
	