import logging
import datetime
import time
from random import randint
from uniflex.core import modules
from uniflex.core import events
from rem_events.sensing_events import *

__author__ = "Daniel Denkovski"
__copyright__ = "Copyright (c) 2017, Faculty of Electrical Engineering and Information Technologies, UKIM, Skopje, Macedonia"
__version__ = "0.1.0"
__email__ = "{danield}@feit.ukim.edu.mk"

'''
Local controller of WiFi flex device.
sudo uniflex-agent --config config_slave_1.yaml
'''

class WifiFlexLocalController(modules.ControlApplication):
	def __init__(self):
		super(WifiFlexLocalController, self).__init__()
		self.log = logging.getLogger('WifiFlexLocalController')
		self._mydev = None
		self.running = False

	@modules.on_start()
	def my_start_function(self):
		self.log.info("start local wifi flex controller")
		self.running = True

		try:
			node = self.localNode
			device = node.get_device(0)
			if device:
				self._mydev = device

			while (not self._mydev.get_macaddr()): {}

			for dev in node.get_devices():
				print("Dev: ", dev.name)

			for m in node.get_modules():
				print("Module: ", m.name)

			for apps in node.get_control_applications():
				print("App: ", apps.name)

		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

		self.log.info('... done')

	@modules.on_exit()
	def my_stop_function(self):
		self.log.info("stop local wifi flex controller")
		self.running = False

