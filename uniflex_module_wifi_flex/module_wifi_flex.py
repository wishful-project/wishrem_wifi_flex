import logging
import datetime
import time
import os
import signal
import random

from uniflex.core import modules
import uniflex_module_wifi
from uniflex_module_net_linux import NetworkModule
from uniflex.core import events
from uniflex.core import exceptions
from pyric import pyw # for iw functionality
from pyric.utils.channels import rf2ch
from pyric.utils.channels import ch2rf
from uniflex.core.timer import TimerEventSender

from .pyw_extension import phyinfo as pywe_phyinfo, survey as pywe_survey
from .wifi_pkt_sniffer import PacketSnifferPyShark, WiFiRssiSink
from .ap_daemons import ap_daemons
from rem_events.sensing_events import *

__author__ = "Daniel Denkovski"
__copyright__ = "Copyright (c) 2017, Faculty of Electrical Engineering and Information Technologies, UKIM, Skopje, Macedonia"
__version__ = "0.1.0"
__email__ = "{danield}@feit.ukim.edu.mk"

'''
WiFi Flex Module 
An extension of the uniflex WiFi module with additional functionalities regarding the WISH-I-VE-A-REM extension
Enables generic WiFi devices to work in monitor (sensing, sweeping mode), AP or station mode of operation
Provides control of PHY layer parameters, reporting sensing data and communication performances
'''

class WifiModuleFlex(uniflex_module_wifi.WifiModule):
	def __init__(self, mode, ipaddr, dnsserv, country):
		'''
		Initialization of the WiFi flex module
		Args:
			All arguments read from yaml configuration file.
			mode: start mode of operation (AP, station or monitor)
			ipaddr: IP address of WiFi device in AP mode
			dnsserv: IP address of used DNS server
			country: country code for regulation (e.g. DE)
		'''
		super(WifiModuleFlex, self).__init__()
		self.log = logging.getLogger('WifiModuleFlex')
		self._startmode = mode
		self._ipaddr = ipaddr
		self._dnsserv = dnsserv
		self._country = country
		self._moniface = None
		self._maniface = None
		self._w0 = None
		self._macad = None
		self._monchannels = None
		self._ap_capabilities = None
		self._timeInterval = 0.1
		self._current_chInd = 0
		self._packetSniffer = None
		self._csa = False
		self._wmode = None
		self._rssi_results = {}
		self._coninfo = {}
		self._apconfig = {}
		self.timer = None
		self._daemons = None

	def add_all_ifaces(self):
		'''
		Adds all required WiFi interfaces (monitor and managed) for the controlled WiFi physical device.
			>> self._maniface is the managed interface
			>> self._moniface is the monitor interface
		'''
		ifaces = self.get_interfaces()
		for ifs in ifaces:
			dinfo = pyw.devinfo(ifs)
			if (dinfo['mode'] == 'monitor'):
				self._moniface = dinfo['card'].dev
			elif (dinfo['mode'] in ['managed', 'AP']):
				self._maniface = dinfo['card'].dev

		if (not self._moniface and 'monitor' in pyw.devmodes(self._w0)):
			self._moniface = 'mon-' + self.phyName
			if not self._moniface in pyw.winterfaces():
				self._moniface = pyw.devadd(self._w0, self._moniface, 'monitor').dev
	
		if (not self._maniface and ('managed' in pyw.devmodes(self._w0) or 'AP' in pyw.devmodes(self._w0))):
			self._maniface = 'man-' + self.phyName
			if not self._maniface in pyw.winterfaces():
				self._maniface = pyw.devadd(self._w0, self._maniface, 'managed').dev

	def set_all_ifaces_down(self):
		'''
		Turns down all active interfaces for the controlled WiFi physical device
		'''
		ifaces = self.get_interfaces()
		for ifs in ifaces:
			self.set_interface_down(ifs)

	def get_supported_monitor_channels(self):
		'''
		Utilizes the Pyric extension module for collecting information regarding the channels that can be used for monitoring.
		Available monitor channels are stored in the array self._monchannels.
			>> example: self._monchannels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
		'''
		stds = pyw.devstds(self._w0)
		rfs = pywe_phyinfo(self._w0)['bands']
		self._monchannels = []
		for d in rfs:
			if (d == '5GHz'):
				self._csa = True
			for chsettings in rfs[d]['rf-data']:
				if chsettings['enabled']: self._monchannels.append(chsettings['channel'])

	def get_ap_capabilities(self):
		'''
		Utilizes the Pyric extension module for collecting information regarding the access point capabilities.
		Saves the AP capabilities in the self._ap_capabilities dictionary.
			>> example: self._ap_capabilities = {1: {'max-tx': 20.0, 'stds': ['b','g','n'], 'ht-capab': '[HT20]'}}
		'''
		stds = pyw.devstds(self._w0)
		rfs = pywe_phyinfo(self._w0)['bands']
		self._ap_capabilities = {}
		self._monchannels = []
		for d in rfs:
			if (d == '5GHz'):
				self._csa = True
			for chsettings in rfs[d]['rf-data']:
				if chsettings['enabled']:
					chind = chsettings['channel']
					self._monchannels.append(chind)
					if not chsettings['no-IR']:
						self._ap_capabilities[chind] = {}
						self._ap_capabilities[chind]['max-tx'] = chsettings['max-tx']
						self._ap_capabilities[chind]['ht-capab'] = rfs[d]['ht-capab']
						if '[HT40]' in self._ap_capabilities[chind]['ht-capab']:
							str_cap = self._ap_capabilities[chind]['ht-capab']
							self._ap_capabilities[chind]['ht-capab'] = str_cap.replace('[HT40]', '') # for now
						if (chind >= 1 and chind <= 14):
							stdarr = []
							if ('b' in stds): stdarr.append('b')
							if ('g' in stds): stdarr.append('g')
							if ('n' in stds): stdarr.append('n')
							self._ap_capabilities[chind]['stds'] = stdarr
						elif (chind >= 34 and chind <= 161):
							stdarr = []
							if ('a' in stds): stdarr.append('a')
							if ('n' in stds): stdarr.append('n')
							self._ap_capabilities[chind]['stds'] = stdarr
					#if self._csa: self._capabilities['csa'] = 1
					#else: self._capabilities['csa'] = 0
		return self._ap_capabilities

	def get_duty_cycle(self, iface):
		'''
		Utilizes the Pyric extension module for collecting the duty cycle values for a given channel at a specific interface. 
		Comment: Currently not used.
		Args:
			iface: the interface to use
		Returns:
			duty cycle value (channel busy time/channel active time)
		'''
		#self.log.info("WIFI Module Flex get duty cycle: %s" % str(iface))
		res = None
		try:
			survey_data = pywe_survey(self._w0)
			if survey_data['in_use']:
				res = float(survey_data['channel_time_busy'])/float(survey_data['channel_time'])
		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
		return res

	def get_duty_cycle_old(self, iface):
		'''
		Utilizes the "iw survey dump" command for collecting the duty cycle values for a given channel from a specified interface.
		Args:
			iface: the interface to use
		Returns:
			duty cycle value (channel busy time/channel active time)
		'''
		#self.log.info("WIFI Module Flex get duty cycle: %s" % str(iface))
		res = None
		try:
			[rcode, sout, serr] = self.run_command('iw dev ' + iface + ' survey dump')

			busy_time = 0;
			active_time = 1;
			sout_arr = sout.split("\n")
			in_use = False

			for line in sout_arr:
				s = line.strip()
				if "frequency" in s: 
					if "[in use]" in s: in_use = True
					else: in_use = False
				
				if in_use:
					if "Survey" in s:
						continue
					if "channel active time" in s:
						arr = s.split()
						active_time = arr[3].strip()
					elif "extension channel busy time" in s:
						continue
					elif "channel busy time" in s:
						arr = s.split()
						busy_time = arr[3].strip()
			res = float(busy_time)/float(active_time)

		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
		return res

	def process_rssi_data(self, ta, rssi, chnel):
		'''
		Implements a max hold algorithm for the RSSI gathering process.
		Stores the max hold values in the dictionary self._rssi_results
			>> example: self._rssi_results[1]['00:00:00:00:00:00'] = -45
		Args:
			ta: transmitting MAC address
			rssi: RSSI value sensed from the transmiter
			chnel: channel the packet was received on
		'''
		self.log.debug("RSSI sample: TA: {}, value: {}, channel: {}".format(ta, rssi, chnel))
		if chnel in self._rssi_results: 
			if ta in self._rssi_results[chnel]:
				if (self._rssi_results[chnel][ta] < rssi):
					self._rssi_results[chnel][ta] = rssi
			else: 
				self._rssi_results[chnel][ta] = rssi

	def rssi_service_start(self, iface):
		'''
		Starts the RSSI sensing process on an interface (iface) using the PyShark module
		'''
		self._rssiServiceRunning = True
		#iface = self._moniface

		if not self._packetSniffer:
			self._packetSniffer = PacketSnifferPyShark(iface=iface)
			self._packetSniffer.start()

		self.rssiSink = WiFiRssiSink(callback=self.process_rssi_data)
		self._packetSniffer.add_sink(self.rssiSink)

	def rssi_service_stop(self):
		'''
		Stops the RSSI sensing process
		'''
		self._rssiServiceRunning = False
		try:
			self._packetSniffer.stop()
			del self._packetSniffer
		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

	def configure_ap(self, config):
		'''
		Utilizes the hostapd daemon and Pyric extension to configure the WiFi device in access point mode of operation. 
		I also activates a dnsmasq daemon to configure a simple DNS and DHCP server.
		If Channel Switch Announcement is supported hostap_cli is used to change a configuration of an active AP.
		Sends a WiFiConfigureAPRsp event at configuration success.
		Args:
			config dictionary containing keys 'channel', 'power', 'ssid', 'ht_capab', 'hw_mode' 
			>> example config = {'channel': 1, 'power': 20, 'ssid': 'SMARTAP', 'ht_capab': '[HT20]', 'hw_mode': 'g'}
		'''
		self.log.info("Starting WiFi AP...")
		if (self._wmode == 'AP' and self._csa):
			kwargs = {}
			kwargs["control_socket_path"] = self._daemons.get_hostap_interface()
			if config['channel']:
				self.set_channel(config['channel'], self._maniface, **kwargs)
			if config['power']:
				self.set_tx_power(int(config['power']), self._maniface)
			self._apconfig['channel'] = config['channel']
			self._apconfig['power'] = config['power']

			if self.is_connected(self._maniface):
				apconnEvent = WiFiConfigureAPRsp(self._macad, self._apconfig)
				self.send_event(apconnEvent)
			else:
				self.configure_monitor()
				self.log.error("AP setup failed")
		else:
			self.stop_mode()
			if (self._maniface and 'AP' in pyw.devmodes(self._w0) and None not in [config['hw_mode'], config['channel'], config['ssid']]):
				chint = int(config['channel'])
				if chint in self._ap_capabilities:
					self._daemons.start_dnsmasq()
					if config['ht_capab'] is None:
						config['ht_capab'] = self._ap_capabilities[chint]['ht-capab']
					self._daemons.start_hostapd(config)

					self._wmode = 'AP'
					self._timeInterval = 1
					self.timer.start(self._timeInterval)

					if config['power']:
						self.set_tx_power(int(config['power']), self._maniface)

					self._apconfig['ssid'] = config['ssid']
					self._apconfig['channel'] = config['channel']
					self._apconfig['power'] = config['power']
					self._apconfig['hw_mode'] = config['hw_mode']

				if self.is_connected(self._maniface):
					apconnEvent = WiFiConfigureAPRsp(self._macad, self._apconfig)
					self.send_event(apconnEvent)
					self.rssi_service_start(self._maniface)
				else:
					self.configure_monitor()
					self.log.error("AP setup failed")
				
			else:
				self.log.error("Interface {} not found".format(self._maniface))
				raise exceptions.UniFlexException(msg='AP interface missing')

	def stop_ap(self):
		'''
		Stops the access point hostapd and dnsmasq daemon services and turns down the all interfaces
		'''
		self.log.info("Stop WiFi AP")
		self._daemons.stop_hostapd()
		self._daemons.stop_dnsmasq()
		self.rssi_service_stop()
		self._rssi_results = {}
		self.set_all_ifaces_down()

	def configure_monitor(self):
		'''
		Configures the WiFi device in monitor mode of operation (sweeping through available WiFi channels).
		Starts a timer event to report RSSI and duty cycle values from monitored channels.
		Sends a WiFiConfigureMonitorRsp event at configuration sucess.
		'''
		self.log.info("Starting WiFi monitor...")
		self.stop_mode()
		if self._moniface:
			if not self.is_interface_up(self._moniface):
				self.set_all_ifaces_down()
				self.set_interface_up(self._moniface)
			self.log.info("Started interface {} on device {}".format(self._moniface, self.phyName))

			#self.get_supported_monitor_channels() # already got monitor channels using self.get_ap_capabilities()
			for chan in self._monchannels:
				self._rssi_results[chan] = {}

			self.rssi_service_start(self._moniface)
			self.set_channel(self._monchannels[self._current_chInd], self._moniface)
			self._wmode = 'monitor'
			self._timeInterval = 0.1
			self.timer.start(self._timeInterval)
			configuredMonitorEvent = WiFiConfigureMonitorRsp(self._macad)
			self.send_event(configuredMonitorEvent)
		else:
			self.log.error("Interface {} not successfully started".format(self._moniface))
			raise exceptions.UniFlexException(msg='Monitor interface failed')

	def stop_monitor(self):
		'''
		Stops the monitor mode of operation and turns down all interfaces.
		Turns down the rssi service as well, and clears the self._rssi_results dictionary.
		'''
		self.log.info("Stopped WiFi monitor")
		self.rssi_service_stop()
		self._rssi_results = {}
		self.set_all_ifaces_down()

	def connect_to_network(self, iface, ssid, bssid = None, chnel = None):
		'''
		Triggers the WiFi device to connect to a given access point based on the ssid, bssid and channel of interest.
		Args:
			iface: the interface to use
			ssid: ssid to connect to
			bssid: MAC address of the access point we want to connect to
			chnel: where to search the active access point (to speed up the connection time)
		'''
		self.log.info('Connecting via to AP with SSID with mac and channel: %s->%s, %s, %s' % (str(iface), str(ssid), str(bssid), str(chnel)))
		cmd_str = 'sudo iwconfig ' + iface + ' essid ' + str(ssid)

		if bssid:
			cmd_str += ' ap ' + bssid
		if chnel:
			cmd_str += ' channel ' + str(chnel)

		try:
			self.run_command(cmd_str)
		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

		return True

	def configure_managed(self, config):
		'''
		Triggers the WiFi device to (re)configure its communication parameters and connect to a given access point.
		Starts the dhclient daemon on the managed interface. Sends a WiFiConfigureStationRsp event at connection success.
		Args:
			config dictionary containing keys 'channel', 'power', 'ssid', 'ap' 
			>> example config = {'channel': 1, 'power': 20, 'ssid': 'SMARTAP', 'ap': '00:00:00:00:00:00'}
		'''
		self.log.info("Starting WiFi managed...")
		if (self._wmode == 'station' and self._csa and config['ap'] == self._apconfig['ap']):
			if config['power']:
				self.set_tx_power(int(config['power']), self._maniface)
			self._apconfig['channel'] = config['channel']
			self._apconfig['power'] = config['power']

			if self.is_connected(self._maniface):
				connectionEvent = WiFiConfigureStationRsp(self._macad, config['ap'], self._apconfig)
				self.send_event(connectionEvent)
			else:
				self.configure_monitor()
				self.log.error("AP setup failed")
		else:
			self.stop_mode()
			if (self._maniface and config['ssid']):
				if not self.is_interface_up(self._maniface):
					self.set_all_ifaces_down()
					self.set_interface_up(self._maniface)
				self.log.info("Started interface {} on device {}".format(self._maniface, self.phyName))

				retries = 50
				connectionSuccess = True
				while not self.is_connected(self._maniface):
					if retries <= 0: connectionSuccess = False; break;
					self.connect_to_network(self._maniface, config['ssid'], config['ap'], config['channel'])
					retries -= 1
					time.sleep(0.1)
				
				if (connectionSuccess):
					self._daemons.dhclient_renew()
					self._wmode = 'station'
					self._timeInterval = 1
					self.timer.start(self._timeInterval)

					self._apconfig['ssid'] = config['ssid']
					self._apconfig['ap'] = config['ap']
					self._apconfig['channel'] = config['channel']
					self._apconfig['power'] = config['power']
					connectionEvent = WiFiConfigureStationRsp(self._macad, config['ap'], self._apconfig)
					self.send_event(connectionEvent)
					self.rssi_service_start(self._maniface)
				else:
					self.configure_monitor()
					self.log.error("Connection failed to network {}".format(config['ssid']))
			else:
				self.log.error("Interface {} not successfully started".format(self._maniface))
				raise exceptions.UniFlexException(msg='Managed interface failed')

	def stop_managed(self):
		'''
		Stops the operation of the WiFi device when in station mode and turns down the managed interface. 
		Stops the dhclient daemon.
		'''
		self.log.info("Stopped WiFi managed")
		self._daemons.dhclient_stop()
		self.rssi_service_stop()
		self._rssi_results = {}
		self.set_all_ifaces_down()

	def stop_mode(self):
		'''
		Stops the operation of the WiFi device irrespective of the mode of operation.
		'''
		if (self._wmode == 'monitor'):
			self.stop_monitor()
		elif (self._wmode == 'AP'):
			self.stop_ap()
		elif (self._wmode == 'station'):
			self.stop_managed()
		self._wmode = None
		self._apconfig = {}

	def get_macaddr(self):
		'''
		Gets the MAC address of the WiFi physical device.
		'''
		return self._macad

	def change_country(self, country):
		'''
		Changes regulatory domain based on the country argument (e.g. DE)
		'''
		self.log.info('Changing country to %s' % str(country))
		try:
			cmd_str = 'sudo iw reg set ' + country
			self.run_command(cmd_str)
		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
		return True

	@modules.on_event(PeriodicEvaluationTimeEvent)
	def periodic_evaluation(self, event):
		'''
		Periodically reports information to the node controller triggered by the PeriodicEvaluationTimeEvent. 
		The function checks the device mode and performs the actions accordingly. 
		If the WiFi device is configured in monitor mode, it sweeps channels and reports the RSSI and duty cycle measurements. 
		If the WiFi device is configured as an access point or station it additionally reports the link and AP statistics. 
		'''
		node = self.localNode
		if (node.uuid == event.srcNode.uuid):
			if (self._wmode == 'monitor'):
				next_channel_idx = (self._current_chInd + 1) % len(self._monchannels)
				duty_cycle = self.get_duty_cycle_old(self._moniface)
				if duty_cycle is not None:
					curr_chNo = self._monchannels[self._current_chInd]
					self.log.info("Duty cycle at channel %d: %.2f%%" % (curr_chNo, duty_cycle*100))
					sampleEvent = WiFiDutyCycleSampleEvent(self._macad, duty_cycle, curr_chNo)
					self.send_event(sampleEvent)

				next_chNo = self._monchannels[next_channel_idx]

				#send results for next channel
				#self.log.info("Results for channel %d:" % next_chNo)
				for taddr in self._rssi_results[next_chNo]:
					sampleEvent = WiFiRssiSampleEvent(self._macad, taddr, self._rssi_results[next_chNo][taddr], next_chNo)
					self.send_event(sampleEvent)

				self._rssi_results[next_chNo] = {}
				self.set_channel(next_chNo, self._moniface)
				self._current_chInd = next_channel_idx
				self.timer.start(self._timeInterval)

			elif (self._wmode in ['AP', 'station']):
				if self.is_connected(self._maniface):
					#if not self._apconfig['channel']:
					self._apconfig['channel'] = self.get_channel(self._maniface)
					#if not self._apconfig['power']:
					self._apconfig['power'] = self.get_tx_power(self._maniface)
					used_ch = self._apconfig['channel'] #self.get_channel(self._maniface)
					duty_cycle = self.get_duty_cycle_old(self._maniface)
					if duty_cycle and used_ch:
						self.log.info("Duty cycle at channel %d: %.2f%%" % (used_ch, duty_cycle*100))
						sampleEvent = WiFiDutyCycleSampleEvent(self._macad, duty_cycle, used_ch)
						self.send_event(sampleEvent)
					cdev_info = self.get_info_of_connected_devices(self._maniface)
					#print(cdev_info)
					total_tx_packs = 0; total_tx_retries = 0; total_tx_failed = 0; 
					total_tx_prc_retries = 0.0; total_tx_prc_failed = 0.0; total_tx_thrput = 0.0; total_rx_thrput = 0.0;
					total_tx_time_prc = 0.0; total_rx_time_prc = 0.0;
					all_stations = []

					for taddr in cdev_info:		
						sta_rssi = 0.0; tx_packs = 0; tx_retries = 0; tx_failed = 0;
						tx_prc_retries = 0.0; tx_prc_failed = 0.0; tx_thrput = 0.0; rx_thrput = 0.0; exp_thrput = None;
						tx_time_prc = 0.0; rx_time_prc = 0.0;
						tx_bitrate = 0.0; rx_bitrate = 0.0;
						all_stations.append(taddr)

						if 'signal' in cdev_info[taddr]:
							sta_rssi = float(cdev_info[taddr]['signal'][0])
							sampleEvent = WiFiRssiSampleEvent(self._macad, taddr, sta_rssi, used_ch)
							self.send_event(sampleEvent)

						prev_pkts = 0; prev_retries = 0; prev_failed = 0; prev_txbytes = 0; prev_rxbytes = 0

						if taddr in self._coninfo:
							if 'tx packets' in cdev_info[taddr]:						
								prev_pkts = int(self._coninfo[taddr]['tx packets'][0])
							if 'tx retries' in cdev_info[taddr]:
								prev_retries = int(self._coninfo[taddr]['tx retries'][0])
							if 'tx failed' in cdev_info[taddr]:
								prev_failed = int(self._coninfo[taddr]['tx failed'][0])
							if 'tx bytes' in cdev_info[taddr]:
								prev_txbytes = int(self._coninfo[taddr]['tx bytes'][0])
							if 'rx bytes' in cdev_info[taddr]:
								prev_rxbytes = int(self._coninfo[taddr]['rx bytes'][0])

						if 'tx packets' in cdev_info[taddr]:
							curr_pkts = int(cdev_info[taddr]['tx packets'][0])
							tx_packs = curr_pkts - prev_pkts
							if tx_packs < 0: tx_packs = curr_pkts
							if 'tx retries' in cdev_info[taddr]:
								curr_retries = int(cdev_info[taddr]['tx retries'][0])
								tx_retries = curr_retries - prev_retries
								if tx_retries < 0: tx_retries = curr_retries
								if tx_packs > 0: tx_prc_retries = float(tx_retries/(tx_packs + tx_retries))
							if 'tx failed' in cdev_info[taddr]:
								curr_failed = int(cdev_info[taddr]['tx failed'][0])
								tx_failed = curr_failed - prev_failed
								if tx_failed < 0: tx_failed = curr_failed
								if tx_packs > 0: tx_prc_failed = float(tx_failed/tx_packs)

						if 'tx bitrate' in cdev_info[taddr]:
							tx_bitrate = float(cdev_info[taddr]['tx bitrate'][0])*1000000

						if 'rx bitrate' in cdev_info[taddr]:
							rx_bitrate = float(cdev_info[taddr]['rx bitrate'][0])*1000000

						if 'tx bytes' in cdev_info[taddr]:
							curr_txbytes = int(cdev_info[taddr]['tx bytes'][0])
							tx_bytes = curr_txbytes - prev_txbytes
							if tx_bytes < 0: tx_bytes = curr_txbytes
							tx_thrput = float(tx_bytes/self._timeInterval*8)
							if tx_bitrate > 0:
								tx_time_prc = tx_thrput/tx_bitrate

						if 'rx bytes' in cdev_info[taddr]:
							curr_rxbytes = int(cdev_info[taddr]['rx bytes'][0])
							rx_bytes = curr_rxbytes - prev_rxbytes
							if rx_bytes < 0: rx_bytes = curr_rxbytes
							rx_thrput = float(rx_bytes/self._timeInterval*8)
							if rx_bitrate > 0:
								rx_time_prc = rx_thrput/rx_bitrate

						if 'expected throughput' in cdev_info[taddr]:
							exp_thrput = cdev_info[taddr]['expected throughput'][0]

						total_tx_packs += tx_packs
						total_tx_retries += tx_retries
						total_tx_failed += tx_failed
						total_tx_thrput += tx_thrput
						total_rx_thrput += rx_thrput
						total_tx_time_prc += tx_time_prc
						total_rx_time_prc += rx_time_prc

						self.log.info("%s->%s link statistics:\n\tRSSI: %.0fdBm \n\ttx packet retries: %.2f%% \n\ttx packet fails: %.2f%% \n\ttx bitrate: %.2fMbps \n\trx bitrate: %.2fMbps \n\tachieved tx throughput: %.2fMbps \n\tachieved rx throughput: %.2fMbps \n\ttx activity: %.2f%% \n\trx activity: %.2f%%" % (self._macad, taddr, sta_rssi, tx_prc_retries*100, tx_prc_failed*100, tx_bitrate/1000000, rx_bitrate/1000000, tx_thrput/1000000, rx_thrput/1000000, tx_time_prc*100, rx_time_prc*100))

						wifistatsEvent = WiFiLinkStatistics(self._macad, taddr, sta_rssi, tx_prc_retries, tx_prc_failed, tx_bitrate, rx_bitrate, tx_thrput, rx_thrput, tx_time_prc, rx_time_prc)
						self.send_event(wifistatsEvent)

					if self._wmode == 'AP':
						if total_tx_packs > 0: 
							total_tx_prc_retries = float(total_tx_retries/(total_tx_packs + total_tx_retries))
							total_tx_prc_failed = float(total_tx_failed/total_tx_packs)

						self.log.info("AP (%s) statistics:\n\ttotal tx packet retries: %.2f%% \n\ttotal tx packet fails: %.2f%% \n\tachieved total tx throughput: %.2fMbps \n\tachieved total rx throughput: %.2fMbps \n\ttotal tx activity: %.2f%% \n\ttotal rx activity: %.2f%%" % (self._macad, total_tx_prc_retries*100, total_tx_prc_failed*100, total_tx_thrput/1000000, total_rx_thrput/1000000, total_tx_time_prc*100, total_rx_time_prc*100))

						apstatsEvent = WiFiAPStatistics(self._macad, all_stations, total_tx_prc_retries, total_tx_prc_failed, total_tx_thrput, total_rx_thrput, total_tx_time_prc, total_rx_time_prc)
						self.send_event(apstatsEvent)

					self._coninfo = cdev_info
					self.timer.start(self._timeInterval)

				else: self.configure_monitor()

	def get_ht40allow_map(self):
		'''
		Returns the available HT40 modes of operation for each channel, regarding the extension channel possibilities. 
		E.g. on the left (i.e. [HT40-]) and/or right (i.e. [HT40+])
		Returns:
			ht40map: dictionary, e.g. ht40map = {1: '[HT40+]', 5: '[HT40-][HT40+]'}
		'''
		self.log.info("Get HT40 allow Map")
		ht40map = None
		try:
			cmd_str = "sudo cat /sys/kernel/debug/ieee80211/" + self.phyName + "/ht40allow_map"
			[rcode, sout, serr] = self.run_command(cmd_str)
			sout_arr = sout.split("\n")
			ht40map = {}

			for line in sout_arr:
				s = line.strip()
				str_list = s.split(' ')
				if len(str_list) >= 3:
					str_list = [x for x in str_list if x]
					freq = int(str_list[0])
					if str_list[1] == 'HT40':
						channel = rf2ch(freq)
						if str_list[2] == '+':
							ht40map[channel] = '[HT40+]'
						if str_list[2] == '-+':
							ht40map[channel] = '[HT40-][HT40+]'
						if str_list[2] == '-':
							ht40map[channel] = '[HT40-]'
					elif str_list[1] == 'Disabled':
						continue;
		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
			return None

		return ht40map

	@modules.on_start()
	def my_start_function(self):
		'''
		Starts the WiFi physical device in the given mode of operation that was selected in the configuration yaml file.
		Gets mac address, sets regulatory domain, gets AP capabilities and supported monitor channels, adds interfaces. 
		'''
		self.log.info("Starting WiFi device...")
		try:
			super(WifiModuleFlex, self).my_start_function()
			self.set_all_ifaces_down()
			ifaces = self.get_interfaces()
			iface = ifaces[0]
			self._w0 = pyw.getcard(iface)
			self._macad = pyw.macget(self._w0)
			pyw.regset(self._country)
			self.change_country(self._country) #just in case
			self.log.info("Regulatory domain set to {}".format(pyw.regget()))
			self.get_ap_capabilities()
			print(self._ap_capabilities)
			self.get_supported_monitor_channels()
			self.add_all_ifaces()
			self._daemons = ap_daemons(self._maniface, self._macad, self._ipaddr, self._dnsserv, self._country)
			self._daemons.stop_network_manager()
			self.timer = TimerEventSender(self, PeriodicEvaluationTimeEvent)
			print(self.get_ht40allow_map())

			if (self._startmode == 'monitor'):
				self.configure_monitor()
			elif (self._startmode == 'AP'):
				config = {}
				channel = random.choice(list(self._ap_capabilities.keys()))
				ch_caps = self._ap_capabilities[channel]
				if 'g' in ch_caps['stds']:
					config['hw_mode'] = 'g'
				else:
					config['hw_mode'] = 'a'
				config['channel'] = channel
				config['ht_capab'] = ch_caps['ht-capab']
				config['ssid'] = 'SMARTAP'
				config['power'] = ch_caps['max-tx'] #set to max from channels
				self.configure_ap(config)
			elif (self._startmode == 'station'):
				config = {}
				config['ssid'] = 'SMARTAP'
				config['ap'] = None
				config['channel'] = None
				config['power'] = None
				self.configure_managed(config)
			
		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))		

	@modules.on_exit()
	def my_stop_function(self):
		'''
		Stops the WiFi device. 
		'''
		self.log.info("Stop WiFi Flex device")
		self.stop_mode()
		if self.timer is not None: self.timer.cancel()

	#@modules.on_event(WiFiRssiSampleEvent)
	def serve_rssi_sample_event(self, event):
		'''
		Handles WiFiRssiSampleEvent. For debuging purposes only.
		'''
		devName = None
		if event.device:
			devName = event.device.name
		self.log.info("RSSI: RA: {}, TA: {}, value: {}, channel: {}".format(event.ra, event.ta, event.rssi, event.chnel))

	#@modules.on_event(WiFiDutyCycleSampleEvent)
	def serve_duty_cycle_sample_event(self, event):
		'''
		Handles WiFiDutyCycleSampleEvent. For debuging purposes only.
		'''
		devName = None
		if event.device:
			devName = event.device.name
		self.log.info("Duty cycle: RA: {}, value: {}, channel: {}" .format(event.ra, event.dc, event.chnel))

	@modules.on_event(WiFiConfigureAP)
	def serve_configure_ap(self, event):
		'''
		Handles event for WiFi device reconfiguration in access point mode.
		'''
		if (self._macad == event.macaddr):
			config = {}
			config['ssid'] = event.ssid
			config['power'] = event.power
			config['channel'] = event.channel
			config['hw_mode'] = event.hw_mode
			config['ht_capab'] = event.ht_capab
			self.configure_ap(config)

	@modules.on_event(WiFiConfigureStation)
	def serve_configure_station(self, event):
		'''
		Handles event for WiFi device reconfiguration in station mode.
		'''
		if (self._macad == event.macaddr):
			config = {}
			config['ssid'] = event.ssid
			config['ap'] = event.ap
			config['power'] = event.power
			config['channel'] = event.channel
			self.configure_managed(config)

	@modules.on_event(WiFiConfigureMonitor)
	def serve_configure_monitor(self, event):
		'''
		Handles event for device (re)configuration in monitor mode (sweeping sensing mode of operation).
		'''
		if (self._macad == event.macaddr):
			self.configure_monitor()

	@modules.on_event(WiFiStopAll)
	def serve_stop_all(self, event):
		'''
		Handles event to stop any operation of the WiFi device.
		'''
		if (self._macad == event.macaddr):
			self.stop_mode()

	@modules.on_event(WiFiGetCapabilities)
	def serve_get_capabilities(self, event):
		'''
		Pull request for WiFi device capabilities reporting.
		'''
		node = self.localNode
		if (node.uuid == event.receiverUuid):
			try:
				cap_event = WiFiCapabilities(self._macad, self._ap_capabilities)
				self.send_event(cap_event)
			except Exception as e:
				self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

	@modules.on_event(ConnectionTimeoutEvent)
	def serve_connection_timeout(self, event):
		print("ConnectionTimeoutEvent")

