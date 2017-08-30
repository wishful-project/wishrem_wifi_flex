import logging
import datetime
import os
import signal
import subprocess

__author__ = "Daniel Denkovski"
__copyright__ = "Copyright (c) 2017, Faculty of Electrical Engineering and Information Technologies, UKIM, Skopje, Macedonia"
__version__ = "0.1.0"
__email__ = "{danield}@feit.ukim.edu.mk"

'''
ap_daemons class
Controlling the daemon processes used for automation of (re)configuration and communication of the WiFi devices.
'''

class ap_daemons():
	def __init__(self, interface, macaddr, ipaddr, dnsserver, country):
		'''
		Initialization of the ap_daemons module
		Args:
			interface: the used interface
			macaddr: MAC address of the interface
			ipaddr: IP address to assign to the interface
			dnsserv: IP address of used DNS server
			country: country code for regulation (e.g. DE)
		'''
		self.log = logging.getLogger('AP_daemons')
		self.interface = interface
		self.macaddr = macaddr
		self.ipaddr = ipaddr
		self.dnsserver = dnsserver
		self.country = country
		self.hostap_interface = None
		self.dnsmasq_pid = None
		self.hostapd_pid = None
		self.dhclient_pid = None

	def start_hostapd(self, config):
		'''
		Starts hostapd daemon based on configuration in the config dictionary
		Args:
			config['channel']: the channel to be used
			config['ssid']: the SSID to be used
			config['hw_mode']: the hw_mode to be used 
			config['ht_capab']: the ht_capab to be used
		'''
		self.hostap_interface = '/tmp/hostapd-' + self.interface # needed to stop hostapd daemon if exists
		self.stop_hostapd()
		self.hostap_interface = '/tmp/hostapd-' + self.interface # reset since stop_hostapd sets it to None
		hapd_str = ("driver=nl80211\n"
			"logger_syslog=127\n"
			"logger_syslog_level=0\n"
			"logger_stdout=127\n"
			"logger_stdout_level=0\n"
			"country_code={}\n"
			"ieee80211d=1\n"
			"ieee80211h=1\n"
			"hw_mode={}\n"
			"channel={}\n"
			"interface={}\n"
			"ctrl_interface={}\n"
			"preamble=1\n"
			"wmm_enabled=1\n"
			"ignore_broadcast_ssid=0\n" 
			"uapsd_advertisement_enabled=1\n" 
			"auth_algs=1\n" 
			"wpa=0\n" 
			"ssid={}\n" 
			"wds_sta=1\n" 
			"bssid={}").format(self.country, config['hw_mode'], config['channel'], self.interface, self.hostap_interface, config['ssid'], self.macaddr)

		if config['ht_capab']: #todo
			hapd_str += ("\nieee80211n=1\n"
				"ht_capab={}\n").format(config['ht_capab'])

		hapd_file = "hostapd" + self.interface + ".conf"
		with open(hapd_file, 'w+') as x_file:
			x_file.write(hapd_str)

		try:
			cmd_str = "echo 3600 | sudo tee /proc/sys/net/ipv4/neigh/default/gc_stale_time"
			self.run_command(cmd_str)
		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

		try:
			cmd_str = "sudo hostapd -B -P " + self.hostap_interface + ".pid " + hapd_file
			self.run_command(cmd_str)
			cmd_str = "sudo rm " + hapd_file
			self.run_command(cmd_str)
		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
			self.hostap_interface = None
			return False

		self.log.info("Started hostapd daemon...")
		return True

	def stop_hostapd(self):
		'''
		Stops hostapd daemon process.
		'''
		pid = None
		if self.hostap_interface is not None:
			try:
				with open(self.hostap_interface + '.pid', 'r') as f: pid = f.readline()
				if pid is not None:
					cmd_str = "sudo kill -15 " + pid
					self.run_command(cmd_str)
			except Exception as e:
				self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
				self.hostap_interface = None
				return False
		self.hostap_interface = None
		self.log.info("Stopped hostapd daemon...")
		return True

	def hostapd_running(self):
		'''
		Checks if hostapd daemon is running.
		'''
		if self.hostap_interface is not None:
			return True
		else: return False

	def start_dnsmasq(self):
		'''
		Starts dnsmasq daemon for the interface self.interface using the dnsserver self.dnsserver
		'''
		self.dnsmasq_pid = '/tmp/dnsmasq-' + self.interface + '.pid' # needed to stop dnsmasq daemon if exists
		self.stop_dnsmasq()
		self.dnsmasq_pid = '/tmp/dnsmasq-' + self.interface + '.pid' # reset since stop_dnsmasq sets it to None
		try:
			cmd_str = "sudo ip addr flush dev " + self.interface
			self.run_command(cmd_str)
			cmd_str = "sudo ip addr add " + self.ipaddr + " dev " + self.interface
			self.run_command(cmd_str)
		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
			return False
		
		addr_split = self.ipaddr.split(".")
		addr_base = addr_split[0] + "." + addr_split[1] + "." + addr_split[2]
		addr_range = addr_base + ".2," + addr_base + ".254,12h"
		addr_last = addr_split[3].split("/")

		#try:
		#	cmd_str = "sudo killall dnsmasq" 
		#	self.run_command(cmd_str)
		#except Exception as e:
		#	self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
		
		gateway_interface = None
		try:
			[rcode, sout, serr] = self.run_command("route | grep '^default' | grep -o '[^ ]*$'")
			if sout: 
				sout_arr = sout.split("\n")
				gateway_interface = sout_arr[0].strip()
		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
			return False
				
		print(gateway_interface)
		if gateway_interface is not None:
			dns_str = ("no-resolv\n"
				"interface={}\n"
				"except-interface=lo\n"
				"bind-interfaces\n"
				"dhcp-range={}\n"
				"server={}").format(self.interface, addr_range, self.dnsserver)

			dns_file = "dnsmasq" + self.interface + ".conf"
			with open(dns_file, 'w+') as x_file:
				x_file.write(dns_str)
					
			try:
				cmd_str = "sudo dnsmasq -x " + self.dnsmasq_pid + " -C " + dns_file
				self.run_command(cmd_str)
				cmd_str = "sudo rm " + dns_file
				self.run_command(cmd_str)
			except Exception as e:
				self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
				self.dnsmasq_pid = None
				return False

			try:
				cmd_str = ("iptables --flush && "
					"iptables --table nat --flush && "
					"iptables --delete-chain && "
					"iptables --table nat --delete-chain && "
					"iptables --table nat --append POSTROUTING --out-interface {} -j MASQUERADE && "
					"iptables --append FORWARD --in-interface {} -j ACCEPT && "
					"sysctl -w net.ipv4.ip_forward=1").format(gateway_interface, self.interface)
				self.run_command(cmd_str)
			except Exception as e:
				self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
				return False
		
		self.log.info("Started dnsmasq daemon...")
		return True

	def stop_dnsmasq(self):
		'''
		Stops dnsmasq daemon process.
		'''
		pid = None
		if self.dnsmasq_pid is not None:
			try:
				with open(self.dnsmasq_pid, 'r') as f: pid = f.readline()
				if pid is not None:
					cmd_str = "sudo kill -15 " + pid
					self.run_command(cmd_str)
			except Exception as e:
				self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
				self.dnsmasq_pid = None
				return False
		self.dnsmasq_pid = None
		self.log.info("Stopped dnsmasq daemon...")
		return True

	def dnsmasq_running(self):
		'''
		Checks if dnsmasq is running.
		'''
		if self.dnsmasq_pid is not None:
			return True
		else: return False

	def dhclient_renew(self):
		'''
		Starts a dhclient daemon on the interface self.interface.
		'''
		self.dhclient_pid = "/var/run/dhclient-" + self.interface + ".pid" # needed to stop dhclient daemon if exists
		self.dhclient_stop()
		self.dhclient_pid = "/var/run/dhclient-" + self.interface + ".pid" # reset since dhclient_stop sets it to None
		try:
			cmd_str = "sudo dhclient -r " + self.interface + " -pf " + self.dhclient_pid + " && sudo dhclient " + self.interface + " -pf " + self.dhclient_pid
			print(cmd_str)
			self.run_command(cmd_str)
		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
			return False
		self.log.info("dhclient renew successfull...")
		return True

	def dhclient_stop(self):
		'''
		Stops the dhclient daemon on the interface self.interface.
		'''
		pid = None
		if self.dhclient_pid is not None:
			try:
				with open(self.dhclient_pid, 'r') as f: pid = f.readline()
				if pid is not None:
					cmd_str = "sudo kill -15 " + pid
					self.run_command(cmd_str)
			except Exception as e:
				self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
				self.dhclient_pid = None
				return False
		self.dhclient_pid = None
		self.log.info("Stopped dhclient daemon...")
		return True

	def stop_network_manager(self):
		'''
		Stops the network-manager service if running.
		'''
		try:
			cmd_str = "sudo service network-manager stop"
			self.run_command(cmd_str)
		except Exception as e:
			self.log.error("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))
			return False
		self.log.info("Network manager stopped...")
		return True

	def get_hostap_interface(self):
		'''
		Returns the hostap control interface.
		'''
		return self.hostap_interface

	def run_command(self, command):
		'''
		Runs system commands.
		'''
		sp = subprocess.Popen(command, stdout=subprocess.PIPE,
				stderr=subprocess.PIPE, shell=True)
		out, err = sp.communicate()

		if False:
			if out:
				self.log.debug("standard output of subprocess:")
				self.log.debug(out)
			if err:
				self.log.debug("standard error of subprocess:")
				self.log.debug(err)

		if err:
			raise Exception("An error occurred in AP_daemons run_command: %s" % err)

		return [sp.returncode, out.decode("utf-8"), err.decode("utf-8")]
