from uniflex_module_wifi.packet_sniffer import Sink, PacketSnifferPyShark

__author__ = "Daniel Denkovski"
__copyright__ = "Copyright (c) 2017, Faculty of Electrical Engineering and Information Technologies, UKIM, Skopje, Macedonia"
__version__ = "0.1.0"
__email__ = "{danield}@feit.ukim.edu.mk"

class WiFiRssiSink(Sink):
	def __init__(self, callback=None):
		super().__init__(callback)

	def recv(self, packet):
		if 'radiotap' in packet and 'wlan' in packet:
			rssi = getattr(packet['radiotap'], 'dbm_antsignal', None)
			ta = getattr(packet['wlan'], 'ta_resolved', None)
			chnel = getattr(packet['wlan_radio'], 'channel', None)
			#phy = getattr(packet['wlan_radio'], 'phy', None)
			#nbw = getattr(packet['wlan_radio'], '11n.bandwidth', None)		
			#signal = getattr(packet['wlan_radio'], 'signal_dbm', None)
			#noise = getattr(packet['wlan_radio'], 'noise_dbm', None)
			#drate = getattr(packet['wlan_radio'], 'data_rate', None)
			#txpow = getattr(packet['radiotap'], 'dbm_tx_power', None)
			#quality = getattr(packet['radiotap'], 'quality', None)
			#typeW = getattr(packet['wlan'], 'fc.type', None)
			#stypeW = getattr(packet['wlan'], 'fc.subtype', None)
			if rssi and ta and chnel:
				if self.callback:
					self.callback(str(ta), float(rssi), int(chnel))
