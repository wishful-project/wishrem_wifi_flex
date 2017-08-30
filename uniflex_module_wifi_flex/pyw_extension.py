import logging
import datetime
import time
import os
import signal

from pyric import pyw # for iw functionality
from pyric.utils.channels import rf2ch
from pyric.utils.channels import ch2rf

import pyric.lib.libnl as nl                    # netlink (library) functions
import pyric.net.wireless.nl80211_h as nl80211h # nl80211 definition
import pyric.net.netlink_h as nlh               # netlink definition
import struct                                   # ioctl unpacking

__author__ = "Daniel Denkovski"
__copyright__ = "Copyright (c) 2017, Faculty of Electrical Engineering and Information Technologies, UKIM, Skopje, Macedonia"
__version__ = "0.1.0"
__email__ = "{danield}@feit.ukim.edu.mk"

'''
Extension of the Pyric module to gather additional device capabilities information.
'''

def phyinfo(card, nlsock=None):
	'''
	Gets phyinfo on the WiFi device including the allowed channels for Initiated Radiation (AP mode).
	Returns ht_capabilities as well based on netlink messages exchange and parsing. 
	'''
	if nlsock is None: return pyw._nlstub_(phyinfo, card)

	# iw sends @NL80211_ATTR_SPLIT_WIPHY_DUMP, we don't & get full return at once
	try:
		msg = nl.nlmsg_new(nltype=pyw._familyid_(nlsock),
			cmd=nl80211h.NL80211_CMD_GET_WIPHY,
			flags=nlh.NLM_F_REQUEST | nlh.NLM_F_ACK)
		nl.nla_put_u32(msg, card.phy, nl80211h.NL80211_ATTR_WIPHY)
		nl.nl_sendmsg(nlsock, msg)
		rmsg = nl.nl_recvmsg(nlsock)
	except AttributeError:
		print("{} Failed, because of AttributeError {}".format(datetime.datetime.now()))
	except nl.error as e:
		print("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

	# pull out attributes
	info = {
		'bands':[],
	}

	_, bs, d = nl.nla_find(rmsg, nl80211h.NL80211_ATTR_WIPHY_BANDS, False)
	if d != nlh.NLA_ERROR: info['bands'] = _bands_(bs)

	return info

def _bands_(bs):
	bands = {}
	for idx, band in bs:
		# the index tell us what band were in (enum nl80211_band)
		try:
			idx = nl80211h.NL80211_BANDS[idx]
		except IndexError:
			idx = "UNK ({0})".format(idx)
		bands[idx] = {'HT': False,
			'VHT': False,
			'ht-capab': None,
			'vht-capab': None,
			'rf-data': None}

		# now we delve into multiple levels of nesting
		for bidx,battr in nl.nla_parse_nested(band):
			# There are other data here (see nl80211_h nl80211_band_attr)
			# that we are not currently using
			if bidx == nl80211h.NL80211_BAND_ATTR_FREQS:
				try:
					bands[idx]['rf-data'] = _band_rfs_(battr)
				except nl.error:
					bands[idx]['rf-data'] = []
			elif bidx == nl80211h.NL80211_BAND_ATTR_HT_CAPA:
				htcapabstr = ''			
				if (battr[0] & 1): htcapabstr += "[LDPC]"; #print("RX LDPC"); 
				if (battr[0] & 2): htcapabstr += "[HT20][HT40]"; #print("HT20/HT40"); 
				if not bytes(battr[0] & 4): htcapabstr += "[HT20]"; #print("HT20");
				if ((battr[0] >> 2) & 0x3) == 0: htcapabstr += "[SMPS-STATIC]"; #print("Static SM Power Save");‬
				if ((battr[0] >> 2) & 0x3) == 1: htcapabstr += "[SMPS-DYNAMIC]"; #print("Dynamic SM Power Save");‬
				if ((battr[0] >> 2) & 0x3) == 3: {} #print("SM Power Save disabled");‬
				if (battr[0] & 16): htcapabstr += "[GF]"; #print("RX Greenfield");
				if (battr[0] & 32): htcapabstr += "[SHORT-GI-20]"; #print("RX HT20 SGI");
				if (battr[0] & 64): htcapabstr += "[SHORT-GI-40]"; #print("RX HT40 SGI");
				if (battr[0] & 128): htcapabstr += "[TX-STBC]"; #print("TX STBC");
				if (battr[1] & 3) == 0: {} #print("No RX STBC");‬
				if (battr[1] & 3) == 1: htcapabstr += "[RX-STBC1]"; #print("RX STBC 1-stream");‬
				if (battr[1] & 3) == 2: htcapabstr += "[RX-STBC12]"; #print("RX STBC 2-streams");‬
				if (battr[1] & 3) == 3: htcapabstr += "[RX-STBC123]"; #print("RX STBC 3-streams");‬
				if (battr[1] & 4): htcapabstr += "[DELAYED-BA]"; #print("HT Delayed Block Ack");
				if not (battr[1] & 8): {} #print("Max AMSDU length: 3839 bytes");
				if (battr[1] & 8): htcapabstr += "[MAX-AMSDU-7935]"; #print("Max AMSDU length: 7935 bytes");
				if (battr[1] & 16): htcapabstr += "[DSSS_CCK-40]"; #print("DSSS/CCK HT40");
				if not (battr[1] & 16): {} #print("No DSSS/CCK HT40");
				if (battr[1] & 64): htcapabstr += "[40-INTOLERANT]"; #print("40 MHz Intolerant");
				if (battr[1] & 128): htcapabstr += "[LSIG-TXOP-PROT]"; #print("L-SIG TXOP protection");

				bands[idx]['ht-capab'] = htcapabstr
				bands[idx]['HT'] = True
				print(htcapabstr)
			#elif bidx == nl80211h.NL80211_BAND_ATTR_VHT_CAPA: # to be done
			#	bands[idx]['vht-capab'] = battr
			#	bands[idx]['VHT'] = True
	return bands
def _band_rfs_(rs):
	rfds = []
	for _, fattr in nl.nla_parse_nested(rs):
		rfd = {
			'channel': None,
			'frequency': None,
			'max-tx': None,        # Card's maximum tx-power on this RF
			'enabled': True,    # w/ current reg. dom. RF is enabled
			'20Mhz': True,      # w/ current reg. dom. 20MHz operation is allowed
			'10Mhz': True,      # w/ current reg. dom. 10MHz operation is allowed
			'radar': False,     # w/ current reg. dom. radar detec. required on RF
			'not-permitted': [], # additional flags
			'no-IR': False
		}
		for rfi, rfattr in nl.nla_parse_nested(fattr):
			# rfi is the index into enum nl80211_frequency_attr
			if rfi == nl80211h.NL80211_FREQUENCY_ATTR_FREQ:
				freq = struct.unpack_from('I', rfattr, 0)[0]
				ch = rf2ch(freq)
				rfd['channel'] = ch
				rfd['frequency'] = freq
			elif rfi == nl80211h.NL80211_FREQUENCY_ATTR_DISABLED:
				rfd['enabled'] = False
			elif rfi == nl80211h.NL80211_FREQUENCY_ATTR_MAX_TX_POWER: # in mBm
				rfd['max-tx'] = struct.unpack_from('I', rfattr, 0)[0] / 100
			elif rfi == nl80211h.NL80211_FREQUENCY_ATTR_NO_HT40_MINUS:
				rfd['not-permitted'].append('HT40-')
			elif rfi == nl80211h.NL80211_FREQUENCY_ATTR_NO_HT40_PLUS:
				rfd['not-permitted'].append('HT40+')
			elif rfi == nl80211h.NL80211_FREQUENCY_ATTR_NO_80MHZ:
				rfd['not-permitted'].append('80MHz')
			elif rfi == nl80211h.NL80211_FREQUENCY_ATTR_NO_160MHZ:
				rfd['not-permitted'].append('160MHz')
			elif rfi == nl80211h.NL80211_FREQUENCY_ATTR_INDOOR_ONLY:
				rfd['not-permitted'].append('outdoor')
			elif rfi == nl80211h.NL80211_FREQUENCY_ATTR_NO_20MHZ:
				rfd['20MHz'] = False
			elif rfi == nl80211h.NL80211_FREQUENCY_ATTR_NO_10MHZ:
				rfd['10MHz'] = False
			elif rfi == nl80211h.NL80211_FREQUENCY_ATTR_NO_IR:
				rfd['no-IR'] = True
			elif rfi == nl80211h.NL80211_FREQUENCY_ATTR_RADAR:
				rfd['radar'] = True
		if rfd['channel'] is not None: rfds.append(rfd)

	return rfds

def survey(card, nlsock=None):
	'''
	Returns survey data to calculate duty cycle at given channel. 
	'''
	if nlsock is None: return pyw._nlstub_(survey, card)

	# iw sends @NL80211_ATTR_SURVEY_INFO
	try:
		flags = nlh.NLM_F_REQUEST | nlh.NLM_F_ACK | nlh.NLM_F_ROOT | nlh.NLM_F_MATCH
		msg = nl.nlmsg_new(nltype=pyw._familyid_(nlsock),
			cmd=nl80211h.NL80211_CMD_GET_SURVEY,
			flags=flags)
		nl.nla_put_u32(msg, card.idx, nl80211h.NL80211_ATTR_IFINDEX)
		nl.nl_sendmsg(nlsock, msg)
		rmsg = nl.nl_recvmsg(nlsock)
	except AttributeError:
		print("{} Failed, because of AttributeError {}".format(datetime.datetime.now()))
	except nl.error as e:
		print("{} Failed, err_msg: {}".format(datetime.datetime.now(), e))

	# pull out attributes
	survey_data = {
		'frequency': 0,
		'noise': None,
		'in_use': False,
		'channel_time': 1,
		'channel_time_busy': 0,
		'channel_time_ext_busy': None,
		'channel_time_tx': None,
		'channel_time_rx': None
		}

	_, bs, d = nl.nla_find(rmsg, nl80211h.NL80211_ATTR_SURVEY_INFO, False)

	in_use = False
	frequency = None
	if d != nlh.NLA_ERROR: 
		for rfi, rfattr in nl.nla_parse_nested(bs):
			# rfi is the index into enum nl80211_frequency_attr
			if rfi == nl80211h.NL80211_SURVEY_INFO_FREQUENCY:
				in_use = False
				frequency = struct.unpack_from('I', rfattr, 0)[0]
			elif rfi == nl80211h.NL80211_SURVEY_INFO_IN_USE:
				in_use = True
				survey_data['frequency'] = frequency
				survey_data['in_use'] = True
			elif rfi == nl80211h.NL80211_SURVEY_INFO_NOISE and in_use == True:
				survey_data['noise'] =  struct.unpack_from('B', rfattr, 0)[0]
			elif rfi == nl80211h.NL80211_SURVEY_INFO_CHANNEL_TIME and in_use == True:
				survey_data['channel_time'] =  struct.unpack_from('Q', rfattr, 0)[0]
			elif rfi == nl80211h.NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY and in_use == True:
				survey_data['channel_time_busy'] =  struct.unpack_from('Q', rfattr, 0)[0]
			elif rfi == nl80211h.NL80211_SURVEY_INFO_CHANNEL_TIME_EXT_BUSY and in_use == True:
				survey_data['channel_time_ext_busy'] =  struct.unpack_from('Q', rfattr, 0)[0]
			elif rfi == nl80211h.NL80211_SURVEY_INFO_CHANNEL_TIME_TX and in_use == True:
				survey_data['channel_time_tx'] =  struct.unpack_from('Q', rfattr, 0)[0]
			elif rfi == nl80211h.NL80211_SURVEY_INFO_CHANNEL_TIME_RX and in_use == True:
				survey_data['channel_time_rx'] =  struct.unpack_from('Q', rfattr, 0)[0]
	return survey_data
