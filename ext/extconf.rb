require 'mkmf'

dir_config('pcap')
fail "Couldn't find libpcap." unless have_library("pcap", "pcap_open_live", "pcap.h")

create_makefile("rb_pcap")
