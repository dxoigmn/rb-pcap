require 'mkmf'

if have_header("pcap.h") 
  have_library("pcap", "pcap_open_live")
  have_library("pcap", "pcap_compile_nopcap")
  have_library("pcap", "pcap_snapshot")
  create_makefile("rb-pcap")
end
