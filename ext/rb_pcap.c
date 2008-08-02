#include "rb_pcap.h"

void Init_rb_pcap() {
  cCapture = rb_define_class("Capture", rb_cObject);
  rb_include_module(cCapture, rb_mEnumerable); 
  rb_define_singleton_method(cCapture, "open", capture_open, -1);
  rb_define_singleton_method(cCapture, "open_offline", capture_open_offline, 1);
  rb_define_method(cCapture, "close", capture_close, 0);
  rb_define_method(cCapture, "dispatch", capture_dispatch, -1);
  rb_define_method(cCapture, "each", capture_loop, -1);
  rb_define_method(cCapture, "each_packet", capture_loop, -1);
  rb_define_method(cCapture, "filter=", capture_setfilter, 1);
  rb_define_method(cCapture, "limit", capture_getlimit, 0);
  rb_define_method(cCapture, "limit=", capture_setlimit, 1);
  rb_define_method(cCapture, "dissector", capture_getdissector, 0);
  rb_define_method(cCapture, "dissector=", capture_setdissector, 0);
  rb_define_method(cCapture, "datalink", capture_datalink, 0);
  rb_define_method(cCapture, "snapshot_length", capture_snapshot, 0);
  
  cFilter = rb_define_class_under(cCapture, "Filter", rb_cObject);
  rb_define_alloc_func(cFilter, filter_alloc);
  rb_define_method(cFilter, "initialize", filter_init, -1);
  rb_define_method(cFilter, "expression", filter_source, 0);
  rb_define_method(cFilter, "=~", filter_match, 1);
  rb_define_method(cFilter, "===", filter_match, 1);
  
  eCaptureError    = rb_define_class_under(cCapture, "CaptureError", rb_eStandardError);
  eTruncatedPacket = rb_define_class_under(cCapture, "TruncatedPacket", eCaptureError);
}
