#ifndef __CAPTURE_H__
#define __CAPTURE_H__

#include <ruby.h>
#include <rubysig.h>
#include <pcap.h>
#include "filter.h"

#define DEFAULT_DATALINK  DLT_EN10MB
#define DEFAULT_SNAPLEN  256
#define DEFAULT_PROMISC  1
#define DEFAULT_TO_MS  1000

static char pcap_errbuf[PCAP_ERRBUF_SIZE];

static VALUE eCaptureError;
static VALUE eTruncatedPacket;
static VALUE cCapture;
static VALUE cCaptureStat;

struct capture_object {
  pcap_t        *pcap;
  pcap_dumper_t *dumper;
  int            limit;      
  bpf_u_int32    netmask;
  int            dl_type;
  VALUE          dissector;
};

#define GetFilter(obj, filter) Data_Get_Struct(obj, struct filter_object, filter)
#define GetPacket(obj, pkt) Data_Get_Struct(obj, struct packet_object, pkt)
#define GetCapture(obj, cap) { Data_Get_Struct(obj, struct capture_object, cap); if (cap->pcap == NULL) closed_capture(); }
#define Caplen(pkt, from) ((pkt)->hdr.pkthdr.caplen - (from))
#define CheckTruncate(pkt, from, need, emsg) ((from) + (need) > (pkt)->hdr.pkthdr.caplen ? rb_raise(eTruncatedPacket, (emsg)) : 0)
#define IsKindOf(v, class) RTEST(rb_obj_is_kind_of(v, class))
#define CheckClass(v, class) ((IsKindOf(v, class)) ? 0 : rb_raise(rb_eTypeError, "wrong type %s (expected %s)", rb_class2name(CLASS_OF(v)), rb_class2name(class)))

void closed_capture();
void free_capture(struct capture_object *cap);
VALUE capture_close(VALUE self);
VALUE capture_setfilter(VALUE self, VALUE v_filter);
VALUE capture_setdissector(VALUE self, VALUE dissector);
VALUE capture_open(int argc, VALUE *argv, VALUE class);
VALUE capture_open_offline(VALUE class, VALUE fname);
void handler1(struct capture_object *cap, const struct pcap_pkthdr *pkthdr, const u_char *data);
void handler2(struct capture_object *cap, const struct pcap_pkthdr *pkthdr, const u_char *data);
VALUE capture_dispatch(int argc, VALUE *argv, VALUE self);
VALUE capture_loop(int argc, VALUE *argv, VALUE self);
VALUE capture_datalink(VALUE self);
VALUE capture_snapshot(VALUE self);
VALUE capture_stats(VALUE self);
VALUE capture_getlimit(VALUE self);
VALUE capture_setlimit(VALUE self, VALUE limit);
VALUE capture_getdissector(VALUE self);

#endif
