#ifndef __RB_PCAP_FILTER_H__
#define __RB_PCAP_FILTER_H__

#include <ruby.h>
#include <rubysig.h>
#include <pcap.h>

#include "rb_pcap_capture.h"

struct filter_object {
  char                *expr;
  struct bpf_program  program;
  int                 datalink;
  int                 snaplen;
  VALUE               optimize;
  VALUE               netmask;
};

extern VALUE cFilter;

void mark_filter(struct filter_object *filter);
void free_filter(struct filter_object *filter);
VALUE filter_alloc(VALUE self);
VALUE filter_init(int argc, VALUE *argv, VALUE class);
VALUE filter_source(VALUE self);
VALUE filter_match(VALUE self, VALUE v_pkt);

#endif
