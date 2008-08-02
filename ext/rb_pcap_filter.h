#ifndef __FILTER_H__
#define __FILTER_H__

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
  VALUE               capture;
  VALUE               netmask;
};

static VALUE cFilter;

void mark_filter(struct filter_object *filter);
void free_filter(struct filter_object *filter);
VALUE filter_new(int argc, VALUE *argv, VALUE class);
VALUE filter_source(VALUE self);
VALUE filter_match(VALUE self, VALUE v_pkt);

#endif
