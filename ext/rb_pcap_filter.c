#include "rb_pcap_filter.h"

void free_filter(struct filter_object *filter)
{
  free(filter->expr);
  free(filter);
}

VALUE filter_alloc(VALUE self)
{
  struct filter_object *filter = (struct filter_object *)xmalloc(sizeof(struct filter_object));
  
  filter->expr = NULL;
  
  return Data_Wrap_Struct(self, NULL, free_filter, filter);
}

VALUE filter_init(int argc, VALUE* argv, VALUE self)
{
  VALUE v_expr, v_optimize, v_netmask;
  struct filter_object *filter;
  char *expr;
  int n, optimize, snaplen, linktype;
  bpf_u_int32 netmask;
  
  n = rb_scan_args(argc, argv, "12", &v_expr, &v_optimize, &v_netmask);
  
  /* filter expression */
  Check_Type(v_expr, T_STRING);
  expr = STR2CSTR(v_expr);
  
  snaplen   = DEFAULT_SNAPLEN;
  linktype  = DEFAULT_DATALINK;

  /* optimize flag */
  optimize = 1;
  if (n >= 3) {
    optimize = RTEST(v_optimize);
  }
    /* netmask */
  netmask = 0;
  if (n >= 4) {
    bpf_u_int32 mask = NUM2UINT(v_netmask);
    netmask = htonl(mask);
  }
  
  GetFilter(self, filter);
  
  if (pcap_compile_nopcap(snaplen, linktype, &filter->program, expr, optimize, netmask) == -1) {
    rb_raise(eCaptureError, "pcap_compile_nopcap error");
  }
  
  filter->datalink  = linktype;
  filter->snaplen   = snaplen;
  filter->expr      = strdup(expr);
  filter->optimize  = optimize ? Qtrue : Qfalse;
  filter->netmask   = INT2NUM(ntohl(netmask));
  
  return self;
}

VALUE filter_source(VALUE self)
{
    struct filter_object *filter;

    GetFilter(self, filter);
    return rb_str_new2(filter->expr);
}


VALUE filter_match(VALUE self, VALUE v_pkt)
{
  struct filter_object *filter;
  struct packet_object *pkt;

  GetFilter(self, filter);

  int v_pkt_len = RSTRING(v_pkt)->len;
  
  if (bpf_filter(filter->program.bf_insns, (unsigned char *)StringValuePtr(v_pkt), v_pkt_len, v_pkt_len)) {
    return Qtrue;
  }
  
  return Qfalse;
}
