#include "rb_pcap_filter.h"

void mark_filter(struct filter_object *filter)
{
  rb_gc_mark(filter->capture);
  rb_gc_mark(filter->optimize);
  rb_gc_mark(filter->netmask);
}

void free_filter(struct filter_object *filter)
{
  free(filter->expr);
  free(filter);
  /*
  * This causes amemory leak because filter->program holds some memory.
  * We overlook it because libpcap does not implement pcap_freecode().
  */
}

VALUE filter_new(int argc, VALUE *argv, VALUE class)
{
  VALUE self, v_expr, v_optimize, v_capture, v_netmask;
  struct filter_object *filter;
  struct capture_object *capture;
  pcap_t *pcap;
  char *expr;
  int n, optimize, snaplen, linktype;
  bpf_u_int32 netmask;

  n = rb_scan_args(argc, argv, "13", &v_expr, &v_capture, &v_optimize, &v_netmask);
  
    /* filter expression */
  Check_Type(v_expr, T_STRING);
  expr = STR2CSTR(v_expr);
  
  /* capture object */
  if (IsKindOf(v_capture, cCapture)) {
    CheckClass(v_capture, cCapture);
    GetCapture(v_capture, capture);
    pcap                      = capture->pcap;
  } else if (NIL_P(v_capture)) {
  /* assume most common case */
    snaplen                   = DEFAULT_SNAPLEN;
    linktype                  = DEFAULT_DATALINK;
    pcap                      = 0;
  } else {
    snaplen                   = NUM2INT(rb_funcall(v_capture, rb_intern("[]"), 1, INT2FIX(0)));
    linktype                  = NUM2INT(rb_funcall(v_capture, rb_intern("[]"), 1, INT2FIX(1)));
    pcap                      = 0;
  }
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

  filter = (struct filter_object *)xmalloc(sizeof(struct filter_object));
  if (pcap) {
    if (pcap_compile(pcap, &filter->program, expr, optimize, netmask) < 0)
      rb_raise(eCaptureError, "%s", pcap_geterr(pcap));
      
    filter->datalink = pcap_datalink(pcap);
    filter->snaplen = pcap_snapshot(pcap);
    
  } else {
    
    if (pcap_compile_nopcap(snaplen, linktype, &filter->program, expr, optimize, netmask) < 0)
      /* libpcap-0.5 provides no error report for pcap_compile_nopcap */
      rb_raise(eCaptureError, "pcap_compile_nopcap error");
    filter->datalink          = linktype;
    filter->snaplen           = snaplen;
  }
  self                   = Data_Wrap_Struct(class, mark_filter, free_filter, filter);
  filter->expr           = strdup(expr);
  filter->capture        = v_capture;
  filter->optimize       = optimize ? Qtrue : Qfalse;
  filter->netmask        = INT2NUM(ntohl(netmask));

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
  if (bpf_filter(filter->program.bf_insns, (unsigned char *)StringValuePtr(v_pkt), v_pkt_len, v_pkt_len))
    return Qtrue;
  else
    return Qfalse;
}
