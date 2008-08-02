#include "capture.h"

void closed_capture()
{
  rb_raise(rb_eRuntimeError, "device is already closed");
}

void free_capture(struct capture_object *cap)
{
  if (cap->pcap != NULL) {
    rb_thread_fd_close(pcap_fileno(cap->pcap));
    pcap_close(cap->pcap);
    cap->pcap = NULL;
  }
  
  free(cap);
}

VALUE capture_close(VALUE self)
{
  struct capture_object *cap;

  GetCapture(self, cap);

  if (cap->dumper) {
    pcap_dump_close(cap->dumper);
  }

  rb_thread_fd_close(pcap_fileno(cap->pcap));
  pcap_close(cap->pcap);
  cap->pcap = NULL;
  return Qnil;
}

VALUE capture_setfilter(VALUE self, VALUE v_filter)
{
  struct capture_object *cap;
  struct bpf_program program;

  GetCapture(self, cap);

  if (IsKindOf(v_filter, cFilter)) {
    struct filter_object *f;
    GetFilter(v_filter, f);
    program = f->program;
  } else {
    Check_Type(v_filter, T_STRING);
    char *filter = RSTRING(v_filter)->ptr;
    
    if (pcap_compile(cap->pcap, &program, filter, 1, cap->netmask) < 0) {
      rb_raise(eCaptureError, "setfilter: %s", pcap_geterr(cap->pcap));
    }
  }
  
  if (pcap_setfilter(cap->pcap, &program) < 0) {
    rb_raise(eCaptureError, "setfilter: %s", pcap_geterr(cap->pcap));
  }
  
  return v_filter;
}


VALUE capture_setdissector(VALUE self, VALUE dissector)
{
  if (!(IsKindOf(dissector, rb_cProc) || dissector == Qnil)) {
    rb_raise(rb_eArgError, "dissector must be proc or nil");
  }
        
  struct capture_object *cap;
  GetCapture(self, cap);
  
  cap->dissector = dissector;
  
  return dissector;  
}

VALUE capture_open(int argc, VALUE *argv, VALUE class)
{
  VALUE v_device, v_snaplen = Qnil, v_promisc = Qnil, v_to_ms = Qnil, v_filter = Qnil, v_limit = Qnil, v_dissector = Qnil, v_dump = Qnil;
  char *device;
  char *dump;
  int snaplen, promisc, to_ms;
  int rs;
  VALUE self;
  struct capture_object *cap;
  pcap_t *pcap;
  bpf_u_int32 net, netmask;
  
  rs = rb_scan_args(argc, argv, "13", &v_device, &v_snaplen,&v_promisc, &v_to_ms);
  
  if (IsKindOf(v_device, rb_cHash)) {
    v_snaplen   = rb_funcall(v_device, rb_intern("[]"), 1, ID2SYM(rb_intern("snapshot_length")));
    v_to_ms     = rb_funcall(v_device, rb_intern("[]"), 1, ID2SYM(rb_intern("timeout")));
    v_promisc   = rb_funcall(v_device, rb_intern("[]"), 1, ID2SYM(rb_intern("promiscuous")));
    v_limit     = rb_funcall(v_device, rb_intern("[]"), 1, ID2SYM(rb_intern("limit")));
    v_filter    = rb_funcall(v_device, rb_intern("[]"), 1, ID2SYM(rb_intern("filter")));
    v_dissector = rb_funcall(v_device, rb_intern("[]"), 1, ID2SYM(rb_intern("dissector")));
    v_dump      = rb_funcall(v_device, rb_intern("[]"), 1, ID2SYM(rb_intern("dump")));
    v_device    = rb_funcall(v_device, rb_intern("[]"), 1, ID2SYM(rb_intern("device")));
    
    if (v_device == Qnil) {
      rb_raise(rb_eArgError, ":device must be specified");
    }
  }
  
  Check_SafeStr(v_device);
  device = RSTRING(v_device)->ptr;
  
  if (v_snaplen != Qnil) {
    Check_Type(v_snaplen, T_FIXNUM);
    snaplen = FIX2INT(v_snaplen);
  } else {
    snaplen = DEFAULT_SNAPLEN;
  }
  
  if (snaplen <  0) {
    rb_raise(rb_eArgError, "invalid snaplen");
  }
  
  if (v_promisc != Qnil) {
    promisc = RTEST(v_promisc);
  } else {
    promisc = DEFAULT_PROMISC;
  }
  
  if (v_to_ms != Qnil) {
    Check_Type(v_to_ms, T_FIXNUM);
    to_ms = FIX2INT(v_to_ms);
  } else {
    to_ms = DEFAULT_TO_MS;
  }
  
  pcap = pcap_open_live(device, snaplen, promisc, to_ms, pcap_errbuf);
  
  if (pcap == NULL) {
    rb_raise(eCaptureError, "%s", pcap_errbuf);
  }
  
  if (pcap_lookupnet(device, &net, &netmask, pcap_errbuf) == -1) {
    netmask = 0;
    rb_warning("cannot lookup net: %s\n", pcap_errbuf);
  }
  
  self = Data_Make_Struct(class, struct capture_object, 0, free_capture, cap);
  cap->pcap = pcap;
  cap->netmask = netmask;
  cap->dl_type = pcap_datalink(pcap);
  capture_setdissector(self, v_dissector);
  
  if (v_dump != Qnil) {
    Check_Type(v_dump, T_STRING);
    cap->dumper = pcap_dump_open(cap->pcap, RSTRING(v_dump)->ptr);
  } else {
    cap->dumper = NULL;
  }
  
  if (v_limit != Qnil) {
    Check_Type(v_limit, T_FIXNUM);
    cap->limit = FIX2INT(v_limit);
  } else {
    cap->limit = -1;
  }
  
  if (v_filter != Qnil) {
    capture_setfilter(self, v_filter);
  }
  
  if (rb_block_given_p()) {
    rb_yield(self);
    capture_close(self);
    return Qnil;
  } else
    return self;
}

VALUE capture_open_offline(VALUE class, VALUE fname)
{
  VALUE self;
  struct capture_object *cap;
  pcap_t *pcap;
  
  /* open offline */
  Check_SafeStr(fname);
  pcap = pcap_open_offline(RSTRING(fname)->ptr, pcap_errbuf);
  if (pcap == NULL) {
    rb_raise(eCaptureError, "%s", pcap_errbuf);
  }

  /* setup instance */
  self = Data_Make_Struct(class, struct capture_object, 0, free_capture, cap);
  cap->pcap = pcap;
  cap->netmask = 0;
  cap->dl_type = pcap_datalink(pcap);

  return self;
}

void handler1(struct capture_object *cap, const struct pcap_pkthdr *pkthdr, const u_char *data)
{
  if (cap->dissector != Qnil) {
    VALUE dissected = rb_funcall(cap->dissector, rb_intern("call"), 1, rb_str_new((char *)data, pkthdr->caplen));
    
    rb_yield_values(1, dissected); // not sure why rb_yield doesn't work here, but it wasn't for me
  } else
    rb_yield_values(1, rb_str_new((char *)data, pkthdr->caplen));
}


void handler2(struct capture_object *cap, const struct pcap_pkthdr *pkthdr, const u_char *data)
{
  if (cap->dissector != Qnil) {
    VALUE dissected = rb_funcall(cap->dissector, rb_intern("call"), 1, rb_str_new((char *)data, pkthdr->caplen));

    rb_yield_values(2, dissected, rb_time_new(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec));
  } else
    rb_yield_values(2, rb_str_new((char *)data, pkthdr->caplen), rb_time_new(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec));  
}

VALUE capture_dispatch(int argc, VALUE *argv, VALUE self)
{
  VALUE v_cnt;
  int cnt;
  struct capture_object *cap;
  int ret;

  GetCapture(self, cap);

  if (cap->dumper == NULL) {
    rb_raise(rb_eRuntimeError, "No dump file specified, use each to retrieve packets.");
  }

  /*VALUE proc = rb_block_proc();
  VALUE v_arity = rb_funcall(proc, rb_intern("arity"), 0);
    
  int arity = FIX2INT(v_arity);
  
  pcap_handler handler = (arity < 2) ? (pcap_handler)handler1 : (pcap_handler)handler2;
  */
  
  /* scan arg */
  if (rb_scan_args(argc, argv, "01", &v_cnt) >= 1) {
    FIXNUM_P(v_cnt);
    cnt = FIX2INT(v_cnt);
  } else {
    cnt = -1;
  }
  
  TRAP_BEG;
  ret = pcap_dispatch(cap->pcap, cnt, pcap_dump, (u_char *)cap->dumper);
  TRAP_END;
  
  if (ret == -1)
    rb_raise(eCaptureError, "dispatch: %s", pcap_geterr(cap->pcap));

  return INT2FIX(ret);
}

VALUE capture_loop(int argc, VALUE *argv, VALUE self)
{
  VALUE v_cnt;
  int cnt;
  struct capture_object *cap;
  int ret;

  GetCapture(self, cap);

  VALUE proc = rb_block_proc();
  VALUE v_arity = rb_funcall(proc, rb_intern("arity"), 0);
    
  int arity = FIX2INT(v_arity);

  pcap_handler handler = (arity < 2) ? (pcap_handler)handler1 : (pcap_handler)handler2;

  /* scan arg */
  if (rb_scan_args(argc, argv, "01", &v_cnt) >= 1) {
    FIXNUM_P(v_cnt);
    cnt = FIX2INT(v_cnt);
    } else
    cnt = cap->limit;

    if (pcap_file(cap->pcap) != NULL) {
    TRAP_BEG;
    ret = pcap_loop(cap->pcap, cnt, handler, (u_char *)cap);
    TRAP_END;
  } else {
    int fd = pcap_fileno(cap->pcap);
    fd_set rset;
    struct timeval tm;

    FD_ZERO(&rset);
    tm.tv_sec = 0;
    tm.tv_usec = 0;
    for (;;) {
      do {
        FD_SET(fd, &rset);
        if (select(fd+1, &rset, NULL, NULL, &tm) == 0) {
          rb_thread_wait_fd(fd);
        }
        TRAP_BEG;
        ret = pcap_read(cap->pcap, 1, handler, (u_char *)cap);
        TRAP_END;
      } while (ret == 0);
      if (ret <= 0)
        break;
      if (cnt > 0) {
        cnt -= ret;
        if (cnt <= 0)
          break;
      }
    }
  }

    return INT2FIX(ret);
}

VALUE capture_datalink(VALUE self)
{
    struct capture_object *cap;

    GetCapture(self, cap);

    return INT2NUM(pcap_datalink(cap->pcap));
}

VALUE capture_snapshot(VALUE self)
{
    struct capture_object *cap;

    GetCapture(self, cap);

    return INT2NUM(pcap_snapshot(cap->pcap));
}

VALUE capture_stats(VALUE self)
{
    struct capture_object *cap;
    struct pcap_stat stat;
    VALUE v_stat;

    GetCapture(self, cap);

  memset(&stat, 0, sizeof(stat));

    if (pcap_stats(cap->pcap, &stat) == -1)
    return Qnil;

    v_stat = rb_funcall(cCaptureStat, rb_intern("new"), 3,
            UINT2NUM(stat.ps_recv),
            UINT2NUM(stat.ps_drop),
            UINT2NUM(stat.ps_ifdrop));

    return v_stat;
}

VALUE capture_getlimit(VALUE self)
{
  struct capture_object *cap;
  GetCapture(self, cap);

  return INT2FIX(cap->limit);
}


VALUE capture_setlimit(VALUE self, VALUE limit)
{
  Check_Type(limit, T_FIXNUM);

  struct capture_object *cap;
  GetCapture(self, cap);

  cap->limit = FIX2INT(limit);

  return limit;  
}

VALUE capture_getdissector(VALUE self)
{
  struct capture_object *cap;
  GetCapture(self, cap);

  return cap->dissector;
}

