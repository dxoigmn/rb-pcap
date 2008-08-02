Gem::Specification.new do |s|
  s.name          = 'rb-pcap'
  s.version       = '0.0.1'
  s.date          = '2008-08-02'
  s.summary       = 'Simple libpcap wrapper.'
  s.homepage      = 'http://github.com/dxoigmn/rb-pcap'
  s.description   = 'A simple libpcap wrapper.'
  s.files         = [ 'README.markdown',
                      'lib/rb-pcap.rb',
                      'ext/extconf.rb',
                      'ext/rb_pcap_capture.c',
                      'ext/rb_pcap_capture.h',
                      'ext/rb_pcap_filter.c',
                      'ext/rb_pcap_filter.h',
                      'ext/rb_pcap.c' ]
  s.require_paths = [ 'lib' ]
  s.extensions    = [ 'ext/extconf.rb' ]
end