Gem::Specification.new do |s|
  s.authors       = ['Cory T. Cornelius']
  s.email         = ['cory.t.cornelius@dartmouth.edu']
  s.name          = 'rb-pcap'
  s.version       = '0.1.0'
  s.date          = '2008-08-02'
  s.summary       = 'Simple libpcap wrapper.'
  s.homepage      = 'http://github.com/dxoigmn/rb-pcap'
  s.description   = 'See README.markdown for more information.'
  s.files         = [ 'README.markdown',
                      'lib/rb-pcap.rb',
                      'ext/extconf.rb',
                      'ext/rb_pcap_capture.c',
                      'ext/rb_pcap_capture.h',
                      'ext/rb_pcap_filter.c',
                      'ext/rb_pcap_filter.h',
                      'ext/rb_pcap.c',
                      'ext/rb_pcap.h' ]
  s.require_paths = [ 'lib' ]
  s.extensions    = [ 'ext/extconf.rb' ]
end
