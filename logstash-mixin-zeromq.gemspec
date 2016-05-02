Gem::Specification.new do |s|

  s.name            = 'logstash-mixin-zeromq'
  s.version         = '4.0.1'
  s.licenses        = ['Apache License (2.0)']
  s.summary         = "Mixin to share code for zeromq input, output and filter"
  s.description     = "This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program"
  s.authors         = ["Elastic"]
  s.email           = 'info@elastic.co'
  s.homepage        = "http://www.elastic.co/guide/en/logstash/current/index.html"
  s.require_paths   = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']

  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"

  s.add_runtime_dependency 'ffi-rzmq', '~> 2.0.4'

  s.add_development_dependency 'logstash-devutils'
  s.add_development_dependency 'logstash-codec-plain'
end
