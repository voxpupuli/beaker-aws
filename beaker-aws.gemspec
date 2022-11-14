# -*- encoding: utf-8 -*-
$LOAD_PATH.unshift File.expand_path("../lib", __FILE__)
require 'beaker-aws/version'

Gem::Specification.new do |s|
  s.name        = "beaker-aws"
  s.version     = BeakerAws::VERSION
  s.authors     = ["Rishi Javia, Kevin Imber, Tony Vu"]
  s.email       = ["rishi.javia@puppet.com, kevin.imber@puppet.com, tony.vu@puppet.com"]
  s.homepage    = "https://github.com/puppetlabs/beaker-aws"
  s.summary     = %q{Beaker DSL Extension Helpers!}
  s.description = %q{For use for the Beaker acceptance testing tool}
  s.license     = 'Apache2'

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  # Testing dependencies
  s.add_development_dependency 'rspec', '~> 3.0'
  s.add_development_dependency 'rspec-its'
  s.add_development_dependency 'fakefs', '~> 1.3', '<= 1.9.1'
  s.add_development_dependency 'rake', '~> 13.0'

  # Documentation dependencies
  s.add_development_dependency 'yard'
  s.add_development_dependency 'markdown'
  s.add_development_dependency 'thin'

  # Run time dependencies
  s.add_runtime_dependency 'stringify-hash', '~> 0.0.0'
  s.add_runtime_dependency 'aws-sdk-ec2', '~> 1.35'
  s.add_runtime_dependency 'aws-partitions', '~> 1.91'
end

