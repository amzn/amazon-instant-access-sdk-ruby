# coding: utf-8
require File.expand_path('../lib/amazon-instant-access/version', __FILE__)

Gem::Specification.new do |spec|
  spec.name          = 'amazon-instant-access'
  spec.version       = AmazonInstantAccess::VERSION
  spec.authors       = ['Amazon.com']
  spec.email         = ['d3-support@amazon.com']

  spec.summary       = 'Amazon Instant Access - Ruby SDK'
  spec.description   = 'Ruby SDK to aid third-party integration with Amazon Instant Access'
  spec.homepage      = 'https://github.com/amzn/amazon-instant-access-sdk-ruby'
  spec.license       = 'Apache-2.0'

  spec.files         = `git ls-files -z`.split("\x0").reject do |f| f.match(%r{^(test|spec|features)/}) end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec'
end
