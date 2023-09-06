# frozen_string_literal: true

require_relative 'lib/google/auth/extras/version'

Gem::Specification.new do |spec|
  spec.name          = 'googleauth-extras'
  spec.version       = Google::Auth::Extras::VERSION
  spec.authors       = ['Persona Identities']
  spec.email         = ['alex.coomans@withpersona.com']

  spec.summary       = 'Additions to the googleauth gem for unsupported authentication schemes.'
  spec.homepage      = 'https://github.com/persona-id/googleauth-extras'
  spec.license       = 'MIT'

  spec.required_ruby_version = Gem::Requirement.new('>= 2.7.0')

  spec.metadata['allowed_push_host']     = 'https://rubygems.org'
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.metadata['homepage_uri']    = spec.homepage
  spec.metadata['source_code_uri'] = 'https://github.com/persona-id/googleauth-extras'
  spec.metadata['changelog_uri']   = 'https://github.com/persona-id/googleauth-extras/blob/main/CHANGELOG.md'

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_runtime_dependency 'addressable', '~> 2.8'
  spec.add_runtime_dependency 'faraday', '>= 1.0', '< 3.0'
  spec.add_runtime_dependency 'google-apis-iamcredentials_v1'
  spec.add_runtime_dependency 'googleauth', '~> 1.3'
  spec.add_runtime_dependency 'signet', '>= 0.17.0', '< 0.19.0'
end
