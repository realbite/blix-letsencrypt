Gem::Specification.new do |s|
  s.name = 'blix-letsencrypt'
  s.description = %Q[Command line utilities for letsencrypt]
  s.summary = %Q[Command line utilities for managing  letsencrypt ssl certificates]
  s.version = '1.0.0'
  s.platform = Gem::Platform::RUBY
  s.authors = ['Clive Andrews']
  s.license = 'MIT'
  s.email = ['gems@realitybites.eu']
  s.homepage = 'https://github.com/realbite/blix-letsencrypt'
  s.add_dependency('acme-client')


  s.add_development_dependency('rspec')

  s.files = ['lib/blix/letsencrypt.rb']
  s.files << 'bin/letsencrypt'
  s.files << 'LICENSE'
  s.files << 'README.md'

  s.extra_rdoc_files = ['README.md','LICENSE']
  s.require_paths = ['lib']
  s.executables << 'letsencrypt'
end
