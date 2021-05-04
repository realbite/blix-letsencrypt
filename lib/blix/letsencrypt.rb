# frozen_string_literal: true

# this is a script for renewing letsencrypt certicates. .. to automate the
# process create a shell script to run this command and a shell script to
# restart the web server
#
# ensure that both scripts are executable..
# copy the first script to /etc/cron.daily directory.
# link the second script to the --hook option of this ruby command.
#
# eg:
#
#    cat /etc/cron.daily/renew_ssl
#
#    #!/bin/sh
#    /opt/ruby-2.6.4/bin/ruby /root/bin/letsencrypt.rb --key=/etc/letsencrypt/account/key.pem \
#      -d"example.com www.example.com" \
#      --challenge_dir="/tmp/certbot/public_html/.well-known" \
#      --ssl_dir="/etc/letsencrypt/ssl" \
#      --logfile=/var/log/letsencrypt.log \
#      --hook=/root/bin/reload_nginx
#
#
#    cat /root/bin/reload_nginx
#    #!/bin/sh
#    /opt/nginx-1.2.2/sbin/nginx -t && /opt/nginx-1.2.2/sbin/nginx -sreload
#
#
# copyright Clive Andrews 2020
#
# licence MIT



require 'openssl'
require 'optparse'
require 'acme-client'
require 'logger'

# location /.well-known{
#                rewrite ^\.well-known(.*)$ $1 break;
#                alias /srv/letsencrypt/challenge;
#                add_header Content-Type text/plain;
#           }

CHALLENGE_DIR = '/srv/letsencrypt'
SSL_DIR       = '/etc/letsencrypt/cert'
SSL_CERT      = 'cert.pem'
SSL_KEY       = 'privkey.pem'
ACME_DIR_S    = 'https://acme-staging-v02.api.letsencrypt.org/directory' # letsencrypt
ACME_DIR_L    = 'https://acme-v02.api.letsencrypt.org/directory' # letsencrypt live

TIMEOUT = 60

# check if certificate is about to expire.
def certificate_expiry_is_soon(ssl_dir, certificate_file, days = 30)
  file = File.join(ssl_dir, certificate_file)
  return true unless File.file?(file)

  cert = OpenSSL::X509::Certificate.new(File.read(file))
  cert.not_after < Time.now + days * (24 * 60 * 60)
end

def tidy_challenge_file(file)
  file = file[1..-1] if file[0, 1] == '/'
  str = '.well-known'
  file = file[str.length..-1] if file[0, str.length] == str
  file
end

def fatal_error(message)
  STDERR.puts "error: #{message}"
  exit(false)
end

# write the challenge file and ensure that intermediate dirs exist
def write_file(dir, file, content)
  file = tidy_challenge_file(file)
  parts = file.split('/')
  last_index = parts.length - 1
  path = nil
  parts.each_with_index do |_part, idx|
    path = File.join(dir, *parts[0, idx + 1])
    if idx == last_index # the file name
      File.write(path, content)
    else
      if File.file?(path)
        fatal_error "invalid challenge path: #{path}"
      elsif File.directory?(path)

      else
        Dir.mkdir(path)
      end
    end
  end
  path
end

def backup_file(dir, file)
  orig_path = File.join(dir, file)
  orig_file = File.basename(orig_path)
  orig_dir  = File.dirname(orig_path)

  fatal_error "backup file does not exist:#{orig_path}" unless File.exist?(orig_path)

  seq = 1
  loop  do
    prefix = '%04d_' % seq
    new_file = prefix + orig_file
    new_path = File.join(orig_dir, new_file)
    if File.exist?(new_path)
      seq += 1
      next
    else
      content = File.read(orig_path)
      File.write(new_path, content)
      break new_path
    end
  end
end

# delete the challenge files
def remove_file(dir, file)
  file = tidy_challenge_file(file)
  path = File.join(dir, file)
  File.unlink(path) if File.file?(path)
  true
end

# perform an authorization by creating the challenge files
# and waiting for validation to occur.
def perform_authorization(challenge_dir, authorization)
  http_challenge = authorization.http

  # write the challenge to file

  http_challenge.content_type # => 'text/plain'
  http_challenge.file_content # => example_token.TO1xJ0UDgfQ8WY5zT3txynup87UU3PhcDEIcuPyw4QU
  http_challenge.filename # => '.well-known/acme-challenge/example_token'
  http_challenge.token

  challenge_file = tidy_challenge_file(http_challenge.filename)
  challenge_path = write_file(challenge_dir, challenge_file, http_challenge.file_content)

  puts "challenge has been written to :#{challenge_path}"

  # now wait for the challenge ..

  http_challenge.request_validation
  timeout_time = Time.now + TIMEOUT

  while http_challenge.status == 'pending'
    if Time.now > timeout_time
      remove_file(challenge_dir, challenge_file)
      fatal_error 'Challenge timeout'
    end
    sleep(2)
    http_challenge.reload
  end

  remove_file(challenge_dir, challenge_file)
  fatal_error 'challenge failed' unless http_challenge.status == 'valid' # => 'valid'
end

# handle options here
options = {}
OptionParser.new do |opts|
  # opts.banner = "Usage: example.rb [options]"

  opts.on('-c', '--create', 'Create ACME private key') do |_v|
    options[:create] = true
  end

  opts.on('-k', '--key=FILE', 'ACME private key file') do |v|
    options[:key] = v
  end

  opts.on('-e', '--email=EMAIL', 'your contact email') do |v|
    options[:email] = v
  end

  opts.on('-d', '--domain=DOMAIN', 'domain name for certificate') do |v|
    options[:site] = v
  end

  opts.on('--challenge_dir=CDIR', 'challenge file directory') do |v|
    options[:challenge_dir] = v
  end

  opts.on('--ssl_dir=SSLDIR', 'ssl certificate file directory') do |v|
    options[:ssl_dir] = v
  end

  opts.on('--ssl_key=SSLKEY', 'ssl private key file') do |v|
    options[:ssl_dir] = v
  end

  opts.on('-t', '--test', 'enable test mode') do |v|
    options[:test] = v
  end

  opts.on('--force', 'force update even if not expired') do |v|
    options[:force] = v
  end

  opts.on('-l', '--logfile=LOGFILE', 'log to file') do |v|
    options[:logfile] = v
  end

  opts.on('-h', '--hook=HOOK', 'script to run on renewal') do |v|
    options[:hook] = v
  end
end.parse!

# check that we have sensible values four our options before we start the
# whole [rpcess]
domains = options[:site].to_s
domains.gsub!(',', ' ')
domains.gsub!(';', ' ')
domains.gsub!(/  +/, ' ')
names = domains.split(' ')
site = names[0]
ssl_dir = File.expand_path(options[:ssl_dir] || SSL_DIR)
challenge_dir = File.expand_path(options[:challenge_dir] || CHALLENGE_DIR)
ssl_key_path  = options[:ssl_key] || File.join(ssl_dir, SSL_KEY)
hook_path     = options[:hook]

fatal_error 'domain name missing'               unless site
fatal_error 'invalid challenge directory'       unless File.directory?(challenge_dir)
fatal_error 'invalid ssl certificate directory'       unless File.directory?(ssl_dir)
fatal_error "ssl private key invalid:#{ssl_key_path}" unless File.file?(ssl_key_path)
fatal_error "script missing or not executable:#{hook_path}" unless !hook_path || File.executable?(hook_path)

certificate_file = File.join(site, SSL_CERT)
acme_key = File.expand_path(options[:key])
ssl_key = OpenSSL::PKey::RSA.new(File.read(ssl_key_path))

logger = Logger.new(options[:logfile] || STDOUT)

# check to see if the certificate is due for renewal. if the
# certificate expires within 30 days then renew otherwise exit
# unless the force option is set.
unless options[:force]
  unless certificate_expiry_is_soon(ssl_dir, certificate_file)
    logger.info "certificate:#{certificate_file} not due for renewal"
    exit
  end
end

# first read our private key..
if File.file?(acme_key)
  private_key = OpenSSL::PKey::RSA.new(File.read(acme_key)) # read
elsif options[:create]
  private_key = OpenSSL::PKey::RSA.new(4096) # generate
  File.write(acme_key, private_key)
else
  fatal_error "acme key file:#{acme_key} not found"
end

client = if options[:test]
           Acme::Client.new(:private_key => private_key, :directory => ACME_DIR_S)
         else
           Acme::Client.new(:private_key => private_key, :directory => ACME_DIR_L)
         end

# ensure that we hav an account.
kid = begin
        client.kid
      rescue StandardError
        nil
      end

unless kid
  email = options[:email] || begin
    print('enter your email:')
    gets.strip
  end
  fatal_error "invalid email:#{email}" unless email && email =~ /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$/

  account = client.new_account(:contact => "mailto:#{email}", :terms_of_service_agreed => true)
end

puts 'account found..'

# now set up our order ..

puts "setting up domain #{site}:#{names.join(',')}:"

order = client.new_order(:identifiers => names)
order.authorizations.each { |auth| perform_authorization(challenge_dir, auth) }

# download the certificate

puts 'now obtaining certificate..'

csr = Acme::Client::CertificateRequest.new(:private_key => ssl_key, :names => names, :subject => { :common_name => site })
order.finalize(:csr => csr)

timeout_time = Time.now + TIMEOUT
while order.status == 'processing'
  fatal_error 'certificate timeout' if Time.now > timeout_time

  sleep(1)
  order.reload
end

# now write the certificate to file

# backup the old file if it exists.

if File.file?(File.join(ssl_dir, certificate_file))
  backup_file(ssl_dir, certificate_file)
end

ssl_path = write_file(ssl_dir, certificate_file, order.certificate)
logger.info "ssl certificate has been written to :#{ssl_path}"

if hook_path
  if system(hook_path)
    logger.info "script :#{hook_path} succeeded"
  else
    logger.info "script :#{hook_path} failed !!"
  end
end
