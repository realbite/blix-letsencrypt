# letsencrypt

a command line utility for managing letsencrypt ssl certificates.


## depends

ruby >= 2.4

## install

gem install blix-letsencrypt

## command options:

		Usage: letsencrypt [options]
			-c, --create                     Create ACME private key
			-k, --key=FILE                   ACME private key file
			-e, --email=EMAIL                your contact email
			-d, --domain=DOMAIN              domain name for certificate
				--challenge_dir=CDIR         challenge file directory
				--ssl_dir=SSLDIR             ssl certificate file directory
				--ssl_key=SSLKEY             ssl private key file
			-t, --test                       enable test mode
				--force                      force update even if not expired
			-l, --logfile=LOGFILE            log to file
			-h, --hook=HOOK                  script to run on renewal


## conventions used

*  the private key is called `privkey.pem`


*  the certificate is called `cert.pem` and is placed in a directory named
   after the main (first) domain name.

## create letsencrypt certificates

* create directory to hold your keys and certificates .. eg:

      mkdir /etc/letsencrypt/account
      mkdir /etc/letsencrypt/ssl

* create directory to serve challenges from.. eg:

      mkdir /srv/certbot/.well-known

* create a ssl private key if you do not yet have one.. eg:

      openssl genrsa -out /etc/letsencrypt/ssl/privkey.pem 2048

* update your webserver to serve the challengefiles eg for nginx..:

      location /.well-known {
       alias /srv/certbot/.well-known;
       add_header "Content-Type" "text/plain";
       break;
      }

* now create your certificate

      letsencrypt --key=/etc/letsencrypt/account/key.pem -d"example.com www.example.com" --challenge_dir="/srv/certbot/.well-known" --ssl_dir="/etc/letsencrypt/ssl" --logfile=/var/log/letsencrypt.log --create

* hopefully your certificate has be created  so update your webserver to use it...

      ssl_certificate /etc/letsencrypt/ssl/example.com/cert.pem;
      ssl_certificate_key /etc/letsencrypt/ssl/privkey.pem;

* reload the webserver and check all is well.

## auto renew letsencrypt certificates

the letsencrypt certificates are valid for 90 days. it is recommended that you
run a script every day to check if the certificates are due for renewal.

* create two shell scrips, one to renew the certificates and another to
  restart the webserver.

* ensure that both scripts are executable..
* copy the first script to /etc/cron.daily directory.
* link the second script to the `--hook` option of the letsencrypt command.

 eg:

        cat /etc/cron.daily/renew_ssl

    		!/bin/sh
    		/opt/ruby-2.6.4/bin/letsencrypt --key=/etc/letsencrypt/account/key.pem \
            -d"example.com www.example.com" \
            --challenge_dir="/srv/certbot/.well-known" --ssl_dir="/etc/letsencrypt/ssl" \
            --logfile=/var/log/letsencrypt.log \
            --hook=/root/bin/reload_nginx

        cat /root/bin/reload_nginx

    		!/bin/sh
    		/sbin/nginx -t && /sbin/nginx -sreload
