CaumeDSE

This is not an exhaustive guide for generating digital certificates. It simply illustrates how to generate manually certificates for TLS authentication with CaumeDSE.
The test certificates were generated using the OpenSSL command line tool. Note that these certificates are only for testing purposes and should be replaced with your
own certificates, adding the corresponding extensions for your needs.

The recommended way to regenerate all test certificates at once is to use the provided script:

	./gen_test_certs.sh [output_dir] [server_cn]

After running the script, install the server certificates for CaumeDSE:

	cp server.key server.pem ca.pem /opt/cdse/


1. OPENSSL (manual steps — RSA 4096-bit keys, SHA-256 signatures)

Generate self signed digital certificate (ca is CA), valid for 3650 days. CN = CA:
	openssl genrsa -out ca.key 4096
	openssl req -new -x509 -days 3650 -key ca.key -subj "/C=MX/ST=DF/L=Mexico City/O=EngineOrg/OU=CA/CN=CA" -sha256 -extensions v3_ca -config openssl.cnf -out ca.pem

Generate certificate requirement from engineOrg for the CA. CN = EngineOrg:
	openssl genrsa -out engineOrg.key 4096
	openssl req -new -key engineOrg.key -subj "/C=MX/ST=DF/L=Mexico City/O=EngineOrg/OU=CA/CN=EngineOrg" -out engineOrg.req

Sign engineOrg's requirement by the CA, creating a 2nd level digital certificate:
	openssl x509 -req -days 3650 -sha256 -in engineOrg.req -extfile openssl.cnf -extensions v3_ca -CAkey ca.key -CA ca.pem -CAcreateserial -out engineOrg.pem

Generate certificate requirement from web server for the CA. CN = <IP address or domain of CDSE server>:
	openssl genrsa -out server.key 4096
	openssl req -new -key server.key -subj "/C=MX/ST=DF/L=Mexico City/O=EngineOrg/OU=Webmaster/CN=localhost" -out server.req

Sign web server's requirement by the CA (includes SAN extension for hostname verification):
	openssl x509 -req -days 3650 -sha256 -in server.req -extfile openssl.cnf -extensions web_cert -CAkey ca.key -CA ca.pem -CAcreateserial -out server.pem

Generate certificate requirement from engineAdmin for the engineOrg. CN = EngineAdmin:
	openssl genrsa -out engineAdmin.key 4096
	openssl req -new -key engineAdmin.key -subj "/C=MX/ST=DF/L=Mexico City/O=EngineOrg/OU=Webmaster/CN=EngineAdmin" -out engineAdmin.req

Sign engineAdmin's requirement by engineOrg, creating a 3rd level digital certificate:
	openssl x509 -req -days 3650 -sha256 -in engineAdmin.req -extfile openssl.cnf -extensions usr_cert -CAkey engineOrg.key -CA engineOrg.pem -CAcreateserial -out engineAdmin.pem

Concatenate all CA certs in the chain in a single file:
	cat engineOrg.pem ca.pem > caChain.pem

Display engineAdmin certificate:
	openssl x509 -in engineAdmin.pem -noout -text

Verify engineAdmin certificate:
	openssl verify -CAfile caChain.pem engineAdmin.pem

Display engineOrg certificate:
	openssl x509 -in engineOrg.pem -noout -text

Verify engineOrg certificate:
	openssl verify -CAfile caChain.pem engineOrg.pem

Display web server certificate:
	openssl x509 -in server.pem -noout -text

Verify web server certificate:
	openssl verify -CAfile ca.pem server.pem

Convert user certificate to pkcs12 (Note: the test certificate password for engineAdmin.p12 is 'engineAdmin'):
	openssl pkcs12 -export -out engineAdmin.p12 -inkey engineAdmin.key -in engineAdmin.pem -chain -CAfile caChain.pem -passout pass:engineAdmin

Check contents of pkcs12 file:
	openssl pkcs12 -in engineAdmin.p12 -info



2. GNU TLS
Generate self signed digital certificate (ca is CA), rsa with 4096 bits, valid for 3650 days. Name = <ca domain name or IP address>
Note that certtool is mostly interactive. Be sure to answer yes to "Will the certificate be used to sign other certificates? (y/N)" (i.e. Basic Constraints: CA:TRUE):
	certtool -p --bits 4096 --outfile gnutls_ca.key
(Use constraints: ca, cert sign, crl sign)
	certtool -s --load-privkey gnutls_ca.key --outfile gnutls_ca.pem

Generate certificate requirement from engineOrg for the CA. Name = engineOrg, rsa with 4096 bits, valid for 3650 days. Name = <ca domain name or IP address>:
	certtool -p --bits 4096 --outfile gnutls_engineOrg.key
(Use constraints: ca, cert sign, crl sign)
	certtool -q --load-privkey gnutls_engineOrg.key --outfile gnutls_engineOrg.req

Sign engineOrg's requirement by the CA, creating a 2nd level digital certificate:
(Use constraints: ca, cert sign, crl sign)
	certtool -c --load-request gnutls_engineOrg.req --outfile gnutls_engineOrg.pem --load-ca-certificate gnutls_ca.pem --load-ca-privkey gnutls_ca.key

Generate certificate requirement from engineAdmin for the engineOrg CA. Name = engineAdmin, rsa with 4096 bits, valid for 3650 days. Name = <ca domain name or IP address>:
	certtool -p --bits 4096 --outfile gnutls_engineAdmin.key
(Use constraints: encryption, signature)
	certtool -q --load-privkey gnutls_engineAdmin.key --outfile gnutls_engineAdmin.req

Sign engineOrg's requirement by the CA, creating a 2nd level digital certificate:
(use constraints: encryption, signature)
	certtool -c --load-request gnutls_engineAdmin.req --outfile gnutls_engineAdmin.pem --load-ca-certificate gnutls_engineOrg.pem --load-ca-privkey gnutls_engineOrg.key

Generate certificate requirement from Web for the webserver. Name = localhost, rsa with 4096 bits, valid for 3650 days. Name = <ca domain name or IP address>:
	certtool -p --bits 4096 --outfile gnutls_server.key
(Use constraints: encryption, signature)
	certtool -q --load-privkey gnutls_server.key --outfile gnutls_server.req

Sign web server's requirement by the CA:
(Use constraints: encryption, signature)
	certtool -c --load-request gnutls_server.req --outfile gnutls_server.pem --load-ca-certificate gnutls_ca.pem --load-ca-privkey gnutls_ca.key

Concatenate all CA certs in the chain in a single file:
	cat gnutls_engineOrg.pem gnutls_ca.pem > gnutls_caChain.pem

Display engineAdmin certificate:
	certtool -i --infile gnutls_engineAdmin.pem

Verify engineAdmin certificate:
	cat gnutls_engineAdmin.pem gnutls_caChain.pem | certtool -e

Display engineOrg certificate:
	certtool -i --infile gnutls_engineOrg.pem

Verify engineOrg certificate:
	cat gnutls_caChain.pem | certtool -e

Convert engineAdmin certificate to pkcs12:
	cat gnutls_engineAdmin.pem gnutls_engineOrg.pem gnutls_ca.pem > gnutls_wholeChain.pem
	certtool --to-p12 --load-certificate gnutls_wholeChain.pem --load-privkey gnutls_engineAdmin.key --outder --outfile gnutls_engineAdmin.p12
(Note 1: the last command doesn't seem to add the CA certificate chain. You need at least the signing CA certificate in the chain + the user certificate for CaumeDSE. if this is the case, try with openssl:)
	#	openssl pkcs12 -export -out gnutls_engineAdmin.p12 -inkey gnutls_engineAdmin.key -in gnutls_engineAdmin.pem -aes128 -chain -CAfile gnutls_caChain.pem
(Note 2: Another way to do it according to the docs, but which also doesn't seem to work is:) 
	#	certtool --load-ca-certificate gnutls_caChain.pem --load-certificate gnutls_engineAdmin.pem --load-privkey gnutls_engineAdmin.key --to-p12 --outder --outfile gnutls_engineAdmin.p12	

Check contents of pkcs12 file:
	certtool --p12-info --inder --infile gnutls_engineAdmin.p12
