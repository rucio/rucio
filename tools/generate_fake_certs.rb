# This generates a fake CERN Trusted Certification Authority, signs a "real subject" client certificate, and in turn signs a proxy certificate with the client certificate.
# Use the fake certificates to test if mod_ssl and mod_gridsite behave properly.

require "openssl"

root_key = OpenSSL::PKey::RSA.new 2048 # the CA's public/private key
root_ca = OpenSSL::X509::Certificate.new
root_ca.version = 2 # cf. RFC 5280 - to make it a "v3" certificate
root_ca.serial = 1
root_ca.subject = OpenSSL::X509::Name.parse "/DC=ch/DC=cern/CN=CERN Trusted Certification Authority"
root_ca.issuer = root_ca.subject # root CA's are "self-signed"
root_ca.public_key = root_key.public_key
root_ca.not_before = Time.now
root_ca.not_after = root_ca.not_before + 2 * 365 * 24 * 60 * 60 # 2 years validity
ef = OpenSSL::X509::ExtensionFactory.new
ef.subject_certificate = root_ca
ef.issuer_certificate = root_ca
root_ca.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
root_ca.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
root_ca.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
root_ca.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
root_ca.sign(root_key, OpenSSL::Digest::SHA256.new)
File.open("fake-cern-tca.pem", "wb") { |f| f.print root_ca.to_pem }
File.open("fake-cern-tca.pem", "a") { |f| f.print root_key }

key_a = OpenSSL::PKey::RSA.new 2048
cert_a = OpenSSL::X509::Certificate.new
cert_a.version = 2
cert_a.serial = 2
cert_a.subject = OpenSSL::X509::Name.parse "/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=mlassnig/CN=663551/CN=Mario Lassnig"
cert_a.issuer = root_ca.subject # root CA is the issuer
cert_a.public_key = key_a.public_key
cert_a.not_before = Time.now
cert_a.not_after = cert_a.not_before + 1 * 365 * 24 * 60 * 60 # 1 years validity
ef_a = OpenSSL::X509::ExtensionFactory.new
ef_a.subject_certificate = cert_a
ef_a.issuer_certificate = root_ca
cert_a.add_extension(ef_a.create_extension("keyUsage","digitalSignature", true))
cert_a.add_extension(ef_a.create_extension("subjectKeyIdentifier","hash",false))
cert_a.sign(root_key, OpenSSL::Digest::SHA256.new)
File.open("fake-mario.pem", "wb") { |f| f.print cert_a.to_pem }
File.open("fake-mario.pem", "a") { |f| f.print key_a }

key_b = OpenSSL::PKey::RSA.new 2048
cert_b = OpenSSL::X509::Certificate.new
cert_b.version = 2
cert_b.serial = 2
cert_b.subject = OpenSSL::X509::Name.parse "/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=mlassnig/CN=663551/CN=Mario Lassnig/CN=proxy"
cert_b.issuer = cert_a.subject # root CA is the issuer
cert_b.public_key = key_b.public_key
cert_b.not_before = Time.now
cert_b.not_after = cert_b.not_before + 1 * 365 * 24 * 60 * 60 # 1 years validity
ef_b = OpenSSL::X509::ExtensionFactory.new
ef_b.subject_certificate = cert_b
ef_b.issuer_certificate = cert_a
cert_b.add_extension(ef_b.create_extension("keyUsage","digitalSignature", true))
cert_b.add_extension(ef_b.create_extension("subjectKeyIdentifier","hash",false))
cert_b.sign(key_a, OpenSSL::Digest::SHA256.new)
File.open("fake-mario-proxy.pem", "wb") { |f| f.print cert_b.to_pem }
File.open("fake-mario-proxy.pem", "a") { |f| f.print key_b }

