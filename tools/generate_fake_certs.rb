require "openssl"

root_key = OpenSSL::PKey::RSA.new 2048 # the CA's public/private key
root_ca = OpenSSL::X509::Certificate.new
root_ca.version = 2 # cf. RFC 5280 - to make it a "v3" certificate
root_ca.serial = 1
root_ca.subject = OpenSSL::X509::Name.parse "/DC=ch/DC=cern/CN=CERN Trusted Certification Authority"
root_ca.issuer = root_ca.subject # root CA's are "self-signed"
root_ca.public_key = root_key.public_key
root_ca.not_before = Time.now
root_ca.not_after = root_ca.not_before + 32 * 365 * 24 * 60 * 60 # 2 years validity
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

key = OpenSSL::PKey::RSA.new 2048
cert = OpenSSL::X509::Certificate.new
cert.version = 2
cert.serial = 2
cert.subject = OpenSSL::X509::Name.parse "/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=mlassnig/CN=663551/CN=Mario Lassnig"
cert.issuer = root_ca.subject # root CA is the issuer
cert.public_key = key.public_key
cert.not_before = Time.now
cert.not_after = cert.not_before + 1 * 365 * 24 * 60 * 60 # 1 years validity
ef = OpenSSL::X509::ExtensionFactory.new
ef.subject_certificate = cert
ef.issuer_certificate = root_ca
cert.add_extension(ef.create_extension("keyUsage","digitalSignature", true))
cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
cert.sign(root_key, OpenSSL::Digest::SHA256.new)
File.open("fake-mario.pem", "wb") { |f| f.print cert.to_pem }
File.open("fake-mario.pem", "a") { |f| f.print key }

key = OpenSSL::PKey::RSA.new 2048
cert = OpenSSL::X509::Certificate.new
cert.version = 2
cert.serial = 2
cert.subject = OpenSSL::X509::Name.parse "/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=mlassnig/CN=663551/CN=Mario Lassnig/CN=proxy"
cert.issuer = root_ca.subject # root CA is the issuer
cert.public_key = key.public_key
cert.not_before = Time.now
cert.not_after = cert.not_before + 1 * 365 * 24 * 60 * 60 # 1 years validity
ef = OpenSSL::X509::ExtensionFactory.new
ef.subject_certificate = cert
ef.issuer_certificate = root_ca
cert.add_extension(ef.create_extension("keyUsage","digitalSignature", true))
cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
cert.sign(root_key, OpenSSL::Digest::SHA256.new)
File.open("fake-mario-proxy.pem", "wb") { |f| f.print cert.to_pem }
File.open("fake-mario-proxy.pem", "a") { |f| f.print key }

