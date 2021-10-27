import socket
import geoip2.database
host = 'fax.mwt2.org'
host = 'atlasxrootd-kit.gridka.de'
ip = socket.getaddrinfo(host, None)[0][4][0]
print(ip)
with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
    response = reader.city(ip)
    print(response)
    print(response.location.latitude, response.location.longitude)
