import geoip2.database
import re
import sys

reader = geoip2.database.Reader('GeoLite2-City.mmdb')

output = open(sys.argv[2], 'w')
with open(sys.argv[1]) as f:
    for line in f:
        # 2015-03-21      mfrate  188.184.69.154  dq2-get 13      13012   256691
        cols = re.split('^(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)$', line)
        try:
            response = reader.city(cols[3])
            cols[3] = response.country.iso_code
        except:
            cols[1] = 'NotInDatabase'
        output.write('%s\t%s\t%s\t%s\t%s\t%s\t%s\n' % tuple(cols[1:-1]))
output.close()
