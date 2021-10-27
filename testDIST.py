from math import asin, atan2, cos, radians, sin, sqrt
UC_LATITUDE = 41
UC_LONGITUDE = -87
# LRZ
LRZ_LATITUDE = 51
LRZ_LONGITUDE = 9
# client
CLAT = 90
CLON = 0


def dist(lat1, long1, lat2, long2):
    long1, lat1, long2, lat2 = map(radians, [long1, lat1, long2, lat2])
    print('first point: ', lat1, long1, 'second point:', lat2, long2)
    dlon = long2 - long1
    dlat = lat2 - lat1
    # print('dLat:', dlat, 'dLong:', dlon)
    distance = 6378 * 2 * asin(sqrt(sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2))
    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
    distanc1 = 6378 * 2 * atan2(pow(a, 0.5), pow(1 - a, 0.5))
    print(distance, distanc1)


# rucio -H http://rucio-server-int-02.cern.ch list-file-replicas data17_13TeV:DAOD_PHYS.23589107._001299.pool.root.1 --metalink --protocol root

dist(lat1=CLAT, long1=CLON, lat2=UC_LATITUDE, long2=UC_LONGITUDE)
dist(lat1=CLAT, long1=CLON, lat2=LRZ_LATITUDE, long2=LRZ_LONGITUDE)
