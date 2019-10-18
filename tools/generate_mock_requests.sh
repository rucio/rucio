L=3

bin/mock/rucio-conveyor-injector --loop $L --src srm://tmp1.host:8443/srm/managerv2?SFN=/tmp --dst srm://tmp2.host:8443/srm/managerv2?SFN=/tmp
#bin/mock/rucio-conveyor-injector --loop $L --same-src --src srm://tmp1.host:8443/srm/managerv2?SFN=/tmp --dst srm://tmp2.host:8443/srm/managerv2?SFN=/tmp
#bin/mock/rucio-conveyor-injector --loop $L --same-dst --src srm://tmp1.host:8443/srm/managerv2?SFN=/tmp --dst srm://tmp2.host:8443/srm/managerv2?SFN=/tmp
bin/mock/rucio-conveyor-injector --loop $L --same-src --same-dst --src srm://tmp1.host:8443/srm/managerv2?SFN=/tmp --dst srm://tmp2.host:8443/srm/managerv2?SFN=/tmp
# bin/mock/rucio-conveyor-injector --src https://dcache-xdc.desy.de:443/Users/jaroslav/tests/test.txt --dst https://dcache-xdc.desy.de:443/Users/jaroslav/tests/test.txt_copy
