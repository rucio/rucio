# create a bunch of files and datasets
ENDFILE=500
for i in $(seq 0 $ENDFILE); do
	RANDSIZE=$[ $RANDOM % 5000 + 1 ]
	dd if=/dev/urandom of=/tmp/mandalorian_file_test$i bs="$RANDSIZE"K count=1
	rucio upload --rse XRD1 --scope test /tmp/mandalorian_file_test$i --lifetime 0
done

ENDDATASET=50
for i in $(seq 0 $ENDDATASET); do
	rucio add-dataset test:mandalorian_dataset$i
	for j in $(seq 0 10); do
		RANDFILE=$[ $RANDOM % $ENDFILE ]
		rucio attach test:mandalorian_dataset$i test:mandalorian_file_test$RANDFILE
	done
	rucio add-rule test:mandalorian_dataset$i 2 'XRD1|XRD2|XRD3'
done

# Run the deamons couple of times till all files are submitted to the expected datasets
for i in 1 2 3 4 5 6 7 8 9 10 ; do echo $i; rucio-conveyor-submitter --run-once; rucio-conveyor-poller --run-once; rucio-conveyor-finisher --run-once; done
# will clean the locks over files in XRD1
for i in 1 2 3 4 5; do echo $i; rucio-judge-cleaner --run-once ; done
# Will delete all the spureous replicas in XRD1
for i in 1 2 3 4 5; do echo $i; rucio-reaper --run-once --greedy --rse XRD1; done
# This should not erase any file as all are protected by rules over DIDs
rucio-reaper --run-once --greedy --rse XRD2
rucio-reaper --run-once --greedy --rse XRD3

# Test the Mandalorian over XRD2
# avoid new files go to XRD2
rucio-admin rse update --setting availability_write --value False --rse XRD2
# decommission of XRD2, should remove all the rules over all the datasets in XRD2
rucio-mandalorian XRD2

for i in 1 2 3 4 5 6 7 8 9 10 ; do echo $i; rucio-conveyor-submitter --run-once; rucio-conveyor-poller --run-once; rucio-conveyor-finisher --run-once; done
rucio-judge-cleaner --run-once
rucio-reaper --run-once --greedy --rse XRD2
rucio-reaper --run-once --greedy --rse XRD2


# for name in `find / -iname *mandalorian*`; do rm -vf $name; done
