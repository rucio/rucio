## Container for Rucio Demo
The containers provided here can be used to easily setup a small demo instance of Rucio with some mock data to play around with some Rucio commands.

### docker-compose
YAML for docker compose has been provided to allow easily setup of the containers:
```
sudo docker-compose --file etc/docker/demo/docker-compose.yml up -d
```
The names of the two containers (rucio and mysql) should be printed in the terminal for you.

### Checking the containers
After you run the docker-compose command you can check the status of the containers:
```
> $ sudo docker ps
CONTAINER ID        IMAGE                    COMMAND                  CREATED             STATUS                     PORTS                  NAMES
ad03d8dc3b4a        demo_rucio               "/wait-for-it.sh --ti"   13 minutes ago      Up 13 minutes              0.0.0.0:443->443/tcp   demo_rucio_1
8d5f8253f3d8        mysql/mysql-server:5.7   "/entrypoint.sh mysql"   13 minutes ago      Up 13 minutes (healthy)    3306/tcp, 33060/tcp    demo_mysql_1
```

### Waiting for the containers to finish setup
It will take some time until the MySQL DB has started and is populated with the demo data. You can check this process with docker logs. When everything is ready you should see something like this:
```
$ sudo docker logs -f demo_rucio_1
wait-for-it.sh: waiting 60 seconds for mysql:5432
wait-for-it.sh: timeout occurred after waiting 60 seconds for mysql:5432
INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
INFO  [alembic.runtime.migration] Running stamp_revision  -> 94a5961ddbf2
[Thu Feb 08 15:37:26.260272 2018] [so:warn] [pid 207] AH01574: module ssl_module is already loaded, skipping
[Thu Feb 08 15:37:26.260357 2018] [so:warn] [pid 207] AH01574: module auth_kerb_module is already loaded, skipping
[Thu Feb 08 15:37:26.260366 2018] [so:warn] [pid 207] AH01574: module wsgi_module is already loaded, skipping
[Thu Feb 08 15:37:26.263810 2018] [so:warn] [pid 207] AH01574: module gridsite_module is already loaded, skipping
AH00558: httpd: Could not reliably determine the server's fully qualified domain name, using 172.18.0.3. Set the 'ServerName' directive globally to suppress this message
```

### Using the container
When everything is ready you can log into the container and start playing around with rucio:
```
$ sudo docker exec -it dev_rucio_1 tools/run_tests.sh
[root@ad03d8dc3b4a rucio]# rucio whoami
status     : ACTIVE
account    : root
account_type : SERVICE
created_at : 2018-02-08T15:37:26
suspended_at : None
updated_at : 2018-02-08T15:37:26
deleted_at : None
email      : None
[root@ad03d8dc3b4a rucio]# rucio list-scopes
tests
user.jdoe
[root@ad03d8dc3b4a rucio]#
```
