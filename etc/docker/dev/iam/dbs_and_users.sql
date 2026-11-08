CREATE DATABASE IF NOT EXISTS keycloak;
CREATE USER IF NOT EXISTS keycloak@'%' IDENTIFIED BY 'secret';
SET PASSWORD FOR keycloak@'%' = PASSWORD('secret');
GRANT ALL ON keycloak.* TO keycloak@'%';
