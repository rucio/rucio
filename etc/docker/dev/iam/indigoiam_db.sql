/*M!999999\- enable the sandbox mode */
-- MariaDB dump 10.19  Distrib 10.11.14-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: indigoiam
-- ------------------------------------------------------
-- Server version	10.11.14-MariaDB-ubu2204

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Current Database: `indigoiam`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `indigoiam` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci */;

USE `indigoiam`;

--
-- Table structure for table `access_token`
--

DROP TABLE IF EXISTS `access_token`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `access_token` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `token_value` varchar(4096) DEFAULT NULL,
  `expiration` timestamp NULL DEFAULT NULL,
  `token_type` varchar(256) DEFAULT NULL,
  `refresh_token_id` bigint(20) DEFAULT NULL,
  `client_id` bigint(20) DEFAULT NULL,
  `auth_holder_id` bigint(20) DEFAULT NULL,
  `id_token_id` bigint(20) DEFAULT NULL,
  `approved_site_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `token_value` (`token_value`(766)),
  KEY `at_tv_idx` (`token_value`(767)),
  KEY `at_exp_idx` (`expiration`),
  KEY `at_ahi_idx` (`auth_holder_id`)
) ENGINE=InnoDB AUTO_INCREMENT=181 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `access_token`
--

LOCK TABLES `access_token` WRITE;
/*!40000 ALTER TABLE `access_token` DISABLE KEYS */;
INSERT INTO `access_token` VALUES
(37,'eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczpcL1wvaW5kaWdvaWFtXC8iLCJhdWQiOiI4NWU2ZjdhNS01ODBiLTRhMWMtYTZkMi0zOTA1NTE0MzA2M2QiLCJpYXQiOjE3NTgxOTkwNTAsImp0aSI6IjMxMGMzNDkxLWJjY2QtNDg4Ni1iMGU0LTA0NDc0NDcwNTYyNSJ9.OoWvvn7ipKq-ySaQFtZq2dSaEcgGUFe99x2aMhZQ75ohg9yLLNgbYIz8b9DKLKi3Wh9nf5CC-aP-wfinnOcsQPZSVCF0hCjs3ZySNdJvpNJvT9By6q9qjRzaPuH6Zrt47lMtkbJpr26SySMmOPA4PCQ0KNgt3rICkTJ2H7WuSh4',NULL,'Bearer',NULL,2,37,NULL,NULL),
(38,'eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczpcL1wvaW5kaWdvaWFtXC8iLCJhdWQiOiIxMTAzNDY2Ny01YzUwLTRjOWEtOGY0My02YTQ4MDkwZGNlZDIiLCJpYXQiOjE3NTgyMDI3MjAsImp0aSI6ImY5MjM4ZTZhLWVmMmItNDNmZS04MDI0LTBmYjJiZGZhMzQ1YSJ9.iDQgj6w4K4VwDRMRyTbRim5-hGiQN8bJbX4aqWW3vIpxD6VEx0RH_FcV_VbHjXbcXXwo1BNT9Rxn-GEnr2YGsxvwG7rOuGpZPUn1ZuLLpSQEOIKW2Pbw77qnh-SG3GDfcO1dqbsK4R6qUW6amyHX8q2BJfKZG2_HQXeNdvQm7XY',NULL,'Bearer',NULL,9,38,NULL,NULL);
/*!40000 ALTER TABLE `access_token` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `access_token_permissions`
--

DROP TABLE IF EXISTS `access_token_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `access_token_permissions` (
  `access_token_id` bigint(20) NOT NULL,
  `permission_id` bigint(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `access_token_permissions`
--

LOCK TABLES `access_token_permissions` WRITE;
/*!40000 ALTER TABLE `access_token_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `access_token_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `address`
--

DROP TABLE IF EXISTS `address`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `address` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `formatted` varchar(256) DEFAULT NULL,
  `street_address` varchar(256) DEFAULT NULL,
  `locality` varchar(256) DEFAULT NULL,
  `region` varchar(256) DEFAULT NULL,
  `postal_code` varchar(256) DEFAULT NULL,
  `country` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `address`
--

LOCK TABLES `address` WRITE;
/*!40000 ALTER TABLE `address` DISABLE KEYS */;
/*!40000 ALTER TABLE `address` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `approved_site`
--

DROP TABLE IF EXISTS `approved_site`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `approved_site` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_id` varchar(256) DEFAULT NULL,
  `client_id` varchar(256) DEFAULT NULL,
  `creation_date` timestamp NULL DEFAULT NULL,
  `access_date` timestamp NULL DEFAULT NULL,
  `timeout_date` timestamp NULL DEFAULT NULL,
  `whitelisted_site_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `approved_site`
--

LOCK TABLES `approved_site` WRITE;
/*!40000 ALTER TABLE `approved_site` DISABLE KEYS */;
INSERT INTO `approved_site` VALUES
(1,'admin','85e6f7a5-580b-4a1c-a6d2-39055143063d','2025-09-18 12:16:21','2025-09-25 08:36:37',NULL,NULL);
/*!40000 ALTER TABLE `approved_site` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `approved_site_scope`
--

DROP TABLE IF EXISTS `approved_site_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `approved_site_scope` (
  `owner_id` bigint(20) DEFAULT NULL,
  `scope` varchar(256) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `approved_site_scope`
--

LOCK TABLES `approved_site_scope` WRITE;
/*!40000 ALTER TABLE `approved_site_scope` DISABLE KEYS */;
INSERT INTO `approved_site_scope` VALUES
(1,'openid'),
(1,'profile');
/*!40000 ALTER TABLE `approved_site_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder`
--

DROP TABLE IF EXISTS `authentication_holder`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `authentication_holder` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_auth_id` bigint(20) DEFAULT NULL,
  `approved` tinyint(1) DEFAULT NULL,
  `redirect_uri` varchar(2048) DEFAULT NULL,
  `client_id` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=320 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder`
--

LOCK TABLES `authentication_holder` WRITE;
/*!40000 ALTER TABLE `authentication_holder` DISABLE KEYS */;
INSERT INTO `authentication_holder` VALUES
(37,NULL,1,NULL,'85e6f7a5-580b-4a1c-a6d2-39055143063d'),
(38,NULL,1,NULL,'11034667-5c50-4c9a-8f43-6a48090dced2');
/*!40000 ALTER TABLE `authentication_holder` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder_authority`
--

DROP TABLE IF EXISTS `authentication_holder_authority`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `authentication_holder_authority` (
  `owner_id` bigint(20) DEFAULT NULL,
  `authority` varchar(256) DEFAULT NULL,
  KEY `aha_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder_authority`
--

LOCK TABLES `authentication_holder_authority` WRITE;
/*!40000 ALTER TABLE `authentication_holder_authority` DISABLE KEYS */;
INSERT INTO `authentication_holder_authority` VALUES
(37,'ROLE_CLIENT'),
(38,'ROLE_CLIENT');
/*!40000 ALTER TABLE `authentication_holder_authority` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder_extension`
--

DROP TABLE IF EXISTS `authentication_holder_extension`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `authentication_holder_extension` (
  `owner_id` bigint(20) DEFAULT NULL,
  `extension` varchar(2048) DEFAULT NULL,
  `val` varchar(2048) DEFAULT NULL,
  KEY `ahe_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder_extension`
--

LOCK TABLES `authentication_holder_extension` WRITE;
/*!40000 ALTER TABLE `authentication_holder_extension` DISABLE KEYS */;
/*!40000 ALTER TABLE `authentication_holder_extension` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder_request_parameter`
--

DROP TABLE IF EXISTS `authentication_holder_request_parameter`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `authentication_holder_request_parameter` (
  `owner_id` bigint(20) DEFAULT NULL,
  `param` varchar(2048) DEFAULT NULL,
  `val` varchar(2048) DEFAULT NULL,
  KEY `ahrp_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder_request_parameter`
--

LOCK TABLES `authentication_holder_request_parameter` WRITE;
/*!40000 ALTER TABLE `authentication_holder_request_parameter` DISABLE KEYS */;
/*!40000 ALTER TABLE `authentication_holder_request_parameter` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder_resource_id`
--

DROP TABLE IF EXISTS `authentication_holder_resource_id`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `authentication_holder_resource_id` (
  `owner_id` bigint(20) DEFAULT NULL,
  `resource_id` varchar(2048) DEFAULT NULL,
  KEY `ahri_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder_resource_id`
--

LOCK TABLES `authentication_holder_resource_id` WRITE;
/*!40000 ALTER TABLE `authentication_holder_resource_id` DISABLE KEYS */;
/*!40000 ALTER TABLE `authentication_holder_resource_id` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder_response_type`
--

DROP TABLE IF EXISTS `authentication_holder_response_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `authentication_holder_response_type` (
  `owner_id` bigint(20) DEFAULT NULL,
  `response_type` varchar(2048) DEFAULT NULL,
  KEY `ahrt_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder_response_type`
--

LOCK TABLES `authentication_holder_response_type` WRITE;
/*!40000 ALTER TABLE `authentication_holder_response_type` DISABLE KEYS */;
/*!40000 ALTER TABLE `authentication_holder_response_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder_scope`
--

DROP TABLE IF EXISTS `authentication_holder_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `authentication_holder_scope` (
  `owner_id` bigint(20) DEFAULT NULL,
  `scope` varchar(2048) DEFAULT NULL,
  KEY `ahs_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder_scope`
--

LOCK TABLES `authentication_holder_scope` WRITE;
/*!40000 ALTER TABLE `authentication_holder_scope` DISABLE KEYS */;
INSERT INTO `authentication_holder_scope` VALUES
(37,'registration-token'),
(38,'registration-token');
/*!40000 ALTER TABLE `authentication_holder_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authorization_code`
--

DROP TABLE IF EXISTS `authorization_code`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `authorization_code` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `code` varchar(256) DEFAULT NULL,
  `auth_holder_id` bigint(20) DEFAULT NULL,
  `expiration` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ac_ahi_idx` (`auth_holder_id`)
) ENGINE=InnoDB AUTO_INCREMENT=140 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authorization_code`
--

LOCK TABLES `authorization_code` WRITE;
/*!40000 ALTER TABLE `authorization_code` DISABLE KEYS */;
/*!40000 ALTER TABLE `authorization_code` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `blacklisted_site`
--

DROP TABLE IF EXISTS `blacklisted_site`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `blacklisted_site` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `uri` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `blacklisted_site`
--

LOCK TABLES `blacklisted_site` WRITE;
/*!40000 ALTER TABLE `blacklisted_site` DISABLE KEYS */;
/*!40000 ALTER TABLE `blacklisted_site` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `claim`
--

DROP TABLE IF EXISTS `claim`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `claim` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(256) DEFAULT NULL,
  `friendly_name` varchar(1024) DEFAULT NULL,
  `claim_type` varchar(1024) DEFAULT NULL,
  `claim_value` varchar(1024) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `claim`
--

LOCK TABLES `claim` WRITE;
/*!40000 ALTER TABLE `claim` DISABLE KEYS */;
/*!40000 ALTER TABLE `claim` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `claim_issuer`
--

DROP TABLE IF EXISTS `claim_issuer`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `claim_issuer` (
  `owner_id` bigint(20) NOT NULL,
  `issuer` varchar(1024) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `claim_issuer`
--

LOCK TABLES `claim_issuer` WRITE;
/*!40000 ALTER TABLE `claim_issuer` DISABLE KEYS */;
/*!40000 ALTER TABLE `claim_issuer` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `claim_to_permission_ticket`
--

DROP TABLE IF EXISTS `claim_to_permission_ticket`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `claim_to_permission_ticket` (
  `permission_ticket_id` bigint(20) NOT NULL,
  `claim_id` bigint(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `claim_to_permission_ticket`
--

LOCK TABLES `claim_to_permission_ticket` WRITE;
/*!40000 ALTER TABLE `claim_to_permission_ticket` DISABLE KEYS */;
/*!40000 ALTER TABLE `claim_to_permission_ticket` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `claim_to_policy`
--

DROP TABLE IF EXISTS `claim_to_policy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `claim_to_policy` (
  `policy_id` bigint(20) NOT NULL,
  `claim_id` bigint(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `claim_to_policy`
--

LOCK TABLES `claim_to_policy` WRITE;
/*!40000 ALTER TABLE `claim_to_policy` DISABLE KEYS */;
/*!40000 ALTER TABLE `claim_to_policy` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `claim_token_format`
--

DROP TABLE IF EXISTS `claim_token_format`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `claim_token_format` (
  `owner_id` bigint(20) NOT NULL,
  `claim_token_format` varchar(1024) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `claim_token_format`
--

LOCK TABLES `claim_token_format` WRITE;
/*!40000 ALTER TABLE `claim_token_format` DISABLE KEYS */;
/*!40000 ALTER TABLE `claim_token_format` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_authority`
--

DROP TABLE IF EXISTS `client_authority`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_authority` (
  `owner_id` bigint(20) DEFAULT NULL,
  `authority` varchar(256) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_authority`
--

LOCK TABLES `client_authority` WRITE;
/*!40000 ALTER TABLE `client_authority` DISABLE KEYS */;
INSERT INTO `client_authority` VALUES
(2,'ROLE_CLIENT'),
(7,'ROLE_CLIENT'),
(8,'ROLE_CLIENT'),
(9,'ROLE_CLIENT');
/*!40000 ALTER TABLE `client_authority` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_claims_redirect_uri`
--

DROP TABLE IF EXISTS `client_claims_redirect_uri`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_claims_redirect_uri` (
  `owner_id` bigint(20) DEFAULT NULL,
  `redirect_uri` varchar(2048) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_claims_redirect_uri`
--

LOCK TABLES `client_claims_redirect_uri` WRITE;
/*!40000 ALTER TABLE `client_claims_redirect_uri` DISABLE KEYS */;
/*!40000 ALTER TABLE `client_claims_redirect_uri` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_contact`
--

DROP TABLE IF EXISTS `client_contact`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_contact` (
  `owner_id` bigint(20) DEFAULT NULL,
  `contact` varchar(256) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_contact`
--

LOCK TABLES `client_contact` WRITE;
/*!40000 ALTER TABLE `client_contact` DISABLE KEYS */;
INSERT INTO `client_contact` VALUES
(9,'admin@iam.test');
/*!40000 ALTER TABLE `client_contact` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_default_acr_value`
--

DROP TABLE IF EXISTS `client_default_acr_value`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_default_acr_value` (
  `owner_id` bigint(20) DEFAULT NULL,
  `default_acr_value` varchar(2000) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_default_acr_value`
--

LOCK TABLES `client_default_acr_value` WRITE;
/*!40000 ALTER TABLE `client_default_acr_value` DISABLE KEYS */;
/*!40000 ALTER TABLE `client_default_acr_value` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_details`
--

DROP TABLE IF EXISTS `client_details`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_details` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `client_description` varchar(1024) DEFAULT NULL,
  `reuse_refresh_tokens` tinyint(1) NOT NULL DEFAULT 1,
  `dynamically_registered` tinyint(1) NOT NULL DEFAULT 0,
  `allow_introspection` tinyint(1) NOT NULL DEFAULT 0,
  `id_token_validity_seconds` bigint(20) NOT NULL DEFAULT 600,
  `client_id` varchar(256) DEFAULT NULL,
  `client_secret` text DEFAULT NULL,
  `access_token_validity_seconds` bigint(20) DEFAULT NULL,
  `refresh_token_validity_seconds` bigint(20) DEFAULT NULL,
  `application_type` varchar(256) DEFAULT NULL,
  `client_name` varchar(256) DEFAULT NULL,
  `token_endpoint_auth_method` varchar(256) DEFAULT NULL,
  `subject_type` varchar(256) DEFAULT NULL,
  `logo_uri` text DEFAULT NULL,
  `policy_uri` text DEFAULT NULL,
  `client_uri` text DEFAULT NULL,
  `tos_uri` text DEFAULT NULL,
  `jwks_uri` text DEFAULT NULL,
  `jwks` text DEFAULT NULL,
  `sector_identifier_uri` text DEFAULT NULL,
  `request_object_signing_alg` varchar(256) DEFAULT NULL,
  `user_info_signed_response_alg` varchar(256) DEFAULT NULL,
  `user_info_encrypted_response_alg` varchar(256) DEFAULT NULL,
  `user_info_encrypted_response_enc` varchar(256) DEFAULT NULL,
  `id_token_signed_response_alg` varchar(256) DEFAULT NULL,
  `id_token_encrypted_response_alg` varchar(256) DEFAULT NULL,
  `id_token_encrypted_response_enc` varchar(256) DEFAULT NULL,
  `token_endpoint_auth_signing_alg` varchar(256) DEFAULT NULL,
  `default_max_age` bigint(20) DEFAULT NULL,
  `require_auth_time` tinyint(1) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `initiate_login_uri` varchar(2048) DEFAULT NULL,
  `clear_access_tokens_on_refresh` tinyint(1) NOT NULL DEFAULT 1,
  `software_statement` text DEFAULT NULL,
  `code_challenge_method` varchar(256) DEFAULT NULL,
  `software_id` text DEFAULT NULL,
  `software_version` text DEFAULT NULL,
  `device_code_validity_seconds` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `client_id` (`client_id`),
  KEY `cd_ci_idx` (`client_id`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_details`
--

LOCK TABLES `client_details` WRITE;
/*!40000 ALTER TABLE `client_details` DISABLE KEYS */;
INSERT INTO `client_details` VALUES
(2,NULL,0,0,1,600,'85e6f7a5-580b-4a1c-a6d2-39055143063d','AIYIneAVGs9PTVvQnxNGqDmh3rNTsyFOrrwRIqy1Zc6ngPN9hQe6I2VzDzN2uGLCPsvQI8nhYxf_V09NHk-yv7o',3600,2592000,NULL,'rucio','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2023-12-12 07:32:39',NULL,0,NULL,NULL,NULL,NULL,600),
(7,NULL,0,0,1,600,'9841f5c5-fb77-454c-a4a5-acd220e0faf2','ALORjpM78x3jvUzPZxJJw94Uu6tFu55dYf7NbQ97uNpbF-32Sxb0bprsUSqSrzWgZzLK64cqVlNwya6i3nvU_LU',3600,2592000,NULL,'web1','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2023-12-23 06:08:01',NULL,0,NULL,NULL,NULL,NULL,600),
(8,NULL,0,0,1,600,'d6dad80f-11f7-4cf4-a4ef-fbd081ec7f98','AJWL5JZtM6I2iaj7XHYq98kPGo6-8Wde2ScSHJhHNvCLeKppTj9fBmeq2xGWi3RCFlj6cPJFjz-BxXIBva4kDYo',3600,2592000,NULL,'fts3','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2024-01-11 15:15:44',NULL,0,NULL,NULL,NULL,NULL,600),
(9,NULL,0,0,1,600,'11034667-5c50-4c9a-8f43-6a48090dced2','eIcPpu5HbjuECyTVUB0iBAwPgIDEaJUm8T4xpsn5tyWH53CTxoG9cH2Vo6etYMWegPeWffdbrEPwwkOJZCHUgQ',3600,2592000,NULL,'rucio_scim','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2025-09-18 11:38:08',NULL,0,NULL,NULL,NULL,NULL,600);
/*!40000 ALTER TABLE `client_details` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_grant_type`
--

DROP TABLE IF EXISTS `client_grant_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_grant_type` (
  `owner_id` bigint(20) DEFAULT NULL,
  `grant_type` varchar(2000) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_grant_type`
--

LOCK TABLES `client_grant_type` WRITE;
/*!40000 ALTER TABLE `client_grant_type` DISABLE KEYS */;
INSERT INTO `client_grant_type` VALUES
(2,'client_credentials'),
(2,'urn:ietf:params:oauth:grant-type:token-exchange'),
(7,'authorization_code'),
(2,'refresh_token'),
(8,'client_credentials'),
(8,'refresh_token'),
(8,'urn:ietf:params:oauth:grant-type:token-exchange'),
(2,'password'),
(2,'implicit'),
(2,'authorization_code'),
(9,'client_credentials');
/*!40000 ALTER TABLE `client_grant_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_post_logout_redirect_uri`
--

DROP TABLE IF EXISTS `client_post_logout_redirect_uri`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_post_logout_redirect_uri` (
  `owner_id` bigint(20) DEFAULT NULL,
  `post_logout_redirect_uri` varchar(2000) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_post_logout_redirect_uri`
--

LOCK TABLES `client_post_logout_redirect_uri` WRITE;
/*!40000 ALTER TABLE `client_post_logout_redirect_uri` DISABLE KEYS */;
/*!40000 ALTER TABLE `client_post_logout_redirect_uri` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_redirect_uri`
--

DROP TABLE IF EXISTS `client_redirect_uri`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_redirect_uri` (
  `owner_id` bigint(20) DEFAULT NULL,
  `redirect_uri` varchar(2048) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_redirect_uri`
--

LOCK TABLES `client_redirect_uri` WRITE;
/*!40000 ALTER TABLE `client_redirect_uri` DISABLE KEYS */;
INSERT INTO `client_redirect_uri` VALUES
(7,'https://localhost:9000/oidc_redirect'),
(2,'https://rucio/auth/oidc_token'),
(9,'https://rucio/auth/oidc_token'),
(2,'https://rucio/auth/oidc_redirect'),
(2,'https://rucio/auth/oidc_code');
/*!40000 ALTER TABLE `client_redirect_uri` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_request_uri`
--

DROP TABLE IF EXISTS `client_request_uri`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_request_uri` (
  `owner_id` bigint(20) DEFAULT NULL,
  `request_uri` varchar(2000) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_request_uri`
--

LOCK TABLES `client_request_uri` WRITE;
/*!40000 ALTER TABLE `client_request_uri` DISABLE KEYS */;
/*!40000 ALTER TABLE `client_request_uri` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_resource`
--

DROP TABLE IF EXISTS `client_resource`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_resource` (
  `owner_id` bigint(20) DEFAULT NULL,
  `resource_id` varchar(256) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_resource`
--

LOCK TABLES `client_resource` WRITE;
/*!40000 ALTER TABLE `client_resource` DISABLE KEYS */;
/*!40000 ALTER TABLE `client_resource` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_response_type`
--

DROP TABLE IF EXISTS `client_response_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_response_type` (
  `owner_id` bigint(20) DEFAULT NULL,
  `response_type` varchar(2000) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_response_type`
--

LOCK TABLES `client_response_type` WRITE;
/*!40000 ALTER TABLE `client_response_type` DISABLE KEYS */;
/*!40000 ALTER TABLE `client_response_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_scope`
--

DROP TABLE IF EXISTS `client_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_scope` (
  `owner_id` bigint(20) DEFAULT NULL,
  `scope` varchar(2048) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_scope`
--

LOCK TABLES `client_scope` WRITE;
/*!40000 ALTER TABLE `client_scope` DISABLE KEYS */;
INSERT INTO `client_scope` VALUES
(2,'openid'),
(2,'profile'),
(2,'email'),
(2,'storage.read:/'),
(2,'storage.modify:/'),
(7,'openid'),
(7,'profile'),
(7,'email'),
(7,'web1'),
(2,'fts'),
(2,'offline_access'),
(8,'openid'),
(8,'profile'),
(8,'email'),
(8,'offline_access'),
(8,'storage.read:/'),
(8,'storage.modify:/'),
(2,'scim:read'),
(9,'address'),
(9,'phone'),
(9,'openid'),
(9,'profile'),
(9,'scim:read'),
(9,'email'),
(2,'ruciodev');
/*!40000 ALTER TABLE `client_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `device_code`
--

DROP TABLE IF EXISTS `device_code`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_code` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `device_code` varchar(1024) DEFAULT NULL,
  `user_code` varchar(1024) DEFAULT NULL,
  `expiration` timestamp NOT NULL DEFAULT current_timestamp(),
  `client_id` varchar(256) DEFAULT NULL,
  `approved` tinyint(1) DEFAULT NULL,
  `auth_holder_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `device_code`
--

LOCK TABLES `device_code` WRITE;
/*!40000 ALTER TABLE `device_code` DISABLE KEYS */;
/*!40000 ALTER TABLE `device_code` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `device_code_request_parameter`
--

DROP TABLE IF EXISTS `device_code_request_parameter`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_code_request_parameter` (
  `owner_id` bigint(20) DEFAULT NULL,
  `param` varchar(2048) DEFAULT NULL,
  `val` varchar(2048) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `device_code_request_parameter`
--

LOCK TABLES `device_code_request_parameter` WRITE;
/*!40000 ALTER TABLE `device_code_request_parameter` DISABLE KEYS */;
/*!40000 ALTER TABLE `device_code_request_parameter` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `device_code_scope`
--

DROP TABLE IF EXISTS `device_code_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_code_scope` (
  `owner_id` bigint(20) NOT NULL,
  `scope` varchar(256) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `device_code_scope`
--

LOCK TABLES `device_code_scope` WRITE;
/*!40000 ALTER TABLE `device_code_scope` DISABLE KEYS */;
/*!40000 ALTER TABLE `device_code_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account`
--

DROP TABLE IF EXISTS `iam_account`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_account` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `active` tinyint(1) NOT NULL DEFAULT 0,
  `CREATIONTIME` datetime NOT NULL,
  `LASTUPDATETIME` datetime NOT NULL,
  `PASSWORD` varchar(128) DEFAULT NULL,
  `USERNAME` varchar(128) NOT NULL,
  `UUID` varchar(36) NOT NULL,
  `user_info_id` bigint(20) DEFAULT NULL,
  `confirmation_key` varchar(36) DEFAULT NULL,
  `reset_key` varchar(36) DEFAULT NULL,
  `provisioned` tinyint(1) NOT NULL DEFAULT 0,
  `last_login_time` datetime DEFAULT NULL,
  `end_time` datetime DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `USERNAME` (`USERNAME`),
  UNIQUE KEY `UUID` (`UUID`),
  KEY `FK_iam_account_user_info_id` (`user_info_id`),
  KEY `ia_ct_idx` (`CREATIONTIME`),
  KEY `ia_lut_idx` (`LASTUPDATETIME`),
  KEY `ia_llt_idx` (`last_login_time`),
  KEY `ia_et_idx` (`end_time`),
  CONSTRAINT `FK_iam_account_user_info_id` FOREIGN KEY (`user_info_id`) REFERENCES `iam_user_info` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account`
--

LOCK TABLES `iam_account` WRITE;
/*!40000 ALTER TABLE `iam_account` DISABLE KEYS */;
INSERT INTO `iam_account` VALUES
(1,1,'2023-12-12 09:27:37','2023-12-12 09:27:37','$2a$10$LRFsDuz9axhOskRfNH5jR.cyUpP463400pY5S6BDelKakdzI6mJ9W','admin','73f16d93-2441-4a50-88ff-85360d78c6b5',1,NULL,NULL,0,'2025-09-25 10:36:36',NULL);
/*!40000 ALTER TABLE `iam_account` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account_attrs`
--

DROP TABLE IF EXISTS `iam_account_attrs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_account_attrs` (
  `NAME` varchar(64) NOT NULL,
  `val` varchar(256) DEFAULT NULL,
  `account_id` bigint(20) DEFAULT NULL,
  KEY `INDEX_iam_account_attrs_name` (`NAME`),
  KEY `INDEX_iam_account_attrs_name_val` (`NAME`,`val`),
  KEY `FK_iam_account_attrs_account_id` (`account_id`),
  CONSTRAINT `FK_iam_account_attrs_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account_attrs`
--

LOCK TABLES `iam_account_attrs` WRITE;
/*!40000 ALTER TABLE `iam_account_attrs` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_account_attrs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account_authority`
--

DROP TABLE IF EXISTS `iam_account_authority`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_account_authority` (
  `account_id` bigint(20) NOT NULL,
  `authority_id` bigint(20) NOT NULL,
  PRIMARY KEY (`account_id`,`authority_id`),
  KEY `FK_iam_account_authority_authority_id` (`authority_id`),
  CONSTRAINT `FK_iam_account_authority_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_account_authority_authority_id` FOREIGN KEY (`authority_id`) REFERENCES `iam_authority` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account_authority`
--

LOCK TABLES `iam_account_authority` WRITE;
/*!40000 ALTER TABLE `iam_account_authority` DISABLE KEYS */;
INSERT INTO `iam_account_authority` VALUES
(1,1),
(1,2);
/*!40000 ALTER TABLE `iam_account_authority` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account_client`
--

DROP TABLE IF EXISTS `iam_account_client`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_account_client` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `creation_time` datetime NOT NULL,
  `account_id` bigint(20) NOT NULL,
  `client_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UNQ_iam_account_client_0` (`account_id`,`client_id`),
  KEY `FK_iam_account_client_client_id` (`client_id`),
  CONSTRAINT `FK_iam_account_client_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_account_client_client_id` FOREIGN KEY (`client_id`) REFERENCES `client_details` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account_client`
--

LOCK TABLES `iam_account_client` WRITE;
/*!40000 ALTER TABLE `iam_account_client` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_account_client` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account_group`
--

DROP TABLE IF EXISTS `iam_account_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_account_group` (
  `account_id` bigint(20) NOT NULL,
  `group_id` bigint(20) NOT NULL,
  `creation_time` datetime DEFAULT NULL,
  `end_time` datetime DEFAULT NULL,
  PRIMARY KEY (`account_id`,`group_id`),
  KEY `FK_iam_account_group_group_id` (`group_id`),
  CONSTRAINT `FK_iam_account_group_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_account_group_group_id` FOREIGN KEY (`group_id`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account_group`
--

LOCK TABLES `iam_account_group` WRITE;
/*!40000 ALTER TABLE `iam_account_group` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_account_group` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account_labels`
--

DROP TABLE IF EXISTS `iam_account_labels`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_account_labels` (
  `NAME` varchar(64) NOT NULL,
  `PREFIX` varchar(256) DEFAULT NULL,
  `val` varchar(64) DEFAULT NULL,
  `account_id` bigint(20) DEFAULT NULL,
  KEY `INDEX_iam_account_labels_prefix_name_val` (`PREFIX`,`NAME`,`val`),
  KEY `INDEX_iam_account_labels_prefix_name` (`PREFIX`,`NAME`),
  KEY `FK_iam_account_labels_account_id` (`account_id`),
  CONSTRAINT `FK_iam_account_labels_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account_labels`
--

LOCK TABLES `iam_account_labels` WRITE;
/*!40000 ALTER TABLE `iam_account_labels` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_account_labels` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_address`
--

DROP TABLE IF EXISTS `iam_address`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_address` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `COUNTRY` varchar(2) DEFAULT NULL,
  `FORMATTED` varchar(128) DEFAULT NULL,
  `LOCALITY` varchar(128) DEFAULT NULL,
  `POSTALCODE` varchar(16) DEFAULT NULL,
  `REGION` varchar(128) DEFAULT NULL,
  `STREETADDRESS` varchar(128) DEFAULT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_address`
--

LOCK TABLES `iam_address` WRITE;
/*!40000 ALTER TABLE `iam_address` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_address` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_aup`
--

DROP TABLE IF EXISTS `iam_aup`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_aup` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `creation_time` datetime NOT NULL,
  `description` varchar(128) DEFAULT NULL,
  `last_update_time` datetime NOT NULL,
  `name` varchar(36) NOT NULL,
  `sig_validity_days` bigint(20) NOT NULL,
  `text` longtext DEFAULT NULL,
  `url` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_aup`
--

LOCK TABLES `iam_aup` WRITE;
/*!40000 ALTER TABLE `iam_aup` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_aup` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_aup_signature`
--

DROP TABLE IF EXISTS `iam_aup_signature`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_aup_signature` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `signature_time` datetime NOT NULL,
  `account_id` bigint(20) DEFAULT NULL,
  `aup_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UNQ_iam_aup_signature_0` (`aup_id`,`account_id`),
  KEY `FK_iam_aup_signature_account_id` (`account_id`),
  CONSTRAINT `FK_iam_aup_signature_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_aup_signature_aup_id` FOREIGN KEY (`aup_id`) REFERENCES `iam_aup` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_aup_signature`
--

LOCK TABLES `iam_aup_signature` WRITE;
/*!40000 ALTER TABLE `iam_aup_signature` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_aup_signature` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_authority`
--

DROP TABLE IF EXISTS `iam_authority`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_authority` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `auth` varchar(128) NOT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `auth` (`auth`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_authority`
--

LOCK TABLES `iam_authority` WRITE;
/*!40000 ALTER TABLE `iam_authority` DISABLE KEYS */;
INSERT INTO `iam_authority` VALUES
(1,'ROLE_ADMIN'),
(3,'ROLE_PRE_AUTHENTICATED'),
(2,'ROLE_USER');
/*!40000 ALTER TABLE `iam_authority` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_email_notification`
--

DROP TABLE IF EXISTS `iam_email_notification`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_email_notification` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `UUID` varchar(36) NOT NULL,
  `NOTIFICATION_TYPE` varchar(128) NOT NULL,
  `SUBJECT` varchar(128) DEFAULT NULL,
  `BODY` text DEFAULT NULL,
  `CREATION_TIME` timestamp NOT NULL DEFAULT current_timestamp(),
  `DELIVERY_STATUS` varchar(128) DEFAULT NULL,
  `LAST_UPDATE` timestamp NULL DEFAULT NULL,
  `REQUEST_ID` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UUID` (`UUID`),
  KEY `FK_iam_email_notification_request_id` (`REQUEST_ID`),
  CONSTRAINT `FK_iam_email_notification_request_id` FOREIGN KEY (`REQUEST_ID`) REFERENCES `iam_reg_request` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_email_notification`
--

LOCK TABLES `iam_email_notification` WRITE;
/*!40000 ALTER TABLE `iam_email_notification` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_email_notification` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_exchange_policy`
--

DROP TABLE IF EXISTS `iam_exchange_policy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_exchange_policy` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `creation_time` datetime NOT NULL,
  `description` varchar(512) DEFAULT NULL,
  `last_update_time` datetime NOT NULL,
  `rule` varchar(6) NOT NULL,
  `dest_m_param` varchar(256) DEFAULT NULL,
  `dest_m_type` varchar(8) NOT NULL,
  `origin_m_param` varchar(256) DEFAULT NULL,
  `origin_m_type` varchar(8) NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_exchange_policy`
--

LOCK TABLES `iam_exchange_policy` WRITE;
/*!40000 ALTER TABLE `iam_exchange_policy` DISABLE KEYS */;
INSERT INTO `iam_exchange_policy` VALUES
(1,'2023-12-12 09:27:41','Allow all exchanges','2023-12-12 09:27:41','PERMIT',NULL,'ANY',NULL,'ANY');
/*!40000 ALTER TABLE `iam_exchange_policy` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_exchange_scope_policies`
--

DROP TABLE IF EXISTS `iam_exchange_scope_policies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_exchange_scope_policies` (
  `param` varchar(256) DEFAULT NULL,
  `rule` varchar(6) NOT NULL,
  `type` varchar(6) NOT NULL,
  `exchange_policy_id` bigint(20) DEFAULT NULL,
  KEY `FK_iam_exchange_scope_policies_exchange_policy_id` (`exchange_policy_id`),
  CONSTRAINT `FK_iam_exchange_scope_policies_exchange_policy_id` FOREIGN KEY (`exchange_policy_id`) REFERENCES `iam_exchange_policy` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_exchange_scope_policies`
--

LOCK TABLES `iam_exchange_scope_policies` WRITE;
/*!40000 ALTER TABLE `iam_exchange_scope_policies` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_exchange_scope_policies` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_ext_authn`
--

DROP TABLE IF EXISTS `iam_ext_authn`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_ext_authn` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `authentication_time` datetime NOT NULL,
  `expiration_time` datetime NOT NULL,
  `saved_authn_id` bigint(20) DEFAULT NULL,
  `type` varchar(32) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `saved_authn_id` (`saved_authn_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_ext_authn`
--

LOCK TABLES `iam_ext_authn` WRITE;
/*!40000 ALTER TABLE `iam_ext_authn` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_ext_authn` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_ext_authn_attr`
--

DROP TABLE IF EXISTS `iam_ext_authn_attr`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_ext_authn_attr` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `value` varchar(512) NOT NULL,
  `details_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FK_iam_ext_authn_attr_details_id` (`details_id`),
  CONSTRAINT `FK_iam_ext_authn_attr_details_id` FOREIGN KEY (`details_id`) REFERENCES `iam_ext_authn` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_ext_authn_attr`
--

LOCK TABLES `iam_ext_authn_attr` WRITE;
/*!40000 ALTER TABLE `iam_ext_authn_attr` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_ext_authn_attr` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_group`
--

DROP TABLE IF EXISTS `iam_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_group` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `CREATIONTIME` datetime NOT NULL,
  `DESCRIPTION` varchar(512) DEFAULT NULL,
  `LASTUPDATETIME` datetime NOT NULL,
  `name` varchar(512) NOT NULL,
  `UUID` varchar(36) NOT NULL,
  `parent_group_id` bigint(20) DEFAULT NULL,
  `default_group` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `NAME` (`name`),
  UNIQUE KEY `UUID` (`UUID`),
  KEY `FK_iam_group_parent_id` (`parent_group_id`),
  CONSTRAINT `FK_iam_group_parent_id` FOREIGN KEY (`parent_group_id`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_group`
--

LOCK TABLES `iam_group` WRITE;
/*!40000 ALTER TABLE `iam_group` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_group` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_group_attrs`
--

DROP TABLE IF EXISTS `iam_group_attrs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_group_attrs` (
  `NAME` varchar(64) NOT NULL,
  `val` varchar(256) DEFAULT NULL,
  `group_id` bigint(20) DEFAULT NULL,
  KEY `INDEX_iam_group_attrs_name` (`NAME`),
  KEY `INDEX_iam_group_attrs_name_val` (`NAME`,`val`),
  KEY `FK_iam_group_attrs_group_id` (`group_id`),
  CONSTRAINT `FK_iam_group_attrs_group_id` FOREIGN KEY (`group_id`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_group_attrs`
--

LOCK TABLES `iam_group_attrs` WRITE;
/*!40000 ALTER TABLE `iam_group_attrs` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_group_attrs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_group_labels`
--

DROP TABLE IF EXISTS `iam_group_labels`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_group_labels` (
  `NAME` varchar(64) NOT NULL,
  `PREFIX` varchar(256) DEFAULT NULL,
  `val` varchar(64) DEFAULT NULL,
  `group_id` bigint(20) DEFAULT NULL,
  KEY `INDEX_iam_group_labels_prefix_name_val` (`PREFIX`,`NAME`,`val`),
  KEY `INDEX_iam_group_labels_prefix_name` (`PREFIX`,`NAME`),
  KEY `FK_iam_group_labels_group_id` (`group_id`),
  CONSTRAINT `FK_iam_group_labels_group_id` FOREIGN KEY (`group_id`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_group_labels`
--

LOCK TABLES `iam_group_labels` WRITE;
/*!40000 ALTER TABLE `iam_group_labels` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_group_labels` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_group_request`
--

DROP TABLE IF EXISTS `iam_group_request`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_group_request` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `UUID` varchar(36) NOT NULL,
  `ACCOUNT_ID` bigint(20) DEFAULT NULL,
  `GROUP_ID` bigint(20) DEFAULT NULL,
  `STATUS` varchar(50) DEFAULT NULL,
  `NOTES` text DEFAULT NULL,
  `MOTIVATION` text DEFAULT NULL,
  `CREATIONTIME` timestamp NOT NULL DEFAULT current_timestamp(),
  `LASTUPDATETIME` timestamp NULL DEFAULT '1999-12-31 23:00:00',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UUID` (`UUID`),
  KEY `FK_iam_group_request_account_id` (`ACCOUNT_ID`),
  KEY `FK_iam_group_request_group_id` (`GROUP_ID`),
  CONSTRAINT `FK_iam_group_request_account_id` FOREIGN KEY (`ACCOUNT_ID`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_group_request_group_id` FOREIGN KEY (`GROUP_ID`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_group_request`
--

LOCK TABLES `iam_group_request` WRITE;
/*!40000 ALTER TABLE `iam_group_request` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_group_request` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_notification_receiver`
--

DROP TABLE IF EXISTS `iam_notification_receiver`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_notification_receiver` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `NOTIFICATION_ID` bigint(20) DEFAULT NULL,
  `EMAIL_ADDRESS` varchar(254) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `FK_iam_notification_receiver_notification_id` (`NOTIFICATION_ID`),
  CONSTRAINT `FK_iam_notification_receiver_notification_id` FOREIGN KEY (`NOTIFICATION_ID`) REFERENCES `iam_email_notification` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_notification_receiver`
--

LOCK TABLES `iam_notification_receiver` WRITE;
/*!40000 ALTER TABLE `iam_notification_receiver` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_notification_receiver` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_oidc_id`
--

DROP TABLE IF EXISTS `iam_oidc_id`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_oidc_id` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `ISSUER` varchar(256) NOT NULL,
  `SUBJECT` varchar(256) NOT NULL,
  `account_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `FK_iam_oidc_id_account_id` (`account_id`),
  CONSTRAINT `FK_iam_oidc_id_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_oidc_id`
--

LOCK TABLES `iam_oidc_id` WRITE;
/*!40000 ALTER TABLE `iam_oidc_id` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_oidc_id` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_reg_request`
--

DROP TABLE IF EXISTS `iam_reg_request`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_reg_request` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `UUID` varchar(36) NOT NULL,
  `CREATIONTIME` timestamp NOT NULL DEFAULT current_timestamp(),
  `ACCOUNT_ID` bigint(20) DEFAULT NULL,
  `STATUS` varchar(50) DEFAULT NULL,
  `LASTUPDATETIME` timestamp NULL DEFAULT NULL,
  `notes` text DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UUID` (`UUID`),
  KEY `FK_iam_reg_request_account_id` (`ACCOUNT_ID`),
  CONSTRAINT `FK_iam_reg_request_account_id` FOREIGN KEY (`ACCOUNT_ID`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_reg_request`
--

LOCK TABLES `iam_reg_request` WRITE;
/*!40000 ALTER TABLE `iam_reg_request` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_reg_request` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_reg_request_labels`
--

DROP TABLE IF EXISTS `iam_reg_request_labels`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_reg_request_labels` (
  `NAME` varchar(64) NOT NULL,
  `PREFIX` varchar(256) DEFAULT NULL,
  `val` varchar(64) DEFAULT NULL,
  `request_id` bigint(20) DEFAULT NULL,
  KEY `INDEX_iam_reg_request_labels_prefix_name_val` (`PREFIX`,`NAME`,`val`),
  KEY `INDEX_iam_reg_request_labels_prefix_name` (`PREFIX`,`NAME`),
  KEY `FK_iam_reg_request_labels_request_id` (`request_id`),
  CONSTRAINT `FK_iam_reg_request_labels_request_id` FOREIGN KEY (`request_id`) REFERENCES `iam_reg_request` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_reg_request_labels`
--

LOCK TABLES `iam_reg_request_labels` WRITE;
/*!40000 ALTER TABLE `iam_reg_request_labels` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_reg_request_labels` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_saml_id`
--

DROP TABLE IF EXISTS `iam_saml_id`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_saml_id` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `IDPID` varchar(256) NOT NULL,
  `USERID` varchar(256) NOT NULL,
  `account_id` bigint(20) DEFAULT NULL,
  `attribute_id` varchar(256) NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `FK_iam_saml_id_account_id` (`account_id`),
  KEY `IDX_IAM_SAML_ID_1` (`IDPID`,`attribute_id`,`USERID`),
  CONSTRAINT `FK_iam_saml_id_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_saml_id`
--

LOCK TABLES `iam_saml_id` WRITE;
/*!40000 ALTER TABLE `iam_saml_id` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_saml_id` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_scope_policy`
--

DROP TABLE IF EXISTS `iam_scope_policy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_scope_policy` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `creation_time` datetime NOT NULL,
  `description` varchar(512) DEFAULT NULL,
  `last_update_time` datetime NOT NULL,
  `rule` varchar(6) NOT NULL,
  `account_id` bigint(20) DEFAULT NULL,
  `group_id` bigint(20) DEFAULT NULL,
  `matching_policy` varchar(6) NOT NULL DEFAULT 'EQ',
  PRIMARY KEY (`ID`),
  KEY `FK_iam_scope_policy_group_id` (`group_id`),
  KEY `FK_iam_scope_policy_account_id` (`account_id`),
  CONSTRAINT `FK_iam_scope_policy_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_scope_policy_group_id` FOREIGN KEY (`group_id`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_scope_policy`
--

LOCK TABLES `iam_scope_policy` WRITE;
/*!40000 ALTER TABLE `iam_scope_policy` DISABLE KEYS */;
INSERT INTO `iam_scope_policy` VALUES
(1,'2023-12-12 09:27:38','Default Permit ALL policy','2023-12-12 09:27:38','PERMIT',NULL,NULL,'EQ');
/*!40000 ALTER TABLE `iam_scope_policy` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_scope_policy_scope`
--

DROP TABLE IF EXISTS `iam_scope_policy_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_scope_policy_scope` (
  `policy_id` bigint(20) DEFAULT NULL,
  `scope` varchar(256) DEFAULT NULL,
  UNIQUE KEY `INDEX_iam_scope_policy_scope_policy_id_scope` (`policy_id`,`scope`),
  KEY `INDEX_iam_scope_policy_scope_scope` (`scope`),
  CONSTRAINT `FK_iam_scope_policy_scope_policy_id` FOREIGN KEY (`policy_id`) REFERENCES `iam_scope_policy` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_scope_policy_scope`
--

LOCK TABLES `iam_scope_policy_scope` WRITE;
/*!40000 ALTER TABLE `iam_scope_policy_scope` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_scope_policy_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_ssh_key`
--

DROP TABLE IF EXISTS `iam_ssh_key`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_ssh_key` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `fingerprint` varchar(48) NOT NULL,
  `LABEL` varchar(36) NOT NULL,
  `is_primary` tinyint(1) DEFAULT 0,
  `val` longtext DEFAULT NULL,
  `ACCOUNT_ID` bigint(20) DEFAULT NULL,
  `creation_time` datetime NOT NULL,
  `last_update_time` datetime NOT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `fingerprint` (`fingerprint`),
  KEY `FK_iam_ssh_key_ACCOUNT_ID` (`ACCOUNT_ID`),
  CONSTRAINT `FK_iam_ssh_key_ACCOUNT_ID` FOREIGN KEY (`ACCOUNT_ID`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_ssh_key`
--

LOCK TABLES `iam_ssh_key` WRITE;
/*!40000 ALTER TABLE `iam_ssh_key` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_ssh_key` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_totp_mfa`
--

DROP TABLE IF EXISTS `iam_totp_mfa`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_totp_mfa` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `active` tinyint(1) NOT NULL DEFAULT 0,
  `secret` varchar(255) NOT NULL,
  `creation_time` datetime NOT NULL,
  `last_update_time` datetime NOT NULL,
  `ACCOUNT_ID` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `FK_iam_totp_mfa_account_id` (`ACCOUNT_ID`),
  CONSTRAINT `FK_iam_totp_mfa_account_id` FOREIGN KEY (`ACCOUNT_ID`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_totp_mfa`
--

LOCK TABLES `iam_totp_mfa` WRITE;
/*!40000 ALTER TABLE `iam_totp_mfa` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_totp_mfa` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_totp_recovery_code`
--

DROP TABLE IF EXISTS `iam_totp_recovery_code`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_totp_recovery_code` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `code` varchar(255) NOT NULL,
  `totp_mfa_id` bigint(20) NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `FK_iam_totp_recovery_code_totp_mfa_id` (`totp_mfa_id`),
  CONSTRAINT `FK_iam_totp_recovery_code_totp_mfa_id` FOREIGN KEY (`totp_mfa_id`) REFERENCES `iam_totp_mfa` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_totp_recovery_code`
--

LOCK TABLES `iam_totp_recovery_code` WRITE;
/*!40000 ALTER TABLE `iam_totp_recovery_code` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_totp_recovery_code` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_user_info`
--

DROP TABLE IF EXISTS `iam_user_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_user_info` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `BIRTHDATE` varchar(255) DEFAULT NULL,
  `EMAIL` varchar(128) NOT NULL,
  `EMAILVERIFIED` tinyint(1) DEFAULT 0,
  `FAMILYNAME` varchar(64) NOT NULL,
  `GENDER` varchar(255) DEFAULT NULL,
  `GIVENNAME` varchar(64) NOT NULL,
  `LOCALE` varchar(255) DEFAULT NULL,
  `MIDDLENAME` varchar(64) DEFAULT NULL,
  `NICKNAME` varchar(255) DEFAULT NULL,
  `PHONENUMBER` varchar(255) DEFAULT NULL,
  `PHONENUMBERVERIFIED` tinyint(1) DEFAULT 0,
  `PICTURE` varchar(255) DEFAULT NULL,
  `PROFILE` varchar(255) DEFAULT NULL,
  `WEBSITE` varchar(255) DEFAULT NULL,
  `ZONEINFO` varchar(255) DEFAULT NULL,
  `ADDRESS_ID` bigint(20) DEFAULT NULL,
  `DTYPE` varchar(31) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `iui_em_idx` (`EMAIL`),
  KEY `iui_gn_fn_idx` (`GIVENNAME`,`FAMILYNAME`),
  KEY `FK_iam_user_info_address_id` (`ADDRESS_ID`),
  CONSTRAINT `FK_iam_user_info_address_id` FOREIGN KEY (`ADDRESS_ID`) REFERENCES `iam_address` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_user_info`
--

LOCK TABLES `iam_user_info` WRITE;
/*!40000 ALTER TABLE `iam_user_info` DISABLE KEYS */;
INSERT INTO `iam_user_info` VALUES
(1,NULL,'admin@iam.test',1,'User',NULL,'Admin',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL);
/*!40000 ALTER TABLE `iam_user_info` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_x509_cert`
--

DROP TABLE IF EXISTS `iam_x509_cert`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_x509_cert` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `subject_dn` varchar(256) DEFAULT NULL,
  `LABEL` varchar(36) NOT NULL,
  `is_primary` tinyint(1) DEFAULT 0,
  `ACCOUNT_ID` bigint(20) DEFAULT NULL,
  `CERTIFICATE` text DEFAULT NULL,
  `issuer_dn` varchar(256) DEFAULT NULL,
  `creation_time` datetime NOT NULL,
  `last_update_time` datetime NOT NULL,
  `proxy_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `subject_dn` (`subject_dn`),
  UNIQUE KEY `idx_iam_x509_cert_cerificate` (`CERTIFICATE`(256)),
  KEY `FK_iam_x509_cert_ACCOUNT_ID` (`ACCOUNT_ID`),
  KEY `FK_iam_x509_cert_proxy_id` (`proxy_id`),
  CONSTRAINT `FK_iam_x509_cert_ACCOUNT_ID` FOREIGN KEY (`ACCOUNT_ID`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_x509_cert_proxy_id` FOREIGN KEY (`proxy_id`) REFERENCES `iam_x509_proxy` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_x509_cert`
--

LOCK TABLES `iam_x509_cert` WRITE;
/*!40000 ALTER TABLE `iam_x509_cert` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_x509_cert` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_x509_proxy`
--

DROP TABLE IF EXISTS `iam_x509_proxy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_x509_proxy` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `CHAIN` longtext NOT NULL,
  `exp_time` datetime NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_IAM_X509_PXY_EXP_T` (`exp_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_x509_proxy`
--

LOCK TABLES `iam_x509_proxy` WRITE;
/*!40000 ALTER TABLE `iam_x509_proxy` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_x509_proxy` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `pairwise_identifier`
--

DROP TABLE IF EXISTS `pairwise_identifier`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `pairwise_identifier` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `identifier` varchar(256) DEFAULT NULL,
  `sub` varchar(256) DEFAULT NULL,
  `sector_identifier` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pairwise_identifier`
--

LOCK TABLES `pairwise_identifier` WRITE;
/*!40000 ALTER TABLE `pairwise_identifier` DISABLE KEYS */;
/*!40000 ALTER TABLE `pairwise_identifier` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `permission`
--

DROP TABLE IF EXISTS `permission`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `permission` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `resource_set_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `permission`
--

LOCK TABLES `permission` WRITE;
/*!40000 ALTER TABLE `permission` DISABLE KEYS */;
/*!40000 ALTER TABLE `permission` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `permission_scope`
--

DROP TABLE IF EXISTS `permission_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `permission_scope` (
  `owner_id` bigint(20) NOT NULL,
  `scope` varchar(256) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `permission_scope`
--

LOCK TABLES `permission_scope` WRITE;
/*!40000 ALTER TABLE `permission_scope` DISABLE KEYS */;
/*!40000 ALTER TABLE `permission_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `permission_ticket`
--

DROP TABLE IF EXISTS `permission_ticket`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `permission_ticket` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `ticket` varchar(256) NOT NULL,
  `permission_id` bigint(20) NOT NULL,
  `expiration` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `permission_ticket`
--

LOCK TABLES `permission_ticket` WRITE;
/*!40000 ALTER TABLE `permission_ticket` DISABLE KEYS */;
/*!40000 ALTER TABLE `permission_ticket` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `policy`
--

DROP TABLE IF EXISTS `policy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `policy` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) DEFAULT NULL,
  `resource_set_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `policy`
--

LOCK TABLES `policy` WRITE;
/*!40000 ALTER TABLE `policy` DISABLE KEYS */;
/*!40000 ALTER TABLE `policy` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `policy_scope`
--

DROP TABLE IF EXISTS `policy_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `policy_scope` (
  `owner_id` bigint(20) NOT NULL,
  `scope` varchar(256) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `policy_scope`
--

LOCK TABLES `policy_scope` WRITE;
/*!40000 ALTER TABLE `policy_scope` DISABLE KEYS */;
/*!40000 ALTER TABLE `policy_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `refresh_token`
--

DROP TABLE IF EXISTS `refresh_token`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `refresh_token` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `token_value` varchar(4096) DEFAULT NULL,
  `expiration` timestamp NULL DEFAULT NULL,
  `auth_holder_id` bigint(20) DEFAULT NULL,
  `client_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `rf_ahi_idx` (`auth_holder_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `refresh_token`
--

LOCK TABLES `refresh_token` WRITE;
/*!40000 ALTER TABLE `refresh_token` DISABLE KEYS */;
/*!40000 ALTER TABLE `refresh_token` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `resource_set`
--

DROP TABLE IF EXISTS `resource_set`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `resource_set` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) NOT NULL,
  `uri` varchar(1024) DEFAULT NULL,
  `icon_uri` varchar(1024) DEFAULT NULL,
  `rs_type` varchar(256) DEFAULT NULL,
  `owner` varchar(256) NOT NULL,
  `client_id` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `resource_set`
--

LOCK TABLES `resource_set` WRITE;
/*!40000 ALTER TABLE `resource_set` DISABLE KEYS */;
/*!40000 ALTER TABLE `resource_set` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `resource_set_scope`
--

DROP TABLE IF EXISTS `resource_set_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `resource_set_scope` (
  `owner_id` bigint(20) NOT NULL,
  `scope` varchar(256) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `resource_set_scope`
--

LOCK TABLES `resource_set_scope` WRITE;
/*!40000 ALTER TABLE `resource_set_scope` DISABLE KEYS */;
/*!40000 ALTER TABLE `resource_set_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `saved_registered_client`
--

DROP TABLE IF EXISTS `saved_registered_client`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `saved_registered_client` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `issuer` varchar(1024) DEFAULT NULL,
  `registered_client` varchar(8192) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `saved_registered_client`
--

LOCK TABLES `saved_registered_client` WRITE;
/*!40000 ALTER TABLE `saved_registered_client` DISABLE KEYS */;
/*!40000 ALTER TABLE `saved_registered_client` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `saved_user_auth`
--

DROP TABLE IF EXISTS `saved_user_auth`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `saved_user_auth` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) DEFAULT NULL,
  `authenticated` tinyint(1) DEFAULT NULL,
  `source_class` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=286 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `saved_user_auth`
--

LOCK TABLES `saved_user_auth` WRITE;
/*!40000 ALTER TABLE `saved_user_auth` DISABLE KEYS */;
/*!40000 ALTER TABLE `saved_user_auth` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `saved_user_auth_authority`
--

DROP TABLE IF EXISTS `saved_user_auth_authority`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `saved_user_auth_authority` (
  `owner_id` bigint(20) DEFAULT NULL,
  `authority` varchar(256) DEFAULT NULL,
  KEY `suaa_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `saved_user_auth_authority`
--

LOCK TABLES `saved_user_auth_authority` WRITE;
/*!40000 ALTER TABLE `saved_user_auth_authority` DISABLE KEYS */;
/*!40000 ALTER TABLE `saved_user_auth_authority` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `saved_user_auth_info`
--

DROP TABLE IF EXISTS `saved_user_auth_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `saved_user_auth_info` (
  `owner_id` bigint(20) DEFAULT NULL,
  `info_key` varchar(256) DEFAULT NULL,
  `info_val` varchar(256) DEFAULT NULL,
  UNIQUE KEY `owner_id` (`owner_id`,`info_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `saved_user_auth_info`
--

LOCK TABLES `saved_user_auth_info` WRITE;
/*!40000 ALTER TABLE `saved_user_auth_info` DISABLE KEYS */;
/*!40000 ALTER TABLE `saved_user_auth_info` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `schema_version`
--

DROP TABLE IF EXISTS `schema_version`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `schema_version` (
  `installed_rank` int(11) NOT NULL,
  `version` varchar(50) DEFAULT NULL,
  `description` varchar(200) NOT NULL,
  `type` varchar(20) NOT NULL,
  `script` varchar(1000) NOT NULL,
  `checksum` int(11) DEFAULT NULL,
  `installed_by` varchar(100) NOT NULL,
  `installed_on` timestamp NOT NULL DEFAULT current_timestamp(),
  `execution_time` int(11) NOT NULL,
  `success` tinyint(1) NOT NULL,
  PRIMARY KEY (`installed_rank`),
  KEY `schema_version_s_idx` (`success`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `schema_version`
--

LOCK TABLES `schema_version` WRITE;
/*!40000 ALTER TABLE `schema_version` DISABLE KEYS */;
INSERT INTO `schema_version` VALUES
(1,'1',' init','SQL','V1___init.sql',-673105977,'indigoiam','2023-12-12 08:27:37',1196,1),
(2,'2',' iam tables','SQL','V2___iam_tables.sql',916872168,'indigoiam','2023-12-12 08:27:37',465,1),
(3,'3',' basic configuration','SQL','V3___basic_configuration.sql',1293553913,'indigoiam','2023-12-12 08:27:37',16,1),
(4,'4',' x509 updates','SQL','V4___x509_updates.sql',803590936,'indigoiam','2023-12-12 08:27:37',16,1),
(5,'5',' registration request','SQL','V5___registration_request.sql',844204664,'indigoiam','2023-12-12 08:27:37',65,1),
(6,'6',' remove wrong constraints','SQL','V6___remove_wrong_constraints.sql',2003434964,'indigoiam','2023-12-12 08:27:37',26,1),
(7,'7',' notification tables','SQL','V7___notification_tables.sql',-1136933843,'indigoiam','2023-12-12 08:27:37',126,1),
(8,'8',' mitre update','SQL','V8___mitre_update.sql',608617254,'indigoiam','2023-12-12 08:27:37',13,1),
(9,'9','mitre saved user authn changes','SQL','V9__mitre_saved_user_authn_changes.sql',302744444,'indigoiam','2023-12-12 08:27:37',17,1),
(10,'10','fix internal authz scopes','SQL','V10__fix_internal_authz_scopes.sql',-686432566,'indigoiam','2023-12-12 08:27:37',2,1),
(11,'10.1','Password Update','JDBC','db.migration.mysql.V10_1__Password_Update',NULL,'indigoiam','2023-12-12 08:27:38',224,1),
(12,'10.2',' CheckDuplicateEmails','JDBC','db.migration.mysql.V10_2___CheckDuplicateEmails',NULL,'indigoiam','2023-12-12 08:27:38',1,1),
(13,'11','fix base scim and reg scopes','SQL','V11__fix_base_scim_and_reg_scopes.sql',-2106952067,'indigoiam','2023-12-12 08:27:38',1,1),
(14,'12','iam group nested groups','SQL','V12__iam_group_nested_groups.sql',-2140651111,'indigoiam','2023-12-12 08:27:38',50,1),
(15,'13','add attribute id to saml id table','SQL','V13__add_attribute_id_to_saml_id_table.sql',681840221,'indigoiam','2023-12-12 08:27:38',63,1),
(16,'14',' x509 certs table changes','SQL','V14___x509_certs_table_changes.sql',-310236366,'indigoiam','2023-12-12 08:27:38',162,1),
(17,'15','alter iam group','SQL','V15__alter_iam_group.sql',588116562,'indigoiam','2023-12-12 08:27:38',32,1),
(18,'16','add provisioned column to iam account','SQL','V16__add_provisioned_column_to_iam_account.sql',448586794,'indigoiam','2023-12-12 08:27:38',84,1),
(19,'17','add scope policy tables','SQL','V17__add_scope_policy_tables.sql',460278210,'indigoiam','2023-12-12 08:27:38',239,1),
(20,'18','mitre 1 3 x database changes','SQL','V18__mitre_1_3_x_database_changes.sql',449297336,'indigoiam','2023-12-12 08:27:39',404,1),
(21,'19','aup tables','SQL','V19__aup_tables.sql',567653912,'indigoiam','2023-12-12 08:27:39',229,1),
(22,'20','group membership request','SQL','V20__group_membership_request.sql',-924931434,'indigoiam','2023-12-12 08:27:39',161,1),
(23,'21',' device code default expiration','SQL','V21___device_code_default_expiration.sql',965164897,'indigoiam','2023-12-12 08:27:39',1,1),
(24,'22','add indexes for search queries','SQL','V22__add_indexes_for_search_queries.sql',-748445998,'indigoiam','2023-12-12 08:27:39',197,1),
(25,'23',' CreateGroupManagerAuthorities','JDBC','db.migration.mysql.V23___CreateGroupManagerAuthorities',NULL,'indigoiam','2023-12-12 08:27:39',2,1),
(26,'24',' set timestamp default','SQL','V24___set_timestamp_default.sql',234306337,'indigoiam','2023-12-12 08:27:39',28,1),
(27,'30',' default group support','SQL','V30___default_group_support.sql',-636476445,'indigoiam','2023-12-12 08:27:40',720,1),
(28,'31',' address table fixes','SQL','V31___address_table_fixes.sql',323916075,'indigoiam','2023-12-12 08:27:40',83,1),
(29,'32',' proxy storage','SQL','V32___proxy_storage.sql',851904690,'indigoiam','2023-12-12 08:27:40',139,1),
(30,'33',' proxy api scopes','SQL','V33___proxy_api_scopes.sql',-394160567,'indigoiam','2023-12-12 08:27:40',0,1),
(31,'34',' req request labels','SQL','V34___req_request_labels.sql',-1247430935,'indigoiam','2023-12-12 08:27:41',154,1),
(32,'34.2',' RemoveOrphanTokens','JDBC','db.migration.mysql.V34_2___RemoveOrphanTokens',NULL,'indigoiam','2023-12-12 08:27:41',6,1),
(33,'35',' scope match policies','SQL','V35___scope_match_policies.sql',773238492,'indigoiam','2023-12-12 08:27:41',116,1),
(34,'40',' aup updates','SQL','V40___aup_updates.sql',-1574961084,'indigoiam','2023-12-12 08:27:41',71,1),
(35,'50',' token exchange policy','SQL','V50___token_exchange_policy.sql',708363568,'indigoiam','2023-12-12 08:27:41',87,1),
(36,'51',' fix scope match policies','SQL','V51___fix_scope_match_policies.sql',1742199118,'indigoiam','2023-12-12 08:27:41',2,1),
(37,'52','add eduperson system scopes','SQL','V52__add_eduperson_system_scopes.sql',-669332083,'indigoiam','2023-12-12 08:27:41',1,1),
(38,'53',' add end time to iam acccount','SQL','V53___add_end_time_to_iam_acccount.sql',795128555,'indigoiam','2023-12-12 08:27:41',77,1),
(39,'60',' fix certificate subject length','SQL','V60___fix_certificate_subject_length.sql',437826198,'indigoiam','2023-12-12 08:27:41',148,1),
(40,'61',' add dates for group membership','SQL','V61___add_dates_for_group_membership.sql',-1216009527,'indigoiam','2023-12-12 08:27:41',44,1),
(41,'62',' add dates to ssh keys table','SQL','V62___add_dates_to_ssh_keys_table.sql',345904759,'indigoiam','2023-12-12 08:27:41',39,1),
(42,'70',' totp mfa','SQL','V70___totp_mfa.sql',358166160,'indigoiam','2023-12-12 08:27:41',96,1),
(43,'71',' add pre authenticated authority','SQL','V71___add_pre_authenticated_authority.sql',234328656,'indigoiam','2023-12-12 08:27:41',1,1),
(44,'80',' account clients','SQL','V80___account_clients.sql',-2130998179,'indigoiam','2023-12-12 08:27:42',152,1),
(45,'81','add eduperson assurance scope','SQL','V81__add_eduperson_assurance_scope.sql',1118450873,'indigoiam','2023-12-12 08:27:42',1,1),
(46,'81.2',' RemoveOrphanTokens','JDBC','db.migration.mysql.V81_2___RemoveOrphanTokens',NULL,'indigoiam','2023-12-12 08:27:42',3,1),
(47,'90','fix eduperson entitlement scope','SQL','V90__fix_eduperson_entitlement_scope.sql',-543114581,'indigoiam','2023-12-12 08:27:42',1,1),
(48,'91','update client name','SQL','V91__update_client_name.sql',-113175668,'indigoiam','2023-12-12 08:27:42',1,1),
(49,'92','add iam api scopes','SQL','V92__add_iam_api_scopes.sql',1959900565,'indigoiam','2023-12-12 08:27:42',1,1);
/*!40000 ALTER TABLE `schema_version` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `system_scope`
--

DROP TABLE IF EXISTS `system_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `system_scope` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `scope` varchar(256) NOT NULL,
  `description` varchar(4096) DEFAULT NULL,
  `icon` varchar(256) DEFAULT NULL,
  `restricted` tinyint(1) NOT NULL DEFAULT 0,
  `default_scope` tinyint(1) NOT NULL DEFAULT 0,
  `structured` tinyint(1) NOT NULL DEFAULT 0,
  `structured_param_description` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `scope` (`scope`)
) ENGINE=InnoDB AUTO_INCREMENT=25 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `system_scope`
--

LOCK TABLES `system_scope` WRITE;
/*!40000 ALTER TABLE `system_scope` DISABLE KEYS */;
INSERT INTO `system_scope` VALUES
(1,'openid','log in using your identity','user',0,1,0,NULL),
(2,'profile','basic profile information','list-alt',0,1,0,NULL),
(3,'email','email address','envelope',0,1,0,NULL),
(4,'address','physical address','home',0,1,0,NULL),
(5,'phone','telephone number','bell',0,1,0,NULL),
(6,'offline_access','offline access','time',0,0,0,NULL),
(7,'scim:read','read access to SCIM user and groups',NULL,1,0,1,'read access to IAM SCIM APIs'),
(8,'scim:write','write access to SCIM user and groups',NULL,1,0,1,'write access to IAM SCIM APIs'),
(9,'registration:read','Grants read access to registration requests',NULL,1,0,1,'read access to IAM registration APIs'),
(10,'registration:write','Grants write access to registration requests',NULL,1,0,1,'write access to IAM registration APIs'),
(11,'scim','Authorizes access to IAM SCIM APIs',NULL,1,0,1,NULL),
(12,'registration','Authorizes access to IAM registration APIs',NULL,1,0,1,NULL),
(13,'proxy:generate','Authorizes access to IAM Proxy APIs',NULL,1,0,1,NULL),
(16,'eduperson_scoped_affiliation','Access to EduPerson scoped affiliation information',NULL,0,0,0,NULL),
(17,'eduperson_entitlement','Access to EduPerson entitlements information',NULL,0,0,0,NULL),
(18,'ssh-keys','Authorizes access to SSH keys linked to IAM accounts via the IAM userinfo endpoint',NULL,1,0,1,NULL),
(19,'eduperson_assurance','Access to EduPerson assurance information',NULL,0,0,0,NULL),
(20,'entitlements','Access to entitlements information',NULL,0,0,0,NULL),
(21,'iam:admin.read','Read access to IAM APIs',NULL,1,0,0,NULL),
(22,'iam:admin.write','Write access to IAM APIs',NULL,1,0,0,NULL),
(23,'storage.read:/','Read access to storage','',0,0,0,NULL),
(24,'storage.modify:/','Write access to storage','',0,0,0,NULL);
/*!40000 ALTER TABLE `system_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `token_scope`
--

DROP TABLE IF EXISTS `token_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `token_scope` (
  `owner_id` bigint(20) DEFAULT NULL,
  `scope` varchar(2048) DEFAULT NULL,
  KEY `ts_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `token_scope`
--

LOCK TABLES `token_scope` WRITE;
/*!40000 ALTER TABLE `token_scope` DISABLE KEYS */;
INSERT INTO `token_scope` VALUES
(37,'registration-token'),
(38,'registration-token');
/*!40000 ALTER TABLE `token_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_info`
--

DROP TABLE IF EXISTS `user_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_info` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `sub` varchar(256) DEFAULT NULL,
  `preferred_username` varchar(256) DEFAULT NULL,
  `name` varchar(256) DEFAULT NULL,
  `given_name` varchar(256) DEFAULT NULL,
  `family_name` varchar(256) DEFAULT NULL,
  `middle_name` varchar(256) DEFAULT NULL,
  `nickname` varchar(256) DEFAULT NULL,
  `profile` varchar(256) DEFAULT NULL,
  `picture` varchar(256) DEFAULT NULL,
  `website` varchar(256) DEFAULT NULL,
  `email` varchar(256) DEFAULT NULL,
  `email_verified` tinyint(1) DEFAULT NULL,
  `gender` varchar(256) DEFAULT NULL,
  `zone_info` varchar(256) DEFAULT NULL,
  `locale` varchar(256) DEFAULT NULL,
  `phone_number` varchar(256) DEFAULT NULL,
  `phone_number_verified` tinyint(1) DEFAULT NULL,
  `address_id` varchar(256) DEFAULT NULL,
  `updated_time` varchar(256) DEFAULT NULL,
  `birthdate` varchar(256) DEFAULT NULL,
  `src` varchar(4096) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_info`
--

LOCK TABLES `user_info` WRITE;
/*!40000 ALTER TABLE `user_info` DISABLE KEYS */;
/*!40000 ALTER TABLE `user_info` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `whitelisted_site`
--

DROP TABLE IF EXISTS `whitelisted_site`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `whitelisted_site` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `creator_user_id` varchar(256) DEFAULT NULL,
  `client_id` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `whitelisted_site`
--

LOCK TABLES `whitelisted_site` WRITE;
/*!40000 ALTER TABLE `whitelisted_site` DISABLE KEYS */;
/*!40000 ALTER TABLE `whitelisted_site` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `whitelisted_site_scope`
--

DROP TABLE IF EXISTS `whitelisted_site_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `whitelisted_site_scope` (
  `owner_id` bigint(20) DEFAULT NULL,
  `scope` varchar(256) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `whitelisted_site_scope`
--

LOCK TABLES `whitelisted_site_scope` WRITE;
/*!40000 ALTER TABLE `whitelisted_site_scope` DISABLE KEYS */;
/*!40000 ALTER TABLE `whitelisted_site_scope` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-09-25 13:47:20
