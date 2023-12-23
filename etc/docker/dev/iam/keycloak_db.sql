-- MariaDB dump 10.19  Distrib 10.11.6-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: keycloak
-- ------------------------------------------------------
-- Server version	10.11.6-MariaDB-1:10.11.6+maria~ubu2204

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
-- Current Database: `keycloak`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `keycloak` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci */;

USE `keycloak`;

--
-- Table structure for table `ADMIN_EVENT_ENTITY`
--

DROP TABLE IF EXISTS `ADMIN_EVENT_ENTITY`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ADMIN_EVENT_ENTITY` (
  `ID` varchar(36) NOT NULL,
  `ADMIN_EVENT_TIME` bigint(20) DEFAULT NULL,
  `REALM_ID` varchar(255) DEFAULT NULL,
  `OPERATION_TYPE` varchar(255) DEFAULT NULL,
  `AUTH_REALM_ID` varchar(255) DEFAULT NULL,
  `AUTH_CLIENT_ID` varchar(255) DEFAULT NULL,
  `AUTH_USER_ID` varchar(255) DEFAULT NULL,
  `IP_ADDRESS` varchar(255) DEFAULT NULL,
  `RESOURCE_PATH` text DEFAULT NULL,
  `REPRESENTATION` text DEFAULT NULL,
  `ERROR` varchar(255) DEFAULT NULL,
  `RESOURCE_TYPE` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_ADMIN_EVENT_TIME` (`REALM_ID`,`ADMIN_EVENT_TIME`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `ADMIN_EVENT_ENTITY`
--

LOCK TABLES `ADMIN_EVENT_ENTITY` WRITE;
/*!40000 ALTER TABLE `ADMIN_EVENT_ENTITY` DISABLE KEYS */;
/*!40000 ALTER TABLE `ADMIN_EVENT_ENTITY` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `ASSOCIATED_POLICY`
--

DROP TABLE IF EXISTS `ASSOCIATED_POLICY`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ASSOCIATED_POLICY` (
  `POLICY_ID` varchar(36) NOT NULL,
  `ASSOCIATED_POLICY_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`POLICY_ID`,`ASSOCIATED_POLICY_ID`),
  KEY `IDX_ASSOC_POL_ASSOC_POL_ID` (`ASSOCIATED_POLICY_ID`),
  CONSTRAINT `FK_FRSR5S213XCX4WNKOG82SSRFY` FOREIGN KEY (`ASSOCIATED_POLICY_ID`) REFERENCES `RESOURCE_SERVER_POLICY` (`ID`),
  CONSTRAINT `FK_FRSRPAS14XCX4WNKOG82SSRFY` FOREIGN KEY (`POLICY_ID`) REFERENCES `RESOURCE_SERVER_POLICY` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `ASSOCIATED_POLICY`
--

LOCK TABLES `ASSOCIATED_POLICY` WRITE;
/*!40000 ALTER TABLE `ASSOCIATED_POLICY` DISABLE KEYS */;
INSERT INTO `ASSOCIATED_POLICY` VALUES
('39c718e6-f814-4e59-8d26-4a9fb7d46947','a53eb10e-0623-4586-a482-7a41666a4c68'),
('71dd1617-3f3b-41d1-8ea7-a2a9f48e5d12','cd2e5ea5-10ef-4aed-8871-a8d31296c40b'),
('ef70cf4a-cf36-4fcf-90e0-6a73eef7cf8a','a53eb10e-0623-4586-a482-7a41666a4c68');
/*!40000 ALTER TABLE `ASSOCIATED_POLICY` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `AUTHENTICATION_EXECUTION`
--

DROP TABLE IF EXISTS `AUTHENTICATION_EXECUTION`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `AUTHENTICATION_EXECUTION` (
  `ID` varchar(36) NOT NULL,
  `ALIAS` varchar(255) DEFAULT NULL,
  `AUTHENTICATOR` varchar(36) DEFAULT NULL,
  `REALM_ID` varchar(36) DEFAULT NULL,
  `FLOW_ID` varchar(36) DEFAULT NULL,
  `REQUIREMENT` int(11) DEFAULT NULL,
  `PRIORITY` int(11) DEFAULT NULL,
  `AUTHENTICATOR_FLOW` bit(1) NOT NULL DEFAULT b'0',
  `AUTH_FLOW_ID` varchar(36) DEFAULT NULL,
  `AUTH_CONFIG` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_AUTH_EXEC_REALM_FLOW` (`REALM_ID`,`FLOW_ID`),
  KEY `IDX_AUTH_EXEC_FLOW` (`FLOW_ID`),
  CONSTRAINT `FK_AUTH_EXEC_FLOW` FOREIGN KEY (`FLOW_ID`) REFERENCES `AUTHENTICATION_FLOW` (`ID`),
  CONSTRAINT `FK_AUTH_EXEC_REALM` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `AUTHENTICATION_EXECUTION`
--

LOCK TABLES `AUTHENTICATION_EXECUTION` WRITE;
/*!40000 ALTER TABLE `AUTHENTICATION_EXECUTION` DISABLE KEYS */;
INSERT INTO `AUTHENTICATION_EXECUTION` VALUES
('050c1680-5147-4358-aefe-8c9a73b903fc',NULL,'client-secret','61c254e2-095d-42b9-b8cc-4546b124e548','ea03a723-575b-423a-8993-ee0232e25692',2,10,'\0',NULL,NULL),
('08a91df5-70e1-49f7-86bd-d2450cd35125',NULL,'idp-email-verification','61c254e2-095d-42b9-b8cc-4546b124e548','b27f5a40-85fd-4ac1-92fd-b97308e2db59',2,10,'\0',NULL,NULL),
('0ed5b850-e167-487e-a2ef-d15599ac2db1',NULL,'conditional-user-configured','139c1488-d000-4061-922b-0c0b518a57db','eb8e300c-da5b-4af1-b74a-e78f2ea65848',0,10,'\0',NULL,NULL),
('14d84040-4802-47ab-841c-48eaa5e295b1',NULL,NULL,'139c1488-d000-4061-922b-0c0b518a57db','9c6d12dc-4099-415c-b5ec-80dba581b1c8',1,20,'','9af5bd0e-85b1-41b3-8726-e2b9c59ae757',NULL),
('1aa9d9e2-eaa9-4f42-9f80-64b9dff01f15',NULL,'idp-username-password-form','139c1488-d000-4061-922b-0c0b518a57db','9c6d12dc-4099-415c-b5ec-80dba581b1c8',0,10,'\0',NULL,NULL),
('281edc28-a243-4f11-b62d-3e288c2d3471',NULL,'conditional-user-configured','139c1488-d000-4061-922b-0c0b518a57db','9af5bd0e-85b1-41b3-8726-e2b9c59ae757',0,10,'\0',NULL,NULL),
('30ad8cf7-8cfe-4d5b-a057-c6ea976dee0e',NULL,'client-x509','139c1488-d000-4061-922b-0c0b518a57db','a729e6a9-8b5a-4cdb-96bf-7589c8ea0c8a',2,40,'\0',NULL,NULL),
('396ec807-417d-4eb8-b68f-356b3ddde551',NULL,'auth-spnego','139c1488-d000-4061-922b-0c0b518a57db','718da82c-570c-4044-8835-40c9a3d7944b',3,20,'\0',NULL,NULL),
('3c80ad55-56f2-4d90-9203-86a90831b51d',NULL,'direct-grant-validate-password','139c1488-d000-4061-922b-0c0b518a57db','431dba76-8573-4297-9670-157d884d265f',0,20,'\0',NULL,NULL),
('3d38d149-bcc4-4a70-b438-36605516dfb2',NULL,'registration-user-creation','61c254e2-095d-42b9-b8cc-4546b124e548','2ca8ec1e-5b37-4b27-8331-5f35a3c4fb84',0,20,'\0',NULL,NULL),
('40acb90b-ce5d-487e-941f-ee44ae7b42bc',NULL,'conditional-user-configured','61c254e2-095d-42b9-b8cc-4546b124e548','be334665-a1cd-4c6f-a269-80be32196acb',0,10,'\0',NULL,NULL),
('481ce562-4796-4f1f-a8bc-fc49ad4f33b7',NULL,'direct-grant-validate-username','61c254e2-095d-42b9-b8cc-4546b124e548','b43e9e5d-af68-4aa0-8e7a-14fc5755734d',0,10,'\0',NULL,NULL),
('491a98a7-a950-4f43-a7c2-1cf47f87be40',NULL,'http-basic-authenticator','61c254e2-095d-42b9-b8cc-4546b124e548','b4c1c797-c9f5-4ec6-8300-3972a6d8c08c',0,10,'\0',NULL,NULL),
('4a82e052-0122-41e2-b2a6-4d879595aedb',NULL,'direct-grant-validate-otp','139c1488-d000-4061-922b-0c0b518a57db','e83c6171-57a0-45ba-9af0-ddf6907f01b6',0,20,'\0',NULL,NULL),
('4c7f7df4-eb61-49f6-ab36-6e8f4665ca17',NULL,'client-jwt','139c1488-d000-4061-922b-0c0b518a57db','a729e6a9-8b5a-4cdb-96bf-7589c8ea0c8a',2,20,'\0',NULL,NULL),
('4d295ab1-2f44-47d7-bd83-aa8cecd61233',NULL,'client-secret','139c1488-d000-4061-922b-0c0b518a57db','a729e6a9-8b5a-4cdb-96bf-7589c8ea0c8a',2,10,'\0',NULL,NULL),
('5002a400-8122-4027-b00e-dd93f41177ea',NULL,NULL,'139c1488-d000-4061-922b-0c0b518a57db','431dba76-8573-4297-9670-157d884d265f',1,30,'','e83c6171-57a0-45ba-9af0-ddf6907f01b6',NULL),
('516a446b-3b7c-4acc-830e-261f903a425a',NULL,'reset-password','139c1488-d000-4061-922b-0c0b518a57db','dc3df143-d1cf-4cba-93c9-f778e9bbb79e',0,30,'\0',NULL,NULL),
('527dff4c-1364-43ca-a3aa-5c5d7a6873e2',NULL,'identity-provider-redirector','61c254e2-095d-42b9-b8cc-4546b124e548','dca5d32d-86b8-4c98-94a5-bb9fce71cc89',2,25,'\0',NULL,NULL),
('54b605fd-c7b2-47c1-bd78-263ed5288708',NULL,NULL,'61c254e2-095d-42b9-b8cc-4546b124e548','a24a9e6d-8ac7-4803-839d-bdf645562b92',0,20,'','cb579ca4-bc59-44cc-998e-20282c5cb887',NULL),
('564fdf74-2218-4c5d-9399-57a1a336f384',NULL,'direct-grant-validate-password','61c254e2-095d-42b9-b8cc-4546b124e548','b43e9e5d-af68-4aa0-8e7a-14fc5755734d',0,20,'\0',NULL,NULL),
('572d8ed4-1b89-4551-8ad2-4359f77f03dc',NULL,'registration-page-form','61c254e2-095d-42b9-b8cc-4546b124e548','41657800-8217-4ac6-af7e-54023e60b888',0,10,'','2ca8ec1e-5b37-4b27-8331-5f35a3c4fb84',NULL),
('59352536-b370-40ce-81e2-a5089db7fc68',NULL,'conditional-user-configured','61c254e2-095d-42b9-b8cc-4546b124e548','aecb185f-8c93-449e-9ab2-ebcd24ad5c16',0,10,'\0',NULL,NULL),
('5c35424e-c42a-4705-816d-b8e355c557df',NULL,NULL,'139c1488-d000-4061-922b-0c0b518a57db','a36bf239-ff44-4f1c-b3fc-75f2636c8eaf',1,20,'','781f09e4-c3d0-49ce-b138-be5f83341f7c',NULL),
('5c5e16ba-3a64-4b70-ab45-2ead9bf1d280',NULL,'client-secret-jwt','61c254e2-095d-42b9-b8cc-4546b124e548','ea03a723-575b-423a-8993-ee0232e25692',2,30,'\0',NULL,NULL),
('695f46cd-8904-4434-8cbd-b8127d39f612',NULL,'registration-recaptcha-action','139c1488-d000-4061-922b-0c0b518a57db','794b0e3d-b5d1-4313-9b64-1b4ed5becd67',3,60,'\0',NULL,NULL),
('6b035453-7bf4-42a8-b9fd-acfa06c3ff7d',NULL,'auth-otp-form','61c254e2-095d-42b9-b8cc-4546b124e548','a06e1aba-5443-4080-b70c-8ca68d2594c7',0,20,'\0',NULL,NULL),
('7090915e-1fec-4b10-88c2-973f2f6adb23',NULL,'reset-password','61c254e2-095d-42b9-b8cc-4546b124e548','cb65b4c2-ea74-478a-b3bc-e58fa769e356',0,30,'\0',NULL,NULL),
('71e06e18-45fd-46c1-a98d-04b9a75c5a31',NULL,'auth-username-password-form','61c254e2-095d-42b9-b8cc-4546b124e548','f2f902e2-f3cb-470b-bcd7-d8d7ed39b2e1',0,10,'\0',NULL,NULL),
('79741669-745f-42b9-a10a-1d2c40007f1e',NULL,NULL,'139c1488-d000-4061-922b-0c0b518a57db','49a1986c-1d1b-4702-8019-c77429029497',0,20,'','efa3f4f4-bdf4-418a-a31b-7a492cc59af8',NULL),
('7bc59459-46e4-4a9a-8b1b-018100d90e85',NULL,NULL,'61c254e2-095d-42b9-b8cc-4546b124e548','87496a5c-8e5c-4d28-896f-db89d2e70c96',1,20,'','a06e1aba-5443-4080-b70c-8ca68d2594c7',NULL),
('7cd50eb8-1733-4121-82a6-23d4dc6893a3',NULL,'registration-password-action','61c254e2-095d-42b9-b8cc-4546b124e548','2ca8ec1e-5b37-4b27-8331-5f35a3c4fb84',0,50,'\0',NULL,NULL),
('803cb61a-740e-4bf5-9670-fbb2e59fdc09',NULL,'conditional-user-configured','139c1488-d000-4061-922b-0c0b518a57db','781f09e4-c3d0-49ce-b138-be5f83341f7c',0,10,'\0',NULL,NULL),
('83272804-c9a4-476d-8eca-2bb05e90e4f2',NULL,NULL,'139c1488-d000-4061-922b-0c0b518a57db','efa3f4f4-bdf4-418a-a31b-7a492cc59af8',2,20,'','9c6d12dc-4099-415c-b5ec-80dba581b1c8',NULL),
('83e4fb51-55b8-484c-9855-84e11254de28',NULL,'registration-recaptcha-action','61c254e2-095d-42b9-b8cc-4546b124e548','2ca8ec1e-5b37-4b27-8331-5f35a3c4fb84',3,60,'\0',NULL,NULL),
('8439c056-e56b-4935-b7cf-a8841847dd20',NULL,NULL,'139c1488-d000-4061-922b-0c0b518a57db','dc3df143-d1cf-4cba-93c9-f778e9bbb79e',1,40,'','eb8e300c-da5b-4af1-b74a-e78f2ea65848',NULL),
('87ad9e6d-9787-43d0-800b-7c37db2fefee',NULL,'idp-create-user-if-unique','139c1488-d000-4061-922b-0c0b518a57db','f4b5cf4b-0d4d-478c-ac55-fbc86287bf9a',2,10,'\0',NULL,'8e64b6bb-c651-4eeb-a38b-65b8536effe5'),
('895a7a93-9066-477d-8f82-e8fc8f969663',NULL,'registration-terms-and-conditions','61c254e2-095d-42b9-b8cc-4546b124e548','2ca8ec1e-5b37-4b27-8331-5f35a3c4fb84',3,70,'\0',NULL,NULL),
('8a1d0fd0-2e9b-4580-b481-af4783a39ed8',NULL,NULL,'139c1488-d000-4061-922b-0c0b518a57db','de31d58e-ecd2-43c3-953a-900e465a9810',0,20,'','f4b5cf4b-0d4d-478c-ac55-fbc86287bf9a',NULL),
('8b4c14b3-3deb-4576-a328-d4cc06db81fe',NULL,'direct-grant-validate-username','139c1488-d000-4061-922b-0c0b518a57db','431dba76-8573-4297-9670-157d884d265f',0,10,'\0',NULL,NULL),
('8c223bbf-4024-41a4-b187-a1ccef8389ac',NULL,NULL,'61c254e2-095d-42b9-b8cc-4546b124e548','cb65b4c2-ea74-478a-b3bc-e58fa769e356',1,40,'','aecb185f-8c93-449e-9ab2-ebcd24ad5c16',NULL),
('8d887264-f726-436f-bad0-6dd62cddcd43',NULL,'registration-password-action','139c1488-d000-4061-922b-0c0b518a57db','794b0e3d-b5d1-4313-9b64-1b4ed5becd67',0,50,'\0',NULL,NULL),
('8e44223a-69db-454f-88d1-1188062995a7',NULL,'http-basic-authenticator','139c1488-d000-4061-922b-0c0b518a57db','8b39a8b8-83f1-4b46-9f6d-854acd9b482e',0,10,'\0',NULL,NULL),
('933e2e43-4a1f-487c-b113-c10759bd6ad8',NULL,'idp-review-profile','139c1488-d000-4061-922b-0c0b518a57db','de31d58e-ecd2-43c3-953a-900e465a9810',0,10,'\0',NULL,'6dd6505a-cef7-4925-a4bf-2148bb0146cb'),
('97db4bdb-8bfd-4d7c-8a12-6947be16b8bb',NULL,NULL,'61c254e2-095d-42b9-b8cc-4546b124e548','f2f902e2-f3cb-470b-bcd7-d8d7ed39b2e1',1,20,'','be334665-a1cd-4c6f-a269-80be32196acb',NULL),
('97e0ef39-5aae-47f8-97ca-a0e805544dd6',NULL,'reset-credentials-choose-user','61c254e2-095d-42b9-b8cc-4546b124e548','cb65b4c2-ea74-478a-b3bc-e58fa769e356',0,10,'\0',NULL,NULL),
('9b9c6c87-f5fd-4057-875b-adf7f3abc7a2',NULL,'idp-confirm-link','61c254e2-095d-42b9-b8cc-4546b124e548','ca7f5c40-2e84-4a31-91ae-7502b4a818ae',0,10,'\0',NULL,NULL),
('a08d28f3-7d0a-4b18-9252-19cc3a5da072',NULL,NULL,'61c254e2-095d-42b9-b8cc-4546b124e548','dca5d32d-86b8-4c98-94a5-bb9fce71cc89',2,30,'','f2f902e2-f3cb-470b-bcd7-d8d7ed39b2e1',NULL),
('a59b8951-be21-49ca-992a-7ef42a0af496',NULL,'client-x509','61c254e2-095d-42b9-b8cc-4546b124e548','ea03a723-575b-423a-8993-ee0232e25692',2,40,'\0',NULL,NULL),
('a64a7b24-93ce-495b-ac8a-6976b0985657',NULL,NULL,'61c254e2-095d-42b9-b8cc-4546b124e548','ca7f5c40-2e84-4a31-91ae-7502b4a818ae',0,20,'','b27f5a40-85fd-4ac1-92fd-b97308e2db59',NULL),
('a733486c-0401-4326-8797-a27391afb214',NULL,'registration-user-creation','139c1488-d000-4061-922b-0c0b518a57db','794b0e3d-b5d1-4313-9b64-1b4ed5becd67',0,20,'\0',NULL,NULL),
('a9dfd5b9-db88-449a-9758-26ff4a8704d2',NULL,'idp-review-profile','61c254e2-095d-42b9-b8cc-4546b124e548','a24a9e6d-8ac7-4803-839d-bdf645562b92',0,10,'\0',NULL,'6bb20ec9-708a-40a8-8a5d-13217c2ed0f4'),
('aa48627a-03f7-489f-b2d8-955a69b65689',NULL,'idp-confirm-link','139c1488-d000-4061-922b-0c0b518a57db','49a1986c-1d1b-4702-8019-c77429029497',0,10,'\0',NULL,NULL),
('abb4eb1d-4620-4889-b6b3-cfe9fba566f5',NULL,NULL,'139c1488-d000-4061-922b-0c0b518a57db','718da82c-570c-4044-8835-40c9a3d7944b',2,30,'','a36bf239-ff44-4f1c-b3fc-75f2636c8eaf',NULL),
('ad35eb5b-b92e-4764-95c6-b0748d43d35b',NULL,'client-secret-jwt','139c1488-d000-4061-922b-0c0b518a57db','a729e6a9-8b5a-4cdb-96bf-7589c8ea0c8a',2,30,'\0',NULL,NULL),
('ad5d48e5-36e4-473d-b84b-c6c79592f443',NULL,'auth-username-password-form','139c1488-d000-4061-922b-0c0b518a57db','a36bf239-ff44-4f1c-b3fc-75f2636c8eaf',0,10,'\0',NULL,NULL),
('ae1491f4-7d34-4515-a643-1cd4e3173e13',NULL,'conditional-user-configured','61c254e2-095d-42b9-b8cc-4546b124e548','9294dc8e-3c6d-4126-9ce5-3c37768f545c',0,10,'\0',NULL,NULL),
('aff5844a-03b1-4a5f-926a-00278c825e0c',NULL,'auth-spnego','61c254e2-095d-42b9-b8cc-4546b124e548','dca5d32d-86b8-4c98-94a5-bb9fce71cc89',3,20,'\0',NULL,NULL),
('b0d8d4fa-82d6-4799-b310-1c75e666925e',NULL,'reset-credential-email','139c1488-d000-4061-922b-0c0b518a57db','dc3df143-d1cf-4cba-93c9-f778e9bbb79e',0,20,'\0',NULL,NULL),
('b3288ad5-4a16-4ad2-a828-c483727cb8ba',NULL,'docker-http-basic-authenticator','139c1488-d000-4061-922b-0c0b518a57db','f0fe1ce7-0d8b-4ada-9b52-8aa9d2bb8ac1',0,10,'\0',NULL,NULL),
('b6adeeed-5afc-4f52-a367-0b6fd4732f80',NULL,NULL,'61c254e2-095d-42b9-b8cc-4546b124e548','cb579ca4-bc59-44cc-998e-20282c5cb887',2,20,'','ca7f5c40-2e84-4a31-91ae-7502b4a818ae',NULL),
('b8361a4e-a984-460c-8c9b-fa92c099899f',NULL,'docker-http-basic-authenticator','61c254e2-095d-42b9-b8cc-4546b124e548','e4fc2888-0400-4daa-a358-70a22443dbda',0,10,'\0',NULL,NULL),
('bc17e6de-6358-4bcf-a363-988e448f71f3',NULL,'auth-otp-form','139c1488-d000-4061-922b-0c0b518a57db','781f09e4-c3d0-49ce-b138-be5f83341f7c',0,20,'\0',NULL,NULL),
('bd16d145-9950-4d90-9822-1548c566ac12',NULL,NULL,'61c254e2-095d-42b9-b8cc-4546b124e548','b43e9e5d-af68-4aa0-8e7a-14fc5755734d',1,30,'','9294dc8e-3c6d-4126-9ce5-3c37768f545c',NULL),
('be6fe023-9399-48cc-a589-277921e17d5c',NULL,'auth-otp-form','61c254e2-095d-42b9-b8cc-4546b124e548','be334665-a1cd-4c6f-a269-80be32196acb',0,20,'\0',NULL,NULL),
('bedf1ec3-2526-4806-ae0e-bb42f3a1d853',NULL,'conditional-user-configured','139c1488-d000-4061-922b-0c0b518a57db','e83c6171-57a0-45ba-9af0-ddf6907f01b6',0,10,'\0',NULL,NULL),
('bf965f3d-21d9-45fb-a479-99569a3ffa0c',NULL,'client-jwt','61c254e2-095d-42b9-b8cc-4546b124e548','ea03a723-575b-423a-8993-ee0232e25692',2,20,'\0',NULL,NULL),
('bfe768b4-785e-4e56-9d24-a0f4e4bcbe49',NULL,'conditional-user-configured','61c254e2-095d-42b9-b8cc-4546b124e548','a06e1aba-5443-4080-b70c-8ca68d2594c7',0,10,'\0',NULL,NULL),
('c09bab25-d717-45ea-810b-87fe25a2a834',NULL,'idp-username-password-form','61c254e2-095d-42b9-b8cc-4546b124e548','87496a5c-8e5c-4d28-896f-db89d2e70c96',0,10,'\0',NULL,NULL),
('c17fabbf-d15e-4039-9f10-ad8e649af0c8',NULL,'identity-provider-redirector','139c1488-d000-4061-922b-0c0b518a57db','718da82c-570c-4044-8835-40c9a3d7944b',2,25,'\0',NULL,NULL),
('d29cfd2f-9544-435b-8415-dee9d5c04eab',NULL,NULL,'61c254e2-095d-42b9-b8cc-4546b124e548','b27f5a40-85fd-4ac1-92fd-b97308e2db59',2,20,'','87496a5c-8e5c-4d28-896f-db89d2e70c96',NULL),
('daa1857e-1813-478e-ab3c-76638d2104af',NULL,'direct-grant-validate-otp','61c254e2-095d-42b9-b8cc-4546b124e548','9294dc8e-3c6d-4126-9ce5-3c37768f545c',0,20,'\0',NULL,NULL),
('dc71f98b-723d-4177-8792-c1599760810f',NULL,NULL,'139c1488-d000-4061-922b-0c0b518a57db','f4b5cf4b-0d4d-478c-ac55-fbc86287bf9a',2,20,'','49a1986c-1d1b-4702-8019-c77429029497',NULL),
('e289b4c0-61c9-4bd1-8583-08be2e6da7fd',NULL,'auth-cookie','61c254e2-095d-42b9-b8cc-4546b124e548','dca5d32d-86b8-4c98-94a5-bb9fce71cc89',2,10,'\0',NULL,NULL),
('e3ac2a9a-875b-4b1f-801e-ace70af57512',NULL,'reset-otp','61c254e2-095d-42b9-b8cc-4546b124e548','aecb185f-8c93-449e-9ab2-ebcd24ad5c16',0,20,'\0',NULL,NULL),
('e3cf7925-e2f4-4438-9df1-fda5f5de3921',NULL,'reset-credential-email','61c254e2-095d-42b9-b8cc-4546b124e548','cb65b4c2-ea74-478a-b3bc-e58fa769e356',0,20,'\0',NULL,NULL),
('e84a65c0-45b9-4a27-8933-fd750f999c4a',NULL,'registration-page-form','139c1488-d000-4061-922b-0c0b518a57db','6b278f0f-5511-4a01-8a0a-81d3d147f82e',0,10,'','794b0e3d-b5d1-4313-9b64-1b4ed5becd67',NULL),
('eb9365e6-2643-41a0-b256-89b98061d171',NULL,'idp-create-user-if-unique','61c254e2-095d-42b9-b8cc-4546b124e548','cb579ca4-bc59-44cc-998e-20282c5cb887',2,10,'\0',NULL,'eab807c3-4054-45ac-addd-583d55b9cb64'),
('f3942fb7-7f69-464d-b724-be11d946a00f',NULL,'auth-cookie','139c1488-d000-4061-922b-0c0b518a57db','718da82c-570c-4044-8835-40c9a3d7944b',2,10,'\0',NULL,NULL),
('f8583c3d-64f6-42b9-a645-2c952d6ce2c1',NULL,'auth-otp-form','139c1488-d000-4061-922b-0c0b518a57db','9af5bd0e-85b1-41b3-8726-e2b9c59ae757',0,20,'\0',NULL,NULL),
('f9874900-1fbb-4b3a-9e4f-0817cbb50cb9',NULL,'idp-email-verification','139c1488-d000-4061-922b-0c0b518a57db','efa3f4f4-bdf4-418a-a31b-7a492cc59af8',2,10,'\0',NULL,NULL),
('f9c77fa1-c023-4097-913b-d9aefe3e515e',NULL,'reset-credentials-choose-user','139c1488-d000-4061-922b-0c0b518a57db','dc3df143-d1cf-4cba-93c9-f778e9bbb79e',0,10,'\0',NULL,NULL),
('fcb5a9d7-e7ec-49ca-93d9-6b73afc02bd0',NULL,'reset-otp','139c1488-d000-4061-922b-0c0b518a57db','eb8e300c-da5b-4af1-b74a-e78f2ea65848',0,20,'\0',NULL,NULL);
/*!40000 ALTER TABLE `AUTHENTICATION_EXECUTION` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `AUTHENTICATION_FLOW`
--

DROP TABLE IF EXISTS `AUTHENTICATION_FLOW`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `AUTHENTICATION_FLOW` (
  `ID` varchar(36) NOT NULL,
  `ALIAS` varchar(255) DEFAULT NULL,
  `DESCRIPTION` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `REALM_ID` varchar(36) DEFAULT NULL,
  `PROVIDER_ID` varchar(36) NOT NULL DEFAULT 'basic-flow',
  `TOP_LEVEL` bit(1) NOT NULL DEFAULT b'0',
  `BUILT_IN` bit(1) NOT NULL DEFAULT b'0',
  PRIMARY KEY (`ID`),
  KEY `IDX_AUTH_FLOW_REALM` (`REALM_ID`),
  CONSTRAINT `FK_AUTH_FLOW_REALM` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `AUTHENTICATION_FLOW`
--

LOCK TABLES `AUTHENTICATION_FLOW` WRITE;
/*!40000 ALTER TABLE `AUTHENTICATION_FLOW` DISABLE KEYS */;
INSERT INTO `AUTHENTICATION_FLOW` VALUES
('2ca8ec1e-5b37-4b27-8331-5f35a3c4fb84','registration form','registration form','61c254e2-095d-42b9-b8cc-4546b124e548','form-flow','\0',''),
('41657800-8217-4ac6-af7e-54023e60b888','registration','registration flow','61c254e2-095d-42b9-b8cc-4546b124e548','basic-flow','',''),
('431dba76-8573-4297-9670-157d884d265f','direct grant','OpenID Connect Resource Owner Grant','139c1488-d000-4061-922b-0c0b518a57db','basic-flow','',''),
('49a1986c-1d1b-4702-8019-c77429029497','Handle Existing Account','Handle what to do if there is existing account with same email/username like authenticated identity provider','139c1488-d000-4061-922b-0c0b518a57db','basic-flow','\0',''),
('6b278f0f-5511-4a01-8a0a-81d3d147f82e','registration','registration flow','139c1488-d000-4061-922b-0c0b518a57db','basic-flow','',''),
('718da82c-570c-4044-8835-40c9a3d7944b','browser','browser based authentication','139c1488-d000-4061-922b-0c0b518a57db','basic-flow','',''),
('781f09e4-c3d0-49ce-b138-be5f83341f7c','Browser - Conditional OTP','Flow to determine if the OTP is required for the authentication','139c1488-d000-4061-922b-0c0b518a57db','basic-flow','\0',''),
('794b0e3d-b5d1-4313-9b64-1b4ed5becd67','registration form','registration form','139c1488-d000-4061-922b-0c0b518a57db','form-flow','\0',''),
('87496a5c-8e5c-4d28-896f-db89d2e70c96','Verify Existing Account by Re-authentication','Reauthentication of existing account','61c254e2-095d-42b9-b8cc-4546b124e548','basic-flow','\0',''),
('8b39a8b8-83f1-4b46-9f6d-854acd9b482e','saml ecp','SAML ECP Profile Authentication Flow','139c1488-d000-4061-922b-0c0b518a57db','basic-flow','',''),
('9294dc8e-3c6d-4126-9ce5-3c37768f545c','Direct Grant - Conditional OTP','Flow to determine if the OTP is required for the authentication','61c254e2-095d-42b9-b8cc-4546b124e548','basic-flow','\0',''),
('9af5bd0e-85b1-41b3-8726-e2b9c59ae757','First broker login - Conditional OTP','Flow to determine if the OTP is required for the authentication','139c1488-d000-4061-922b-0c0b518a57db','basic-flow','\0',''),
('9c6d12dc-4099-415c-b5ec-80dba581b1c8','Verify Existing Account by Re-authentication','Reauthentication of existing account','139c1488-d000-4061-922b-0c0b518a57db','basic-flow','\0',''),
('a06e1aba-5443-4080-b70c-8ca68d2594c7','First broker login - Conditional OTP','Flow to determine if the OTP is required for the authentication','61c254e2-095d-42b9-b8cc-4546b124e548','basic-flow','\0',''),
('a24a9e6d-8ac7-4803-839d-bdf645562b92','first broker login','Actions taken after first broker login with identity provider account, which is not yet linked to any Keycloak account','61c254e2-095d-42b9-b8cc-4546b124e548','basic-flow','',''),
('a36bf239-ff44-4f1c-b3fc-75f2636c8eaf','forms','Username, password, otp and other auth forms.','139c1488-d000-4061-922b-0c0b518a57db','basic-flow','\0',''),
('a729e6a9-8b5a-4cdb-96bf-7589c8ea0c8a','clients','Base authentication for clients','139c1488-d000-4061-922b-0c0b518a57db','client-flow','',''),
('aecb185f-8c93-449e-9ab2-ebcd24ad5c16','Reset - Conditional OTP','Flow to determine if the OTP should be reset or not. Set to REQUIRED to force.','61c254e2-095d-42b9-b8cc-4546b124e548','basic-flow','\0',''),
('b27f5a40-85fd-4ac1-92fd-b97308e2db59','Account verification options','Method with which to verity the existing account','61c254e2-095d-42b9-b8cc-4546b124e548','basic-flow','\0',''),
('b43e9e5d-af68-4aa0-8e7a-14fc5755734d','direct grant','OpenID Connect Resource Owner Grant','61c254e2-095d-42b9-b8cc-4546b124e548','basic-flow','',''),
('b4c1c797-c9f5-4ec6-8300-3972a6d8c08c','saml ecp','SAML ECP Profile Authentication Flow','61c254e2-095d-42b9-b8cc-4546b124e548','basic-flow','',''),
('be334665-a1cd-4c6f-a269-80be32196acb','Browser - Conditional OTP','Flow to determine if the OTP is required for the authentication','61c254e2-095d-42b9-b8cc-4546b124e548','basic-flow','\0',''),
('ca7f5c40-2e84-4a31-91ae-7502b4a818ae','Handle Existing Account','Handle what to do if there is existing account with same email/username like authenticated identity provider','61c254e2-095d-42b9-b8cc-4546b124e548','basic-flow','\0',''),
('cb579ca4-bc59-44cc-998e-20282c5cb887','User creation or linking','Flow for the existing/non-existing user alternatives','61c254e2-095d-42b9-b8cc-4546b124e548','basic-flow','\0',''),
('cb65b4c2-ea74-478a-b3bc-e58fa769e356','reset credentials','Reset credentials for a user if they forgot their password or something','61c254e2-095d-42b9-b8cc-4546b124e548','basic-flow','',''),
('dc3df143-d1cf-4cba-93c9-f778e9bbb79e','reset credentials','Reset credentials for a user if they forgot their password or something','139c1488-d000-4061-922b-0c0b518a57db','basic-flow','',''),
('dca5d32d-86b8-4c98-94a5-bb9fce71cc89','browser','browser based authentication','61c254e2-095d-42b9-b8cc-4546b124e548','basic-flow','',''),
('de31d58e-ecd2-43c3-953a-900e465a9810','first broker login','Actions taken after first broker login with identity provider account, which is not yet linked to any Keycloak account','139c1488-d000-4061-922b-0c0b518a57db','basic-flow','',''),
('e4fc2888-0400-4daa-a358-70a22443dbda','docker auth','Used by Docker clients to authenticate against the IDP','61c254e2-095d-42b9-b8cc-4546b124e548','basic-flow','',''),
('e83c6171-57a0-45ba-9af0-ddf6907f01b6','Direct Grant - Conditional OTP','Flow to determine if the OTP is required for the authentication','139c1488-d000-4061-922b-0c0b518a57db','basic-flow','\0',''),
('ea03a723-575b-423a-8993-ee0232e25692','clients','Base authentication for clients','61c254e2-095d-42b9-b8cc-4546b124e548','client-flow','',''),
('eb8e300c-da5b-4af1-b74a-e78f2ea65848','Reset - Conditional OTP','Flow to determine if the OTP should be reset or not. Set to REQUIRED to force.','139c1488-d000-4061-922b-0c0b518a57db','basic-flow','\0',''),
('efa3f4f4-bdf4-418a-a31b-7a492cc59af8','Account verification options','Method with which to verity the existing account','139c1488-d000-4061-922b-0c0b518a57db','basic-flow','\0',''),
('f0fe1ce7-0d8b-4ada-9b52-8aa9d2bb8ac1','docker auth','Used by Docker clients to authenticate against the IDP','139c1488-d000-4061-922b-0c0b518a57db','basic-flow','',''),
('f2f902e2-f3cb-470b-bcd7-d8d7ed39b2e1','forms','Username, password, otp and other auth forms.','61c254e2-095d-42b9-b8cc-4546b124e548','basic-flow','\0',''),
('f4b5cf4b-0d4d-478c-ac55-fbc86287bf9a','User creation or linking','Flow for the existing/non-existing user alternatives','139c1488-d000-4061-922b-0c0b518a57db','basic-flow','\0','');
/*!40000 ALTER TABLE `AUTHENTICATION_FLOW` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `AUTHENTICATOR_CONFIG`
--

DROP TABLE IF EXISTS `AUTHENTICATOR_CONFIG`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `AUTHENTICATOR_CONFIG` (
  `ID` varchar(36) NOT NULL,
  `ALIAS` varchar(255) DEFAULT NULL,
  `REALM_ID` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_AUTH_CONFIG_REALM` (`REALM_ID`),
  CONSTRAINT `FK_AUTH_REALM` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `AUTHENTICATOR_CONFIG`
--

LOCK TABLES `AUTHENTICATOR_CONFIG` WRITE;
/*!40000 ALTER TABLE `AUTHENTICATOR_CONFIG` DISABLE KEYS */;
INSERT INTO `AUTHENTICATOR_CONFIG` VALUES
('6bb20ec9-708a-40a8-8a5d-13217c2ed0f4','review profile config','61c254e2-095d-42b9-b8cc-4546b124e548'),
('6dd6505a-cef7-4925-a4bf-2148bb0146cb','review profile config','139c1488-d000-4061-922b-0c0b518a57db'),
('8e64b6bb-c651-4eeb-a38b-65b8536effe5','create unique user config','139c1488-d000-4061-922b-0c0b518a57db'),
('eab807c3-4054-45ac-addd-583d55b9cb64','create unique user config','61c254e2-095d-42b9-b8cc-4546b124e548');
/*!40000 ALTER TABLE `AUTHENTICATOR_CONFIG` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `AUTHENTICATOR_CONFIG_ENTRY`
--

DROP TABLE IF EXISTS `AUTHENTICATOR_CONFIG_ENTRY`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `AUTHENTICATOR_CONFIG_ENTRY` (
  `AUTHENTICATOR_ID` varchar(36) NOT NULL,
  `VALUE` longtext DEFAULT NULL,
  `NAME` varchar(255) NOT NULL,
  PRIMARY KEY (`AUTHENTICATOR_ID`,`NAME`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `AUTHENTICATOR_CONFIG_ENTRY`
--

LOCK TABLES `AUTHENTICATOR_CONFIG_ENTRY` WRITE;
/*!40000 ALTER TABLE `AUTHENTICATOR_CONFIG_ENTRY` DISABLE KEYS */;
INSERT INTO `AUTHENTICATOR_CONFIG_ENTRY` VALUES
('6bb20ec9-708a-40a8-8a5d-13217c2ed0f4','missing','update.profile.on.first.login'),
('6dd6505a-cef7-4925-a4bf-2148bb0146cb','missing','update.profile.on.first.login'),
('8e64b6bb-c651-4eeb-a38b-65b8536effe5','false','require.password.update.after.registration'),
('eab807c3-4054-45ac-addd-583d55b9cb64','false','require.password.update.after.registration');
/*!40000 ALTER TABLE `AUTHENTICATOR_CONFIG_ENTRY` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `BROKER_LINK`
--

DROP TABLE IF EXISTS `BROKER_LINK`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `BROKER_LINK` (
  `IDENTITY_PROVIDER` varchar(255) NOT NULL,
  `STORAGE_PROVIDER_ID` varchar(255) DEFAULT NULL,
  `REALM_ID` varchar(36) NOT NULL,
  `BROKER_USER_ID` varchar(255) DEFAULT NULL,
  `BROKER_USERNAME` varchar(255) DEFAULT NULL,
  `TOKEN` text DEFAULT NULL,
  `USER_ID` varchar(255) NOT NULL,
  PRIMARY KEY (`IDENTITY_PROVIDER`,`USER_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `BROKER_LINK`
--

LOCK TABLES `BROKER_LINK` WRITE;
/*!40000 ALTER TABLE `BROKER_LINK` DISABLE KEYS */;
/*!40000 ALTER TABLE `BROKER_LINK` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `CLIENT`
--

DROP TABLE IF EXISTS `CLIENT`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CLIENT` (
  `ID` varchar(36) NOT NULL,
  `ENABLED` bit(1) NOT NULL DEFAULT b'0',
  `FULL_SCOPE_ALLOWED` bit(1) NOT NULL DEFAULT b'0',
  `CLIENT_ID` varchar(255) DEFAULT NULL,
  `NOT_BEFORE` int(11) DEFAULT NULL,
  `PUBLIC_CLIENT` bit(1) NOT NULL DEFAULT b'0',
  `SECRET` varchar(255) DEFAULT NULL,
  `BASE_URL` varchar(255) DEFAULT NULL,
  `BEARER_ONLY` bit(1) NOT NULL DEFAULT b'0',
  `MANAGEMENT_URL` varchar(255) DEFAULT NULL,
  `SURROGATE_AUTH_REQUIRED` bit(1) NOT NULL DEFAULT b'0',
  `REALM_ID` varchar(36) DEFAULT NULL,
  `PROTOCOL` varchar(255) DEFAULT NULL,
  `NODE_REREG_TIMEOUT` int(11) DEFAULT 0,
  `FRONTCHANNEL_LOGOUT` bit(1) NOT NULL DEFAULT b'0',
  `CONSENT_REQUIRED` bit(1) NOT NULL DEFAULT b'0',
  `NAME` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `SERVICE_ACCOUNTS_ENABLED` bit(1) NOT NULL DEFAULT b'0',
  `CLIENT_AUTHENTICATOR_TYPE` varchar(255) DEFAULT NULL,
  `ROOT_URL` varchar(255) DEFAULT NULL,
  `DESCRIPTION` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `REGISTRATION_TOKEN` varchar(255) DEFAULT NULL,
  `STANDARD_FLOW_ENABLED` bit(1) NOT NULL DEFAULT b'1',
  `IMPLICIT_FLOW_ENABLED` bit(1) NOT NULL DEFAULT b'0',
  `DIRECT_ACCESS_GRANTS_ENABLED` bit(1) NOT NULL DEFAULT b'0',
  `ALWAYS_DISPLAY_IN_CONSOLE` bit(1) NOT NULL DEFAULT b'0',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK_B71CJLBENV945RB6GCON438AT` (`REALM_ID`,`CLIENT_ID`),
  KEY `IDX_CLIENT_ID` (`CLIENT_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CLIENT`
--

LOCK TABLES `CLIENT` WRITE;
/*!40000 ALTER TABLE `CLIENT` DISABLE KEYS */;
INSERT INTO `CLIENT` VALUES
('2f7d86a0-e8ba-4b75-9009-2048c5611177','','\0','account-console',0,'',NULL,'/realms/master/account/','\0',NULL,'\0','61c254e2-095d-42b9-b8cc-4546b124e548','openid-connect',0,'\0','\0','${client_account-console}','\0','client-secret','${authBaseUrl}',NULL,NULL,'','\0','\0','\0'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','','','xrd4',0,'\0','OBGvnFSI1njsrnLSmckZbVYmKTPRtFa8','','\0','','\0','139c1488-d000-4061-922b-0c0b518a57db','openid-connect',-1,'','\0','','\0','client-secret','','',NULL,'','\0','','\0'),
('49a49ecd-6045-42e4-9043-edf917f74b18','','','web1',0,'',NULL,'','\0','','\0','139c1488-d000-4061-922b-0c0b518a57db','openid-connect',-1,'','\0','','\0','client-secret','','',NULL,'','\0','','\0'),
('53ef6db9-271e-46c5-bd72-2f12ea045014','','','rucio',0,'\0','DzmZKUfTsGz9bynGIp1gSwI5xen5ce8b','','\0','','\0','139c1488-d000-4061-922b-0c0b518a57db','openid-connect',-1,'','\0','','','client-secret','','',NULL,'','\0','','\0'),
('6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','\0','realm-management',0,'\0',NULL,NULL,'',NULL,'\0','139c1488-d000-4061-922b-0c0b518a57db','openid-connect',0,'\0','\0','${client_realm-management}','\0','client-secret',NULL,NULL,NULL,'','\0','\0','\0'),
('6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','\0','master-realm',0,'\0',NULL,NULL,'',NULL,'\0','61c254e2-095d-42b9-b8cc-4546b124e548',NULL,0,'\0','\0','master Realm','\0','client-secret',NULL,NULL,NULL,'','\0','\0','\0'),
('7429fd2a-6b7c-412c-8042-92288dbcaa58','','\0','admin-cli',0,'',NULL,NULL,'\0',NULL,'\0','61c254e2-095d-42b9-b8cc-4546b124e548','openid-connect',0,'\0','\0','${client_admin-cli}','\0','client-secret',NULL,NULL,NULL,'\0','\0','','\0'),
('79748e7e-06c2-4915-988c-0e30b15d12db','','\0','security-admin-console',0,'',NULL,'/admin/master/console/','\0',NULL,'\0','61c254e2-095d-42b9-b8cc-4546b124e548','openid-connect',0,'\0','\0','${client_security-admin-console}','\0','client-secret','${authAdminUrl}',NULL,NULL,'','\0','\0','\0'),
('8b2528fe-d14e-4b36-8b3d-4a44b89bd6dc','','\0','security-admin-console',0,'',NULL,'/admin/ruciodev/console/','\0',NULL,'\0','139c1488-d000-4061-922b-0c0b518a57db','openid-connect',0,'\0','\0','${client_security-admin-console}','\0','client-secret','${authAdminUrl}',NULL,NULL,'','\0','\0','\0'),
('8d0348ea-8e2b-47bf-a95b-69df3d711ebf','','\0','broker',0,'\0',NULL,NULL,'',NULL,'\0','139c1488-d000-4061-922b-0c0b518a57db','openid-connect',0,'\0','\0','${client_broker}','\0','client-secret',NULL,NULL,NULL,'','\0','\0','\0'),
('95d18788-1f65-4019-81ba-502f2de23982','','\0','admin-cli',0,'',NULL,NULL,'\0',NULL,'\0','139c1488-d000-4061-922b-0c0b518a57db','openid-connect',0,'\0','\0','${client_admin-cli}','\0','client-secret',NULL,NULL,NULL,'\0','\0','','\0'),
('9c1f7e9e-8703-4cca-82b0-d944dbf29287','','\0','account-console',0,'',NULL,'/realms/ruciodev/account/','\0',NULL,'\0','139c1488-d000-4061-922b-0c0b518a57db','openid-connect',0,'\0','\0','${client_account-console}','\0','client-secret','${authBaseUrl}',NULL,NULL,'','\0','\0','\0'),
('a4c24db6-3fe8-4b9c-a183-42a75148d531','','\0','account',0,'',NULL,'/realms/ruciodev/account/','\0',NULL,'\0','139c1488-d000-4061-922b-0c0b518a57db','openid-connect',0,'\0','\0','${client_account}','\0','client-secret','${authBaseUrl}',NULL,NULL,'','\0','\0','\0'),
('c620e22e-74cc-43ed-aa93-92eceaf14f6d','','\0','broker',0,'\0',NULL,NULL,'',NULL,'\0','61c254e2-095d-42b9-b8cc-4546b124e548','openid-connect',0,'\0','\0','${client_broker}','\0','client-secret',NULL,NULL,NULL,'','\0','\0','\0'),
('e32dde36-fa71-4648-aa46-ad822a2b51b6','','\0','account',0,'',NULL,'/realms/master/account/','\0',NULL,'\0','61c254e2-095d-42b9-b8cc-4546b124e548','openid-connect',0,'\0','\0','${client_account}','\0','client-secret','${authBaseUrl}',NULL,NULL,'','\0','\0','\0'),
('e7416090-7f37-401b-b69f-a10a8f8a9a46','','\0','ruciodev-realm',0,'\0',NULL,NULL,'',NULL,'\0','61c254e2-095d-42b9-b8cc-4546b124e548',NULL,0,'\0','\0','ruciodev Realm','\0','client-secret',NULL,NULL,NULL,'','\0','\0','\0');
/*!40000 ALTER TABLE `CLIENT` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `CLIENT_ATTRIBUTES`
--

DROP TABLE IF EXISTS `CLIENT_ATTRIBUTES`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CLIENT_ATTRIBUTES` (
  `CLIENT_ID` varchar(36) NOT NULL,
  `NAME` varchar(255) NOT NULL,
  `VALUE` longtext CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  PRIMARY KEY (`CLIENT_ID`,`NAME`),
  KEY `IDX_CLIENT_ATT_BY_NAME_VALUE` (`NAME`),
  CONSTRAINT `FK3C47C64BEACCA966` FOREIGN KEY (`CLIENT_ID`) REFERENCES `CLIENT` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CLIENT_ATTRIBUTES`
--

LOCK TABLES `CLIENT_ATTRIBUTES` WRITE;
/*!40000 ALTER TABLE `CLIENT_ATTRIBUTES` DISABLE KEYS */;
INSERT INTO `CLIENT_ATTRIBUTES` VALUES
('2f7d86a0-e8ba-4b75-9009-2048c5611177','pkce.code.challenge.method','S256'),
('2f7d86a0-e8ba-4b75-9009-2048c5611177','post.logout.redirect.uris','+'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','acr.loa.map','{}'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','backchannel.logout.revoke.offline.tokens','false'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','backchannel.logout.session.required','true'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','client.secret.creation.time','1703322324'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','client_credentials.use_refresh_token','false'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','display.on.consent.screen','false'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','oauth2.device.authorization.grant.enabled','false'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','oidc.ciba.grant.enabled','false'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','require.pushed.authorization.requests','false'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','tls.client.certificate.bound.access.tokens','false'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','token.response.type.bearer.lower-case','false'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','use.refresh.tokens','true'),
('49a49ecd-6045-42e4-9043-edf917f74b18','backchannel.logout.revoke.offline.tokens','false'),
('49a49ecd-6045-42e4-9043-edf917f74b18','backchannel.logout.session.required','true'),
('49a49ecd-6045-42e4-9043-edf917f74b18','display.on.consent.screen','false'),
('49a49ecd-6045-42e4-9043-edf917f74b18','oauth2.device.authorization.grant.enabled','false'),
('49a49ecd-6045-42e4-9043-edf917f74b18','oidc.ciba.grant.enabled','false'),
('53ef6db9-271e-46c5-bd72-2f12ea045014','backchannel.logout.revoke.offline.tokens','false'),
('53ef6db9-271e-46c5-bd72-2f12ea045014','backchannel.logout.session.required','true'),
('53ef6db9-271e-46c5-bd72-2f12ea045014','client.secret.creation.time','1702649298'),
('53ef6db9-271e-46c5-bd72-2f12ea045014','oauth2.device.authorization.grant.enabled','false'),
('53ef6db9-271e-46c5-bd72-2f12ea045014','oidc.ciba.grant.enabled','false'),
('79748e7e-06c2-4915-988c-0e30b15d12db','pkce.code.challenge.method','S256'),
('79748e7e-06c2-4915-988c-0e30b15d12db','post.logout.redirect.uris','+'),
('8b2528fe-d14e-4b36-8b3d-4a44b89bd6dc','pkce.code.challenge.method','S256'),
('8b2528fe-d14e-4b36-8b3d-4a44b89bd6dc','post.logout.redirect.uris','+'),
('9c1f7e9e-8703-4cca-82b0-d944dbf29287','pkce.code.challenge.method','S256'),
('9c1f7e9e-8703-4cca-82b0-d944dbf29287','post.logout.redirect.uris','+'),
('a4c24db6-3fe8-4b9c-a183-42a75148d531','post.logout.redirect.uris','+'),
('e32dde36-fa71-4648-aa46-ad822a2b51b6','post.logout.redirect.uris','+');
/*!40000 ALTER TABLE `CLIENT_ATTRIBUTES` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `CLIENT_AUTH_FLOW_BINDINGS`
--

DROP TABLE IF EXISTS `CLIENT_AUTH_FLOW_BINDINGS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CLIENT_AUTH_FLOW_BINDINGS` (
  `CLIENT_ID` varchar(36) NOT NULL,
  `FLOW_ID` varchar(36) DEFAULT NULL,
  `BINDING_NAME` varchar(255) NOT NULL,
  PRIMARY KEY (`CLIENT_ID`,`BINDING_NAME`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CLIENT_AUTH_FLOW_BINDINGS`
--

LOCK TABLES `CLIENT_AUTH_FLOW_BINDINGS` WRITE;
/*!40000 ALTER TABLE `CLIENT_AUTH_FLOW_BINDINGS` DISABLE KEYS */;
/*!40000 ALTER TABLE `CLIENT_AUTH_FLOW_BINDINGS` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `CLIENT_INITIAL_ACCESS`
--

DROP TABLE IF EXISTS `CLIENT_INITIAL_ACCESS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CLIENT_INITIAL_ACCESS` (
  `ID` varchar(36) NOT NULL,
  `REALM_ID` varchar(36) NOT NULL,
  `TIMESTAMP` int(11) DEFAULT NULL,
  `EXPIRATION` int(11) DEFAULT NULL,
  `COUNT` int(11) DEFAULT NULL,
  `REMAINING_COUNT` int(11) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_CLIENT_INIT_ACC_REALM` (`REALM_ID`),
  CONSTRAINT `FK_CLIENT_INIT_ACC_REALM` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CLIENT_INITIAL_ACCESS`
--

LOCK TABLES `CLIENT_INITIAL_ACCESS` WRITE;
/*!40000 ALTER TABLE `CLIENT_INITIAL_ACCESS` DISABLE KEYS */;
/*!40000 ALTER TABLE `CLIENT_INITIAL_ACCESS` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `CLIENT_NODE_REGISTRATIONS`
--

DROP TABLE IF EXISTS `CLIENT_NODE_REGISTRATIONS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CLIENT_NODE_REGISTRATIONS` (
  `CLIENT_ID` varchar(36) NOT NULL,
  `VALUE` int(11) DEFAULT NULL,
  `NAME` varchar(255) NOT NULL,
  PRIMARY KEY (`CLIENT_ID`,`NAME`),
  CONSTRAINT `FK4129723BA992F594` FOREIGN KEY (`CLIENT_ID`) REFERENCES `CLIENT` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CLIENT_NODE_REGISTRATIONS`
--

LOCK TABLES `CLIENT_NODE_REGISTRATIONS` WRITE;
/*!40000 ALTER TABLE `CLIENT_NODE_REGISTRATIONS` DISABLE KEYS */;
/*!40000 ALTER TABLE `CLIENT_NODE_REGISTRATIONS` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `CLIENT_SCOPE`
--

DROP TABLE IF EXISTS `CLIENT_SCOPE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CLIENT_SCOPE` (
  `ID` varchar(36) NOT NULL,
  `NAME` varchar(255) DEFAULT NULL,
  `REALM_ID` varchar(36) DEFAULT NULL,
  `DESCRIPTION` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `PROTOCOL` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK_CLI_SCOPE` (`REALM_ID`,`NAME`),
  KEY `IDX_REALM_CLSCOPE` (`REALM_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CLIENT_SCOPE`
--

LOCK TABLES `CLIENT_SCOPE` WRITE;
/*!40000 ALTER TABLE `CLIENT_SCOPE` DISABLE KEYS */;
INSERT INTO `CLIENT_SCOPE` VALUES
('0526da56-aab3-455b-9cc8-2d3d8b0457d6','profile','61c254e2-095d-42b9-b8cc-4546b124e548','OpenID Connect built-in scope: profile','openid-connect'),
('0b211c52-ca02-4f22-b786-5a0b5085fc78','phone','61c254e2-095d-42b9-b8cc-4546b124e548','OpenID Connect built-in scope: phone','openid-connect'),
('0c885a01-891a-481f-9087-f6567af22b13','email','139c1488-d000-4061-922b-0c0b518a57db','OpenID Connect built-in scope: email','openid-connect'),
('21ce4324-232a-46b2-b113-9407b67de017','roles','61c254e2-095d-42b9-b8cc-4546b124e548','OpenID Connect scope for add user roles to the access token','openid-connect'),
('434407ef-1d7f-45e8-b91c-7db10210760a','address','139c1488-d000-4061-922b-0c0b518a57db','OpenID Connect built-in scope: address','openid-connect'),
('4e38235f-7289-4fa2-9840-d4a4fbcd2e0e','address','61c254e2-095d-42b9-b8cc-4546b124e548','OpenID Connect built-in scope: address','openid-connect'),
('4e882685-31e1-451b-9006-cd4ff0dcf750','acr','139c1488-d000-4061-922b-0c0b518a57db','OpenID Connect scope for add acr (authentication context class reference) to the token','openid-connect'),
('5019c5be-c7bd-47b0-a5b3-403a98162efe','phone','139c1488-d000-4061-922b-0c0b518a57db','OpenID Connect built-in scope: phone','openid-connect'),
('596a6555-3ee8-4aa9-8168-b8f0de92dbb1','offline_access','139c1488-d000-4061-922b-0c0b518a57db','OpenID Connect built-in scope: offline_access','openid-connect'),
('5e32d7b8-50b7-4a49-90d4-8c1e467a427c','storage.modify','139c1488-d000-4061-922b-0c0b518a57db','','openid-connect'),
('781fbb54-8552-44a0-9ea2-fab43dcf0b24','web-origins','139c1488-d000-4061-922b-0c0b518a57db','OpenID Connect scope for add allowed web origins to the access token','openid-connect'),
('78975493-67a3-4819-a933-47b99c7c7e60','profile','139c1488-d000-4061-922b-0c0b518a57db','OpenID Connect built-in scope: profile','openid-connect'),
('7c7de55b-c72a-4006-9b14-db1398fed22f','role_list','139c1488-d000-4061-922b-0c0b518a57db','SAML role list','saml'),
('8920b300-1b2f-4d18-ab8a-e975974fd013','role_list','61c254e2-095d-42b9-b8cc-4546b124e548','SAML role list','saml'),
('afc839cc-2307-4260-9924-338375d22c2b','email','61c254e2-095d-42b9-b8cc-4546b124e548','OpenID Connect built-in scope: email','openid-connect'),
('c945998b-68b7-4894-9561-7863799cc667','microprofile-jwt','61c254e2-095d-42b9-b8cc-4546b124e548','Microprofile - JWT built-in scope','openid-connect'),
('ccb9d5ba-bf89-4762-81c1-c9c87da7d1e8','microprofile-jwt','139c1488-d000-4061-922b-0c0b518a57db','Microprofile - JWT built-in scope','openid-connect'),
('d0262425-28ca-4dba-8f8d-12d1146cd725','offline_access','61c254e2-095d-42b9-b8cc-4546b124e548','OpenID Connect built-in scope: offline_access','openid-connect'),
('d6da6000-2013-417d-ad33-33f0804b5b80','roles','139c1488-d000-4061-922b-0c0b518a57db','OpenID Connect scope for add user roles to the access token','openid-connect'),
('e0711367-7927-43ef-9419-42e57c1d7dd4','acr','61c254e2-095d-42b9-b8cc-4546b124e548','OpenID Connect scope for add acr (authentication context class reference) to the token','openid-connect'),
('e58db343-7593-4ffb-8791-bf88b0675191','storage.read','139c1488-d000-4061-922b-0c0b518a57db','','openid-connect'),
('ede179a5-d38e-4943-98f9-627b3b05848d','web-origins','61c254e2-095d-42b9-b8cc-4546b124e548','OpenID Connect scope for add allowed web origins to the access token','openid-connect');
/*!40000 ALTER TABLE `CLIENT_SCOPE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `CLIENT_SCOPE_ATTRIBUTES`
--

DROP TABLE IF EXISTS `CLIENT_SCOPE_ATTRIBUTES`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CLIENT_SCOPE_ATTRIBUTES` (
  `SCOPE_ID` varchar(36) NOT NULL,
  `VALUE` text DEFAULT NULL,
  `NAME` varchar(255) NOT NULL,
  PRIMARY KEY (`SCOPE_ID`,`NAME`),
  KEY `IDX_CLSCOPE_ATTRS` (`SCOPE_ID`),
  CONSTRAINT `FK_CL_SCOPE_ATTR_SCOPE` FOREIGN KEY (`SCOPE_ID`) REFERENCES `CLIENT_SCOPE` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CLIENT_SCOPE_ATTRIBUTES`
--

LOCK TABLES `CLIENT_SCOPE_ATTRIBUTES` WRITE;
/*!40000 ALTER TABLE `CLIENT_SCOPE_ATTRIBUTES` DISABLE KEYS */;
INSERT INTO `CLIENT_SCOPE_ATTRIBUTES` VALUES
('0526da56-aab3-455b-9cc8-2d3d8b0457d6','${profileScopeConsentText}','consent.screen.text'),
('0526da56-aab3-455b-9cc8-2d3d8b0457d6','true','display.on.consent.screen'),
('0526da56-aab3-455b-9cc8-2d3d8b0457d6','true','include.in.token.scope'),
('0b211c52-ca02-4f22-b786-5a0b5085fc78','${phoneScopeConsentText}','consent.screen.text'),
('0b211c52-ca02-4f22-b786-5a0b5085fc78','true','display.on.consent.screen'),
('0b211c52-ca02-4f22-b786-5a0b5085fc78','true','include.in.token.scope'),
('0c885a01-891a-481f-9087-f6567af22b13','${emailScopeConsentText}','consent.screen.text'),
('0c885a01-891a-481f-9087-f6567af22b13','true','display.on.consent.screen'),
('0c885a01-891a-481f-9087-f6567af22b13','true','include.in.token.scope'),
('21ce4324-232a-46b2-b113-9407b67de017','${rolesScopeConsentText}','consent.screen.text'),
('21ce4324-232a-46b2-b113-9407b67de017','true','display.on.consent.screen'),
('21ce4324-232a-46b2-b113-9407b67de017','false','include.in.token.scope'),
('434407ef-1d7f-45e8-b91c-7db10210760a','${addressScopeConsentText}','consent.screen.text'),
('434407ef-1d7f-45e8-b91c-7db10210760a','true','display.on.consent.screen'),
('434407ef-1d7f-45e8-b91c-7db10210760a','true','include.in.token.scope'),
('4e38235f-7289-4fa2-9840-d4a4fbcd2e0e','${addressScopeConsentText}','consent.screen.text'),
('4e38235f-7289-4fa2-9840-d4a4fbcd2e0e','true','display.on.consent.screen'),
('4e38235f-7289-4fa2-9840-d4a4fbcd2e0e','true','include.in.token.scope'),
('4e882685-31e1-451b-9006-cd4ff0dcf750','false','display.on.consent.screen'),
('4e882685-31e1-451b-9006-cd4ff0dcf750','false','include.in.token.scope'),
('5019c5be-c7bd-47b0-a5b3-403a98162efe','${phoneScopeConsentText}','consent.screen.text'),
('5019c5be-c7bd-47b0-a5b3-403a98162efe','true','display.on.consent.screen'),
('5019c5be-c7bd-47b0-a5b3-403a98162efe','true','include.in.token.scope'),
('596a6555-3ee8-4aa9-8168-b8f0de92dbb1','${offlineAccessScopeConsentText}','consent.screen.text'),
('596a6555-3ee8-4aa9-8168-b8f0de92dbb1','true','display.on.consent.screen'),
('5e32d7b8-50b7-4a49-90d4-8c1e467a427c','','consent.screen.text'),
('5e32d7b8-50b7-4a49-90d4-8c1e467a427c','true','display.on.consent.screen'),
('5e32d7b8-50b7-4a49-90d4-8c1e467a427c','storage.modify:*','dynamic.scope.regexp'),
('5e32d7b8-50b7-4a49-90d4-8c1e467a427c','','gui.order'),
('5e32d7b8-50b7-4a49-90d4-8c1e467a427c','true','include.in.token.scope'),
('5e32d7b8-50b7-4a49-90d4-8c1e467a427c','true','is.dynamic.scope'),
('781fbb54-8552-44a0-9ea2-fab43dcf0b24','','consent.screen.text'),
('781fbb54-8552-44a0-9ea2-fab43dcf0b24','false','display.on.consent.screen'),
('781fbb54-8552-44a0-9ea2-fab43dcf0b24','false','include.in.token.scope'),
('78975493-67a3-4819-a933-47b99c7c7e60','${profileScopeConsentText}','consent.screen.text'),
('78975493-67a3-4819-a933-47b99c7c7e60','true','display.on.consent.screen'),
('78975493-67a3-4819-a933-47b99c7c7e60','true','include.in.token.scope'),
('7c7de55b-c72a-4006-9b14-db1398fed22f','${samlRoleListScopeConsentText}','consent.screen.text'),
('7c7de55b-c72a-4006-9b14-db1398fed22f','true','display.on.consent.screen'),
('8920b300-1b2f-4d18-ab8a-e975974fd013','${samlRoleListScopeConsentText}','consent.screen.text'),
('8920b300-1b2f-4d18-ab8a-e975974fd013','true','display.on.consent.screen'),
('afc839cc-2307-4260-9924-338375d22c2b','${emailScopeConsentText}','consent.screen.text'),
('afc839cc-2307-4260-9924-338375d22c2b','true','display.on.consent.screen'),
('afc839cc-2307-4260-9924-338375d22c2b','true','include.in.token.scope'),
('c945998b-68b7-4894-9561-7863799cc667','false','display.on.consent.screen'),
('c945998b-68b7-4894-9561-7863799cc667','true','include.in.token.scope'),
('ccb9d5ba-bf89-4762-81c1-c9c87da7d1e8','false','display.on.consent.screen'),
('ccb9d5ba-bf89-4762-81c1-c9c87da7d1e8','true','include.in.token.scope'),
('d0262425-28ca-4dba-8f8d-12d1146cd725','${offlineAccessScopeConsentText}','consent.screen.text'),
('d0262425-28ca-4dba-8f8d-12d1146cd725','true','display.on.consent.screen'),
('d6da6000-2013-417d-ad33-33f0804b5b80','${rolesScopeConsentText}','consent.screen.text'),
('d6da6000-2013-417d-ad33-33f0804b5b80','true','display.on.consent.screen'),
('d6da6000-2013-417d-ad33-33f0804b5b80','false','include.in.token.scope'),
('e0711367-7927-43ef-9419-42e57c1d7dd4','false','display.on.consent.screen'),
('e0711367-7927-43ef-9419-42e57c1d7dd4','false','include.in.token.scope'),
('e58db343-7593-4ffb-8791-bf88b0675191','','consent.screen.text'),
('e58db343-7593-4ffb-8791-bf88b0675191','true','display.on.consent.screen'),
('e58db343-7593-4ffb-8791-bf88b0675191','storage.read:*','dynamic.scope.regexp'),
('e58db343-7593-4ffb-8791-bf88b0675191','','gui.order'),
('e58db343-7593-4ffb-8791-bf88b0675191','true','include.in.token.scope'),
('e58db343-7593-4ffb-8791-bf88b0675191','true','is.dynamic.scope'),
('ede179a5-d38e-4943-98f9-627b3b05848d','','consent.screen.text'),
('ede179a5-d38e-4943-98f9-627b3b05848d','false','display.on.consent.screen'),
('ede179a5-d38e-4943-98f9-627b3b05848d','false','include.in.token.scope');
/*!40000 ALTER TABLE `CLIENT_SCOPE_ATTRIBUTES` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `CLIENT_SCOPE_CLIENT`
--

DROP TABLE IF EXISTS `CLIENT_SCOPE_CLIENT`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CLIENT_SCOPE_CLIENT` (
  `CLIENT_ID` varchar(255) NOT NULL,
  `SCOPE_ID` varchar(255) NOT NULL,
  `DEFAULT_SCOPE` bit(1) NOT NULL DEFAULT b'0',
  PRIMARY KEY (`CLIENT_ID`,`SCOPE_ID`),
  KEY `IDX_CLSCOPE_CL` (`CLIENT_ID`),
  KEY `IDX_CL_CLSCOPE` (`SCOPE_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CLIENT_SCOPE_CLIENT`
--

LOCK TABLES `CLIENT_SCOPE_CLIENT` WRITE;
/*!40000 ALTER TABLE `CLIENT_SCOPE_CLIENT` DISABLE KEYS */;
INSERT INTO `CLIENT_SCOPE_CLIENT` VALUES
('2f7d86a0-e8ba-4b75-9009-2048c5611177','0526da56-aab3-455b-9cc8-2d3d8b0457d6',''),
('2f7d86a0-e8ba-4b75-9009-2048c5611177','0b211c52-ca02-4f22-b786-5a0b5085fc78','\0'),
('2f7d86a0-e8ba-4b75-9009-2048c5611177','21ce4324-232a-46b2-b113-9407b67de017',''),
('2f7d86a0-e8ba-4b75-9009-2048c5611177','4e38235f-7289-4fa2-9840-d4a4fbcd2e0e','\0'),
('2f7d86a0-e8ba-4b75-9009-2048c5611177','afc839cc-2307-4260-9924-338375d22c2b',''),
('2f7d86a0-e8ba-4b75-9009-2048c5611177','c945998b-68b7-4894-9561-7863799cc667','\0'),
('2f7d86a0-e8ba-4b75-9009-2048c5611177','d0262425-28ca-4dba-8f8d-12d1146cd725','\0'),
('2f7d86a0-e8ba-4b75-9009-2048c5611177','e0711367-7927-43ef-9419-42e57c1d7dd4',''),
('2f7d86a0-e8ba-4b75-9009-2048c5611177','ede179a5-d38e-4943-98f9-627b3b05848d',''),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','0c885a01-891a-481f-9087-f6567af22b13','\0'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','434407ef-1d7f-45e8-b91c-7db10210760a','\0'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','4e882685-31e1-451b-9006-cd4ff0dcf750',''),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','5019c5be-c7bd-47b0-a5b3-403a98162efe','\0'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','596a6555-3ee8-4aa9-8168-b8f0de92dbb1','\0'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','5e32d7b8-50b7-4a49-90d4-8c1e467a427c','\0'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','781fbb54-8552-44a0-9ea2-fab43dcf0b24','\0'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','78975493-67a3-4819-a933-47b99c7c7e60','\0'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','ccb9d5ba-bf89-4762-81c1-c9c87da7d1e8','\0'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','d6da6000-2013-417d-ad33-33f0804b5b80','\0'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','e58db343-7593-4ffb-8791-bf88b0675191','\0'),
('49a49ecd-6045-42e4-9043-edf917f74b18','0c885a01-891a-481f-9087-f6567af22b13',''),
('49a49ecd-6045-42e4-9043-edf917f74b18','434407ef-1d7f-45e8-b91c-7db10210760a','\0'),
('49a49ecd-6045-42e4-9043-edf917f74b18','4e882685-31e1-451b-9006-cd4ff0dcf750',''),
('49a49ecd-6045-42e4-9043-edf917f74b18','5019c5be-c7bd-47b0-a5b3-403a98162efe','\0'),
('49a49ecd-6045-42e4-9043-edf917f74b18','596a6555-3ee8-4aa9-8168-b8f0de92dbb1','\0'),
('49a49ecd-6045-42e4-9043-edf917f74b18','5e32d7b8-50b7-4a49-90d4-8c1e467a427c','\0'),
('49a49ecd-6045-42e4-9043-edf917f74b18','781fbb54-8552-44a0-9ea2-fab43dcf0b24',''),
('49a49ecd-6045-42e4-9043-edf917f74b18','78975493-67a3-4819-a933-47b99c7c7e60',''),
('49a49ecd-6045-42e4-9043-edf917f74b18','ccb9d5ba-bf89-4762-81c1-c9c87da7d1e8','\0'),
('49a49ecd-6045-42e4-9043-edf917f74b18','d6da6000-2013-417d-ad33-33f0804b5b80',''),
('49a49ecd-6045-42e4-9043-edf917f74b18','e58db343-7593-4ffb-8791-bf88b0675191','\0'),
('53ef6db9-271e-46c5-bd72-2f12ea045014','0c885a01-891a-481f-9087-f6567af22b13',''),
('53ef6db9-271e-46c5-bd72-2f12ea045014','434407ef-1d7f-45e8-b91c-7db10210760a','\0'),
('53ef6db9-271e-46c5-bd72-2f12ea045014','4e882685-31e1-451b-9006-cd4ff0dcf750',''),
('53ef6db9-271e-46c5-bd72-2f12ea045014','5019c5be-c7bd-47b0-a5b3-403a98162efe','\0'),
('53ef6db9-271e-46c5-bd72-2f12ea045014','596a6555-3ee8-4aa9-8168-b8f0de92dbb1','\0'),
('53ef6db9-271e-46c5-bd72-2f12ea045014','5e32d7b8-50b7-4a49-90d4-8c1e467a427c','\0'),
('53ef6db9-271e-46c5-bd72-2f12ea045014','781fbb54-8552-44a0-9ea2-fab43dcf0b24',''),
('53ef6db9-271e-46c5-bd72-2f12ea045014','78975493-67a3-4819-a933-47b99c7c7e60',''),
('53ef6db9-271e-46c5-bd72-2f12ea045014','ccb9d5ba-bf89-4762-81c1-c9c87da7d1e8','\0'),
('53ef6db9-271e-46c5-bd72-2f12ea045014','d6da6000-2013-417d-ad33-33f0804b5b80',''),
('53ef6db9-271e-46c5-bd72-2f12ea045014','e58db343-7593-4ffb-8791-bf88b0675191','\0'),
('6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','0c885a01-891a-481f-9087-f6567af22b13',''),
('6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','434407ef-1d7f-45e8-b91c-7db10210760a','\0'),
('6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','4e882685-31e1-451b-9006-cd4ff0dcf750',''),
('6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','5019c5be-c7bd-47b0-a5b3-403a98162efe','\0'),
('6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','596a6555-3ee8-4aa9-8168-b8f0de92dbb1','\0'),
('6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','781fbb54-8552-44a0-9ea2-fab43dcf0b24',''),
('6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','78975493-67a3-4819-a933-47b99c7c7e60',''),
('6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','ccb9d5ba-bf89-4762-81c1-c9c87da7d1e8','\0'),
('6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','d6da6000-2013-417d-ad33-33f0804b5b80',''),
('6fcc4ef0-a82c-453e-90ba-0753d2c11c58','0526da56-aab3-455b-9cc8-2d3d8b0457d6',''),
('6fcc4ef0-a82c-453e-90ba-0753d2c11c58','0b211c52-ca02-4f22-b786-5a0b5085fc78','\0'),
('6fcc4ef0-a82c-453e-90ba-0753d2c11c58','21ce4324-232a-46b2-b113-9407b67de017',''),
('6fcc4ef0-a82c-453e-90ba-0753d2c11c58','4e38235f-7289-4fa2-9840-d4a4fbcd2e0e','\0'),
('6fcc4ef0-a82c-453e-90ba-0753d2c11c58','afc839cc-2307-4260-9924-338375d22c2b',''),
('6fcc4ef0-a82c-453e-90ba-0753d2c11c58','c945998b-68b7-4894-9561-7863799cc667','\0'),
('6fcc4ef0-a82c-453e-90ba-0753d2c11c58','d0262425-28ca-4dba-8f8d-12d1146cd725','\0'),
('6fcc4ef0-a82c-453e-90ba-0753d2c11c58','e0711367-7927-43ef-9419-42e57c1d7dd4',''),
('6fcc4ef0-a82c-453e-90ba-0753d2c11c58','ede179a5-d38e-4943-98f9-627b3b05848d',''),
('7429fd2a-6b7c-412c-8042-92288dbcaa58','0526da56-aab3-455b-9cc8-2d3d8b0457d6',''),
('7429fd2a-6b7c-412c-8042-92288dbcaa58','0b211c52-ca02-4f22-b786-5a0b5085fc78','\0'),
('7429fd2a-6b7c-412c-8042-92288dbcaa58','21ce4324-232a-46b2-b113-9407b67de017',''),
('7429fd2a-6b7c-412c-8042-92288dbcaa58','4e38235f-7289-4fa2-9840-d4a4fbcd2e0e','\0'),
('7429fd2a-6b7c-412c-8042-92288dbcaa58','afc839cc-2307-4260-9924-338375d22c2b',''),
('7429fd2a-6b7c-412c-8042-92288dbcaa58','c945998b-68b7-4894-9561-7863799cc667','\0'),
('7429fd2a-6b7c-412c-8042-92288dbcaa58','d0262425-28ca-4dba-8f8d-12d1146cd725','\0'),
('7429fd2a-6b7c-412c-8042-92288dbcaa58','e0711367-7927-43ef-9419-42e57c1d7dd4',''),
('7429fd2a-6b7c-412c-8042-92288dbcaa58','ede179a5-d38e-4943-98f9-627b3b05848d',''),
('79748e7e-06c2-4915-988c-0e30b15d12db','0526da56-aab3-455b-9cc8-2d3d8b0457d6',''),
('79748e7e-06c2-4915-988c-0e30b15d12db','0b211c52-ca02-4f22-b786-5a0b5085fc78','\0'),
('79748e7e-06c2-4915-988c-0e30b15d12db','21ce4324-232a-46b2-b113-9407b67de017',''),
('79748e7e-06c2-4915-988c-0e30b15d12db','4e38235f-7289-4fa2-9840-d4a4fbcd2e0e','\0'),
('79748e7e-06c2-4915-988c-0e30b15d12db','afc839cc-2307-4260-9924-338375d22c2b',''),
('79748e7e-06c2-4915-988c-0e30b15d12db','c945998b-68b7-4894-9561-7863799cc667','\0'),
('79748e7e-06c2-4915-988c-0e30b15d12db','d0262425-28ca-4dba-8f8d-12d1146cd725','\0'),
('79748e7e-06c2-4915-988c-0e30b15d12db','e0711367-7927-43ef-9419-42e57c1d7dd4',''),
('79748e7e-06c2-4915-988c-0e30b15d12db','ede179a5-d38e-4943-98f9-627b3b05848d',''),
('8b2528fe-d14e-4b36-8b3d-4a44b89bd6dc','0c885a01-891a-481f-9087-f6567af22b13',''),
('8b2528fe-d14e-4b36-8b3d-4a44b89bd6dc','434407ef-1d7f-45e8-b91c-7db10210760a','\0'),
('8b2528fe-d14e-4b36-8b3d-4a44b89bd6dc','4e882685-31e1-451b-9006-cd4ff0dcf750',''),
('8b2528fe-d14e-4b36-8b3d-4a44b89bd6dc','5019c5be-c7bd-47b0-a5b3-403a98162efe','\0'),
('8b2528fe-d14e-4b36-8b3d-4a44b89bd6dc','596a6555-3ee8-4aa9-8168-b8f0de92dbb1','\0'),
('8b2528fe-d14e-4b36-8b3d-4a44b89bd6dc','781fbb54-8552-44a0-9ea2-fab43dcf0b24',''),
('8b2528fe-d14e-4b36-8b3d-4a44b89bd6dc','78975493-67a3-4819-a933-47b99c7c7e60',''),
('8b2528fe-d14e-4b36-8b3d-4a44b89bd6dc','ccb9d5ba-bf89-4762-81c1-c9c87da7d1e8','\0'),
('8b2528fe-d14e-4b36-8b3d-4a44b89bd6dc','d6da6000-2013-417d-ad33-33f0804b5b80',''),
('8d0348ea-8e2b-47bf-a95b-69df3d711ebf','0c885a01-891a-481f-9087-f6567af22b13',''),
('8d0348ea-8e2b-47bf-a95b-69df3d711ebf','434407ef-1d7f-45e8-b91c-7db10210760a','\0'),
('8d0348ea-8e2b-47bf-a95b-69df3d711ebf','4e882685-31e1-451b-9006-cd4ff0dcf750',''),
('8d0348ea-8e2b-47bf-a95b-69df3d711ebf','5019c5be-c7bd-47b0-a5b3-403a98162efe','\0'),
('8d0348ea-8e2b-47bf-a95b-69df3d711ebf','596a6555-3ee8-4aa9-8168-b8f0de92dbb1','\0'),
('8d0348ea-8e2b-47bf-a95b-69df3d711ebf','781fbb54-8552-44a0-9ea2-fab43dcf0b24',''),
('8d0348ea-8e2b-47bf-a95b-69df3d711ebf','78975493-67a3-4819-a933-47b99c7c7e60',''),
('8d0348ea-8e2b-47bf-a95b-69df3d711ebf','ccb9d5ba-bf89-4762-81c1-c9c87da7d1e8','\0'),
('8d0348ea-8e2b-47bf-a95b-69df3d711ebf','d6da6000-2013-417d-ad33-33f0804b5b80',''),
('95d18788-1f65-4019-81ba-502f2de23982','0c885a01-891a-481f-9087-f6567af22b13',''),
('95d18788-1f65-4019-81ba-502f2de23982','434407ef-1d7f-45e8-b91c-7db10210760a','\0'),
('95d18788-1f65-4019-81ba-502f2de23982','4e882685-31e1-451b-9006-cd4ff0dcf750',''),
('95d18788-1f65-4019-81ba-502f2de23982','5019c5be-c7bd-47b0-a5b3-403a98162efe','\0'),
('95d18788-1f65-4019-81ba-502f2de23982','596a6555-3ee8-4aa9-8168-b8f0de92dbb1','\0'),
('95d18788-1f65-4019-81ba-502f2de23982','781fbb54-8552-44a0-9ea2-fab43dcf0b24',''),
('95d18788-1f65-4019-81ba-502f2de23982','78975493-67a3-4819-a933-47b99c7c7e60',''),
('95d18788-1f65-4019-81ba-502f2de23982','ccb9d5ba-bf89-4762-81c1-c9c87da7d1e8','\0'),
('95d18788-1f65-4019-81ba-502f2de23982','d6da6000-2013-417d-ad33-33f0804b5b80',''),
('9c1f7e9e-8703-4cca-82b0-d944dbf29287','0c885a01-891a-481f-9087-f6567af22b13',''),
('9c1f7e9e-8703-4cca-82b0-d944dbf29287','434407ef-1d7f-45e8-b91c-7db10210760a','\0'),
('9c1f7e9e-8703-4cca-82b0-d944dbf29287','4e882685-31e1-451b-9006-cd4ff0dcf750',''),
('9c1f7e9e-8703-4cca-82b0-d944dbf29287','5019c5be-c7bd-47b0-a5b3-403a98162efe','\0'),
('9c1f7e9e-8703-4cca-82b0-d944dbf29287','596a6555-3ee8-4aa9-8168-b8f0de92dbb1','\0'),
('9c1f7e9e-8703-4cca-82b0-d944dbf29287','781fbb54-8552-44a0-9ea2-fab43dcf0b24',''),
('9c1f7e9e-8703-4cca-82b0-d944dbf29287','78975493-67a3-4819-a933-47b99c7c7e60',''),
('9c1f7e9e-8703-4cca-82b0-d944dbf29287','ccb9d5ba-bf89-4762-81c1-c9c87da7d1e8','\0'),
('9c1f7e9e-8703-4cca-82b0-d944dbf29287','d6da6000-2013-417d-ad33-33f0804b5b80',''),
('a4c24db6-3fe8-4b9c-a183-42a75148d531','0c885a01-891a-481f-9087-f6567af22b13',''),
('a4c24db6-3fe8-4b9c-a183-42a75148d531','434407ef-1d7f-45e8-b91c-7db10210760a','\0'),
('a4c24db6-3fe8-4b9c-a183-42a75148d531','4e882685-31e1-451b-9006-cd4ff0dcf750',''),
('a4c24db6-3fe8-4b9c-a183-42a75148d531','5019c5be-c7bd-47b0-a5b3-403a98162efe','\0'),
('a4c24db6-3fe8-4b9c-a183-42a75148d531','596a6555-3ee8-4aa9-8168-b8f0de92dbb1','\0'),
('a4c24db6-3fe8-4b9c-a183-42a75148d531','781fbb54-8552-44a0-9ea2-fab43dcf0b24',''),
('a4c24db6-3fe8-4b9c-a183-42a75148d531','78975493-67a3-4819-a933-47b99c7c7e60',''),
('a4c24db6-3fe8-4b9c-a183-42a75148d531','ccb9d5ba-bf89-4762-81c1-c9c87da7d1e8','\0'),
('a4c24db6-3fe8-4b9c-a183-42a75148d531','d6da6000-2013-417d-ad33-33f0804b5b80',''),
('c620e22e-74cc-43ed-aa93-92eceaf14f6d','0526da56-aab3-455b-9cc8-2d3d8b0457d6',''),
('c620e22e-74cc-43ed-aa93-92eceaf14f6d','0b211c52-ca02-4f22-b786-5a0b5085fc78','\0'),
('c620e22e-74cc-43ed-aa93-92eceaf14f6d','21ce4324-232a-46b2-b113-9407b67de017',''),
('c620e22e-74cc-43ed-aa93-92eceaf14f6d','4e38235f-7289-4fa2-9840-d4a4fbcd2e0e','\0'),
('c620e22e-74cc-43ed-aa93-92eceaf14f6d','afc839cc-2307-4260-9924-338375d22c2b',''),
('c620e22e-74cc-43ed-aa93-92eceaf14f6d','c945998b-68b7-4894-9561-7863799cc667','\0'),
('c620e22e-74cc-43ed-aa93-92eceaf14f6d','d0262425-28ca-4dba-8f8d-12d1146cd725','\0'),
('c620e22e-74cc-43ed-aa93-92eceaf14f6d','e0711367-7927-43ef-9419-42e57c1d7dd4',''),
('c620e22e-74cc-43ed-aa93-92eceaf14f6d','ede179a5-d38e-4943-98f9-627b3b05848d',''),
('e32dde36-fa71-4648-aa46-ad822a2b51b6','0526da56-aab3-455b-9cc8-2d3d8b0457d6',''),
('e32dde36-fa71-4648-aa46-ad822a2b51b6','0b211c52-ca02-4f22-b786-5a0b5085fc78','\0'),
('e32dde36-fa71-4648-aa46-ad822a2b51b6','21ce4324-232a-46b2-b113-9407b67de017',''),
('e32dde36-fa71-4648-aa46-ad822a2b51b6','4e38235f-7289-4fa2-9840-d4a4fbcd2e0e','\0'),
('e32dde36-fa71-4648-aa46-ad822a2b51b6','afc839cc-2307-4260-9924-338375d22c2b',''),
('e32dde36-fa71-4648-aa46-ad822a2b51b6','c945998b-68b7-4894-9561-7863799cc667','\0'),
('e32dde36-fa71-4648-aa46-ad822a2b51b6','d0262425-28ca-4dba-8f8d-12d1146cd725','\0'),
('e32dde36-fa71-4648-aa46-ad822a2b51b6','e0711367-7927-43ef-9419-42e57c1d7dd4',''),
('e32dde36-fa71-4648-aa46-ad822a2b51b6','ede179a5-d38e-4943-98f9-627b3b05848d','');
/*!40000 ALTER TABLE `CLIENT_SCOPE_CLIENT` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `CLIENT_SCOPE_ROLE_MAPPING`
--

DROP TABLE IF EXISTS `CLIENT_SCOPE_ROLE_MAPPING`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CLIENT_SCOPE_ROLE_MAPPING` (
  `SCOPE_ID` varchar(36) NOT NULL,
  `ROLE_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`SCOPE_ID`,`ROLE_ID`),
  KEY `IDX_CLSCOPE_ROLE` (`SCOPE_ID`),
  KEY `IDX_ROLE_CLSCOPE` (`ROLE_ID`),
  CONSTRAINT `FK_CL_SCOPE_RM_SCOPE` FOREIGN KEY (`SCOPE_ID`) REFERENCES `CLIENT_SCOPE` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CLIENT_SCOPE_ROLE_MAPPING`
--

LOCK TABLES `CLIENT_SCOPE_ROLE_MAPPING` WRITE;
/*!40000 ALTER TABLE `CLIENT_SCOPE_ROLE_MAPPING` DISABLE KEYS */;
INSERT INTO `CLIENT_SCOPE_ROLE_MAPPING` VALUES
('596a6555-3ee8-4aa9-8168-b8f0de92dbb1','ddeca6bf-8e98-491c-b9bd-52a60e03b019'),
('d0262425-28ca-4dba-8f8d-12d1146cd725','00548d93-c95b-4b4e-935f-dc7350eeab18');
/*!40000 ALTER TABLE `CLIENT_SCOPE_ROLE_MAPPING` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `CLIENT_SESSION`
--

DROP TABLE IF EXISTS `CLIENT_SESSION`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CLIENT_SESSION` (
  `ID` varchar(36) NOT NULL,
  `CLIENT_ID` varchar(36) DEFAULT NULL,
  `REDIRECT_URI` varchar(255) DEFAULT NULL,
  `STATE` varchar(255) DEFAULT NULL,
  `TIMESTAMP` int(11) DEFAULT NULL,
  `SESSION_ID` varchar(36) DEFAULT NULL,
  `AUTH_METHOD` varchar(255) DEFAULT NULL,
  `REALM_ID` varchar(255) DEFAULT NULL,
  `AUTH_USER_ID` varchar(36) DEFAULT NULL,
  `CURRENT_ACTION` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_CLIENT_SESSION_SESSION` (`SESSION_ID`),
  CONSTRAINT `FK_B4AO2VCVAT6UKAU74WBWTFQO1` FOREIGN KEY (`SESSION_ID`) REFERENCES `USER_SESSION` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CLIENT_SESSION`
--

LOCK TABLES `CLIENT_SESSION` WRITE;
/*!40000 ALTER TABLE `CLIENT_SESSION` DISABLE KEYS */;
/*!40000 ALTER TABLE `CLIENT_SESSION` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `CLIENT_SESSION_AUTH_STATUS`
--

DROP TABLE IF EXISTS `CLIENT_SESSION_AUTH_STATUS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CLIENT_SESSION_AUTH_STATUS` (
  `AUTHENTICATOR` varchar(36) NOT NULL,
  `STATUS` int(11) DEFAULT NULL,
  `CLIENT_SESSION` varchar(36) NOT NULL,
  PRIMARY KEY (`CLIENT_SESSION`,`AUTHENTICATOR`),
  CONSTRAINT `AUTH_STATUS_CONSTRAINT` FOREIGN KEY (`CLIENT_SESSION`) REFERENCES `CLIENT_SESSION` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CLIENT_SESSION_AUTH_STATUS`
--

LOCK TABLES `CLIENT_SESSION_AUTH_STATUS` WRITE;
/*!40000 ALTER TABLE `CLIENT_SESSION_AUTH_STATUS` DISABLE KEYS */;
/*!40000 ALTER TABLE `CLIENT_SESSION_AUTH_STATUS` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `CLIENT_SESSION_NOTE`
--

DROP TABLE IF EXISTS `CLIENT_SESSION_NOTE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CLIENT_SESSION_NOTE` (
  `NAME` varchar(255) NOT NULL,
  `VALUE` varchar(255) DEFAULT NULL,
  `CLIENT_SESSION` varchar(36) NOT NULL,
  PRIMARY KEY (`CLIENT_SESSION`,`NAME`),
  CONSTRAINT `FK5EDFB00FF51C2736` FOREIGN KEY (`CLIENT_SESSION`) REFERENCES `CLIENT_SESSION` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CLIENT_SESSION_NOTE`
--

LOCK TABLES `CLIENT_SESSION_NOTE` WRITE;
/*!40000 ALTER TABLE `CLIENT_SESSION_NOTE` DISABLE KEYS */;
/*!40000 ALTER TABLE `CLIENT_SESSION_NOTE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `CLIENT_SESSION_PROT_MAPPER`
--

DROP TABLE IF EXISTS `CLIENT_SESSION_PROT_MAPPER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CLIENT_SESSION_PROT_MAPPER` (
  `PROTOCOL_MAPPER_ID` varchar(36) NOT NULL,
  `CLIENT_SESSION` varchar(36) NOT NULL,
  PRIMARY KEY (`CLIENT_SESSION`,`PROTOCOL_MAPPER_ID`),
  CONSTRAINT `FK_33A8SGQW18I532811V7O2DK89` FOREIGN KEY (`CLIENT_SESSION`) REFERENCES `CLIENT_SESSION` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CLIENT_SESSION_PROT_MAPPER`
--

LOCK TABLES `CLIENT_SESSION_PROT_MAPPER` WRITE;
/*!40000 ALTER TABLE `CLIENT_SESSION_PROT_MAPPER` DISABLE KEYS */;
/*!40000 ALTER TABLE `CLIENT_SESSION_PROT_MAPPER` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `CLIENT_SESSION_ROLE`
--

DROP TABLE IF EXISTS `CLIENT_SESSION_ROLE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CLIENT_SESSION_ROLE` (
  `ROLE_ID` varchar(255) NOT NULL,
  `CLIENT_SESSION` varchar(36) NOT NULL,
  PRIMARY KEY (`CLIENT_SESSION`,`ROLE_ID`),
  CONSTRAINT `FK_11B7SGQW18I532811V7O2DV76` FOREIGN KEY (`CLIENT_SESSION`) REFERENCES `CLIENT_SESSION` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CLIENT_SESSION_ROLE`
--

LOCK TABLES `CLIENT_SESSION_ROLE` WRITE;
/*!40000 ALTER TABLE `CLIENT_SESSION_ROLE` DISABLE KEYS */;
/*!40000 ALTER TABLE `CLIENT_SESSION_ROLE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `CLIENT_USER_SESSION_NOTE`
--

DROP TABLE IF EXISTS `CLIENT_USER_SESSION_NOTE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CLIENT_USER_SESSION_NOTE` (
  `NAME` varchar(255) NOT NULL,
  `VALUE` text DEFAULT NULL,
  `CLIENT_SESSION` varchar(36) NOT NULL,
  PRIMARY KEY (`CLIENT_SESSION`,`NAME`),
  CONSTRAINT `FK_CL_USR_SES_NOTE` FOREIGN KEY (`CLIENT_SESSION`) REFERENCES `CLIENT_SESSION` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CLIENT_USER_SESSION_NOTE`
--

LOCK TABLES `CLIENT_USER_SESSION_NOTE` WRITE;
/*!40000 ALTER TABLE `CLIENT_USER_SESSION_NOTE` DISABLE KEYS */;
/*!40000 ALTER TABLE `CLIENT_USER_SESSION_NOTE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `COMPONENT`
--

DROP TABLE IF EXISTS `COMPONENT`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `COMPONENT` (
  `ID` varchar(36) NOT NULL,
  `NAME` varchar(255) DEFAULT NULL,
  `PARENT_ID` varchar(36) DEFAULT NULL,
  `PROVIDER_ID` varchar(36) DEFAULT NULL,
  `PROVIDER_TYPE` varchar(255) DEFAULT NULL,
  `REALM_ID` varchar(36) DEFAULT NULL,
  `SUB_TYPE` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_COMPONENT_REALM` (`REALM_ID`),
  KEY `IDX_COMPONENT_PROVIDER_TYPE` (`PROVIDER_TYPE`),
  CONSTRAINT `FK_COMPONENT_REALM` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `COMPONENT`
--

LOCK TABLES `COMPONENT` WRITE;
/*!40000 ALTER TABLE `COMPONENT` DISABLE KEYS */;
INSERT INTO `COMPONENT` VALUES
('1ac94255-7f50-4520-a7b4-7f6e8641359a','rsa-generated','61c254e2-095d-42b9-b8cc-4546b124e548','rsa-generated','org.keycloak.keys.KeyProvider','61c254e2-095d-42b9-b8cc-4546b124e548',NULL),
('2522770c-bcb0-41ae-8ba5-d8fc67d8a2cf','Allowed Client Scopes','139c1488-d000-4061-922b-0c0b518a57db','allowed-client-templates','org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy','139c1488-d000-4061-922b-0c0b518a57db','authenticated'),
('30a5896d-1048-4cfb-ad14-a22602414f90','Consent Required','139c1488-d000-4061-922b-0c0b518a57db','consent-required','org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy','139c1488-d000-4061-922b-0c0b518a57db','anonymous'),
('3666c8cd-f08c-45b7-9bca-da4fc3858680','Allowed Protocol Mapper Types','139c1488-d000-4061-922b-0c0b518a57db','allowed-protocol-mappers','org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy','139c1488-d000-4061-922b-0c0b518a57db','anonymous'),
('3c8b6695-2ed0-41d6-871d-dcddcfc25c31','Trusted Hosts','61c254e2-095d-42b9-b8cc-4546b124e548','trusted-hosts','org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy','61c254e2-095d-42b9-b8cc-4546b124e548','anonymous'),
('58c6f834-5934-4634-b020-7417e2ad2195','Full Scope Disabled','139c1488-d000-4061-922b-0c0b518a57db','scope','org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy','139c1488-d000-4061-922b-0c0b518a57db','anonymous'),
('5a6b3d2e-57dd-4ef9-bd0a-ec62b5d9add1','Allowed Protocol Mapper Types','61c254e2-095d-42b9-b8cc-4546b124e548','allowed-protocol-mappers','org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy','61c254e2-095d-42b9-b8cc-4546b124e548','authenticated'),
('60e8da4c-fe52-47c7-9878-821c92dcd603','Allowed Client Scopes','61c254e2-095d-42b9-b8cc-4546b124e548','allowed-client-templates','org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy','61c254e2-095d-42b9-b8cc-4546b124e548','authenticated'),
('65a294d8-e09e-4b79-9429-07e2e73b906e','hmac-generated','139c1488-d000-4061-922b-0c0b518a57db','hmac-generated','org.keycloak.keys.KeyProvider','139c1488-d000-4061-922b-0c0b518a57db',NULL),
('6683fbb3-ae55-419b-981d-d7463f0ce979','Allowed Protocol Mapper Types','139c1488-d000-4061-922b-0c0b518a57db','allowed-protocol-mappers','org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy','139c1488-d000-4061-922b-0c0b518a57db','authenticated'),
('6b37d7d2-2452-44f6-8813-7d38ed717513','hmac-generated','61c254e2-095d-42b9-b8cc-4546b124e548','hmac-generated','org.keycloak.keys.KeyProvider','61c254e2-095d-42b9-b8cc-4546b124e548',NULL),
('7cb34ca6-8b07-4dc2-83ed-f7b1e48a14b6','rsa-enc-generated','139c1488-d000-4061-922b-0c0b518a57db','rsa-enc-generated','org.keycloak.keys.KeyProvider','139c1488-d000-4061-922b-0c0b518a57db',NULL),
('7d2dd5c8-aa10-44ea-b702-63f4311a60ab','Trusted Hosts','139c1488-d000-4061-922b-0c0b518a57db','trusted-hosts','org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy','139c1488-d000-4061-922b-0c0b518a57db','anonymous'),
('82b495da-9e8b-4652-b1b9-34a5dd832f9d','Max Clients Limit','139c1488-d000-4061-922b-0c0b518a57db','max-clients','org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy','139c1488-d000-4061-922b-0c0b518a57db','anonymous'),
('ae71b196-de10-479f-b594-2258601ad7f2','Allowed Protocol Mapper Types','61c254e2-095d-42b9-b8cc-4546b124e548','allowed-protocol-mappers','org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy','61c254e2-095d-42b9-b8cc-4546b124e548','anonymous'),
('b06bc15a-3a9c-49b2-8653-006b5061dde4','Max Clients Limit','61c254e2-095d-42b9-b8cc-4546b124e548','max-clients','org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy','61c254e2-095d-42b9-b8cc-4546b124e548','anonymous'),
('b34e2381-667d-4eb1-ab53-036419af36d2','Consent Required','61c254e2-095d-42b9-b8cc-4546b124e548','consent-required','org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy','61c254e2-095d-42b9-b8cc-4546b124e548','anonymous'),
('b9b9bb41-a6dc-412d-9015-a1d595e994dd','rsa-enc-generated','61c254e2-095d-42b9-b8cc-4546b124e548','rsa-enc-generated','org.keycloak.keys.KeyProvider','61c254e2-095d-42b9-b8cc-4546b124e548',NULL),
('bd975168-5867-47f4-b1d3-ea2b87c5cf1a','Allowed Client Scopes','61c254e2-095d-42b9-b8cc-4546b124e548','allowed-client-templates','org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy','61c254e2-095d-42b9-b8cc-4546b124e548','anonymous'),
('c0a93b52-cdd4-456a-a284-bb843f67f974','Allowed Client Scopes','139c1488-d000-4061-922b-0c0b518a57db','allowed-client-templates','org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy','139c1488-d000-4061-922b-0c0b518a57db','anonymous'),
('d36f7915-c459-40ef-a00c-2aacf0649140','Full Scope Disabled','61c254e2-095d-42b9-b8cc-4546b124e548','scope','org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy','61c254e2-095d-42b9-b8cc-4546b124e548','anonymous'),
('d64f1292-2bfb-4bb0-99c1-a107973d9252','aes-generated','61c254e2-095d-42b9-b8cc-4546b124e548','aes-generated','org.keycloak.keys.KeyProvider','61c254e2-095d-42b9-b8cc-4546b124e548',NULL),
('d8d3528a-e099-4ccf-9d6e-072e57d62fc5','rsa-generated','139c1488-d000-4061-922b-0c0b518a57db','rsa-generated','org.keycloak.keys.KeyProvider','139c1488-d000-4061-922b-0c0b518a57db',NULL),
('fdfbb9c7-a4db-4c5e-be02-4357244b18a1','aes-generated','139c1488-d000-4061-922b-0c0b518a57db','aes-generated','org.keycloak.keys.KeyProvider','139c1488-d000-4061-922b-0c0b518a57db',NULL);
/*!40000 ALTER TABLE `COMPONENT` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `COMPONENT_CONFIG`
--

DROP TABLE IF EXISTS `COMPONENT_CONFIG`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `COMPONENT_CONFIG` (
  `ID` varchar(36) NOT NULL,
  `COMPONENT_ID` varchar(36) NOT NULL,
  `NAME` varchar(255) NOT NULL,
  `VALUE` longtext CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_COMPO_CONFIG_COMPO` (`COMPONENT_ID`),
  CONSTRAINT `FK_COMPONENT_CONFIG` FOREIGN KEY (`COMPONENT_ID`) REFERENCES `COMPONENT` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `COMPONENT_CONFIG`
--

LOCK TABLES `COMPONENT_CONFIG` WRITE;
/*!40000 ALTER TABLE `COMPONENT_CONFIG` DISABLE KEYS */;
INSERT INTO `COMPONENT_CONFIG` VALUES
('0df2098d-7778-4729-9c33-00f9a46e05c1','d8d3528a-e099-4ccf-9d6e-072e57d62fc5','certificate','MIICnzCCAYcCBgGMbc34rzANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhydWNpb2RldjAeFw0yMzEyMTUxNDA2MDRaFw0zMzEyMTUxNDA3NDRaMBMxETAPBgNVBAMMCHJ1Y2lvZGV2MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxdt/7BYb6LofEejtfQQesY6TMaLhXNcXlaAUXWMKCHRGKiQ1J17qZHsfqOHyxzuf30NbAH0fT1SOFC/6nhlzcm7MPso2tBP7gy1x18tgGJQ789BEicwbfSbRyaBgpOgIvykGPW72OFHw0d3/Tw6WGSMRnZaHZqzam9w63E0tYaMRlrAtIt36ORKoJ8JjlKQwMi8XfQ3qzldXkbAlL3c4ApsIaNXhrX3fe1BvRDIRfOvROW9Am/BYQ3ftsheu9hDD0kmsF+rjE0wR0HP5aRwSTvRGbBcQOsVBoAfZBwIrYBxiZAuuVlxeLYfqKnI6nuU7Ehuvk2MbScZehc6T1xWc9QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBbAa2rWVxCPX6rEi+RtIk0SA98rQUjn3Rsoal8S8TRMc/xpfqGRoEY8lM90AAip1IaMNwusi049xPI8VdfzkOTR9R20IRlmhAL9A9nlAtA/2GWkUtLWHITP6yUT2036u/G1x9OUmZF0nxAxy7Z9XpVI6bO0JMCQ7u6kzYBo2G6e0Fd8iHHU4oQCXwoWfZBoqc4vOxM8xnV/gDR5lvxHUUXcqIVXZXpDrkfJzKo5LAPYr6yeoaj7dbIcxELN1qpV3NjQ164WeZpQKS983mdafqtvCJpJxeli4hXK2HNVm1i8vkSsiebaKvTTZ+VecL8y3awyuoyPENfu+K3a7wRWZTM'),
('0f37a7a0-cdfe-48f4-a77c-a45669fa1168','6683fbb3-ae55-419b-981d-d7463f0ce979','allowed-protocol-mapper-types','oidc-sha256-pairwise-sub-mapper'),
('1b01f5d5-0e0d-4740-8fb0-4887c8663561','ae71b196-de10-479f-b594-2258601ad7f2','allowed-protocol-mapper-types','oidc-sha256-pairwise-sub-mapper'),
('1bb66ef2-94fa-4c48-be2e-d4ed860f37fd','ae71b196-de10-479f-b594-2258601ad7f2','allowed-protocol-mapper-types','oidc-address-mapper'),
('1bfc8f29-e8f8-4880-9191-a4bb352433c0','d8d3528a-e099-4ccf-9d6e-072e57d62fc5','privateKey','MIIEpAIBAAKCAQEAxdt/7BYb6LofEejtfQQesY6TMaLhXNcXlaAUXWMKCHRGKiQ1J17qZHsfqOHyxzuf30NbAH0fT1SOFC/6nhlzcm7MPso2tBP7gy1x18tgGJQ789BEicwbfSbRyaBgpOgIvykGPW72OFHw0d3/Tw6WGSMRnZaHZqzam9w63E0tYaMRlrAtIt36ORKoJ8JjlKQwMi8XfQ3qzldXkbAlL3c4ApsIaNXhrX3fe1BvRDIRfOvROW9Am/BYQ3ftsheu9hDD0kmsF+rjE0wR0HP5aRwSTvRGbBcQOsVBoAfZBwIrYBxiZAuuVlxeLYfqKnI6nuU7Ehuvk2MbScZehc6T1xWc9QIDAQABAoIBAAroLn1Ye6ng5rkRRtQ7L6j4k9cq5DL+vXNXW4AJZ2JvbHXCwLZeplurKOPhrsU6XXYMi73zZ9Ay+FEXEwD3pLRUdMhqU8kqB9WjofC0KqQ4ObTXUIvrF0HXK73qbCFzFBZbn9cvoH2a0MR08S/NvUr98qjmBSlNEpEAezMtQvjskEmxpqoSGPwciV1TUioSD7ueOgq+ArmkPQsbn2cLtMeLz/NUSbHjDQKxmLQfetX9bztnaLNxwZPjhyafqgILPZorgbk/nYh50M9/uc9poJLsWd69FtaWLBggQqlA+lQjSHRV5KEclEPrKcGeFSlrvG85qX+yZcv/PAG5YrRIFyECgYEA4XK2pTG/KSLn+ONV5h2Px68aOsdnZChzW/c5N92r2l7d0x9RRYMbeFyyI2oar7ECtRDB7eKBaKQbrGWP0W0P/nuyBYqJKArvhGpqiKOkF38gChyA76UWn42U6bQVGhr2jcLqx1PSUaDp5zzuat6dCWSYjxlh/H1H/zwDASiO5OECgYEA4Kua+msffGlfbItlEXbZ5EY3KjKFIqvYa2Vp+gJexGwN4facyhIP26ZFw4lwgmBqD0qgdGAnEIbaXZjKEylcEFUUMeFzdgs5cEU+Z38gbtd8vOprMsP9D/2ONqA+CXwpqw/AhHFwNiT0M04t9l6gUaNxd4C5yESwHaOnTDMRJpUCgYEAw/3EBsy+kPaFj/uim5CrhD8XoG3l1k7MKvE7zvNpCUhbs8SQFMwrv3FmdB8z3/UUk3BkB3hYZC322OLaKoiT1PqYAvUy05reKtGQmAUbDEo6AlBRTwTILCEbiihCCBXUrdz72hlmyAwKDDsOUd4Byz6m2hCI/MW1J5B2VDV8NEECgYB8+fiz5HMXWeZjEwedt2dtvEFjj8bPiphQ5ZEWKctdqF3wnKaLIZEAtnWIWCPl4owdBX5MPlB8uQcvmZaPIiq8Sxd4x9jaiVPiSCJ2oBkCj4wr6prHGo7jHkDF0k2wKQlkxtZo1lF9TQEqqQqYSfsUbr7nowu1g8AUPL0LfjzEIQKBgQCm8gXMGKgwK1Nbj7DwzSCsnAWAV14mv1j2LK/SCZRPXFlDP5DCOd6vWId+xQQTfngMYEGISnYhwBS1qO2eX7oThgUr2TZ4i1ARdF16jtPecvFGfIMzeYGvIBjQop12cLXu2sBc2skEBM0h5GMTEAelQ/4/Ud4tNTP6MNT3x5vWsg=='),
('283c675e-71ce-49e3-8c86-f2e09082bc26','6683fbb3-ae55-419b-981d-d7463f0ce979','allowed-protocol-mapper-types','oidc-usermodel-attribute-mapper'),
('3001dae9-83c3-476c-bf83-ed4f31a8a8f3','6683fbb3-ae55-419b-981d-d7463f0ce979','allowed-protocol-mapper-types','oidc-address-mapper'),
('342ef98b-9b8f-429a-a851-78d162f27cf2','d64f1292-2bfb-4bb0-99c1-a107973d9252','priority','100'),
('37e5c48b-23b3-48de-907d-71cb4be66115','5a6b3d2e-57dd-4ef9-bd0a-ec62b5d9add1','allowed-protocol-mapper-types','saml-role-list-mapper'),
('3a20ccff-5a3f-44dc-8e3a-9cbdc58bde8d','6b37d7d2-2452-44f6-8813-7d38ed717513','secret','0d6c7a6tbB7B4yyLkSx0rLSJKEIlvhe6Gu-ZIMpfadZB5ljwu7cIgnEIAqNyiYVj9iYcLdBbRyfBlx_c-NVSxg'),
('4267dd6e-835f-45b5-b37d-13bd6bf16520','5a6b3d2e-57dd-4ef9-bd0a-ec62b5d9add1','allowed-protocol-mapper-types','saml-user-attribute-mapper'),
('463e4312-9416-4ef3-8076-d61a36c3df31','3c8b6695-2ed0-41d6-871d-dcddcfc25c31','client-uris-must-match','true'),
('4ea9a64f-530b-4c96-ad7e-35fb9ba4a70c','7cb34ca6-8b07-4dc2-83ed-f7b1e48a14b6','privateKey','MIIEpQIBAAKCAQEAuqSSIyxaTzUPt//mWjrcE3xtWJV/7B5oOOdzYwmBrmewajcDD8BCpaxkKIpQACL61lw9yItdez/KFmBDYAGQoJdpccUpAl6pxTk62BuSlTTlul1HQARejBsc6gVXXOE238JSLS1f0w7Ow8gTHZC6OJXcib91QCi0H9UoM7cX5gt3aVqY/NohxmZ/X3ibHHU4Dnf0fwLW0eyCHlinbIt9Lrm4gSV+BwYtUvNxaswDI8m6vYneODf7bYATNKrNG4Y6isXl9Tq0imUi55qZUGljYtKZl3x08jRMcQSFxAPfMIHgIDefaPwb9WkWCzeKxkf6G/LdCoY9r2iFWjiedeZHlQIDAQABAoIBABDdsMgFaMbKFnjL4uLJ+Vu4bYApCFWLvOLRhYOQVxvtyksa3Ae3Gb6zaJyiPQ76Gj03Oi0ObPzne4lQmx4Inito61Io3ScV61UDci4XtcQOcukHp1nhWzLhe1gpcebWgjkvq/HhrQxbRPN7t8B+9NkKr9JxzvRkiTxsLHUZ6Uq0HEK5Kub4I3oGCcpZzofjPmKROv1ZCwTNnEssglhh7IVwPuXtBiFfMaAABMu52Z6DEUcqTonYVvM2i7N6VOLqgNBSBvBgkQylplVg97OG3smHGUtDol76x2A/575bdBMItW2J2bDlqBqKcfjLH7VzctKGGOsuAgSvtyDE9XoCpukCgYEA9tiEyC23P1SWK1O6idpw61MkqUOI8PyD+5d0bBBUetxqfgCJQc3CWHV3uCvwdi0jN38w0YHJVCs7wOqXy+wlgOaoiVhoxr5Pvrgsgdn7NRfHqWekKsO8Ffz8AsBG0AeWhBUOHNhoMoc/ajh1EKWdo5JcGaAaqH7D2wxtYAN6mF0CgYEAwZCA2RIBonkCqcT52CsgjCdVWD1+3+hK9wi1zjIRYmCgrMaelrOw3wwpe4zgLr7sSjIZphMl8aOdJTw1M/G6+QpzQ4uPvbK48NraxW3eTvSVTd2Fw5F8JEv4sOj+hLR0P+y36/DnjkGl2bhHdBVa0kD4qevoyp7qYGL+L9kymJkCgYEAiXwzCKOdyuI7+cnavekyt39JjhUVctPSVxEWQRIfW4bksWVvDX2i304d7jBa8BdX5BMth6M4FW83Cs4e2e+fO9o8yLK7OObK17kQ4QoeBoZGKK6XG1KFseGEI6wgRMHVLZ/kimBmOK5nvavQWANGd9KPBZ7M+kgQojKbwLxvTekCgYEAuJp/OAcDRhfQ4Wa5vV9MOD6fF3v2z8a0ECvfcFqx17g+JOl8gE+5pM/tlCaD/DEcG5ryeUAT1QPssIFeYD7vyeocidPFb+7OkO647Mfe2EBNUKivlRfgZKGL+fUMIDYWFI1Hz56+yB519VHZ260uJA3Q2gXiy7OJ5gkjUTD9HykCgYEAsjyLmfIRmTZH3fC9ozJIJmwjiOGfZ+x05hT4P4ah4LMT+0omoqtGgR4oGY6iscmoDQeT8R6GxJB+Yu59PjKYjnVrmkYdYQstgHmTZtKdsbJIdDg7s/20fFeKFSB6AWpl9xs1qZzYwVkyTq+4dUbuhDgl06QelwUIPQeT1+YTe0A='),
('511dea3f-4b2e-4af2-9b14-2072ccf2924d','6683fbb3-ae55-419b-981d-d7463f0ce979','allowed-protocol-mapper-types','oidc-full-name-mapper'),
('519bf517-2255-429b-9596-124a977488a9','3666c8cd-f08c-45b7-9bca-da4fc3858680','allowed-protocol-mapper-types','oidc-usermodel-attribute-mapper'),
('5232fb97-84e6-42db-a2fc-5c8bdcc638f5','6683fbb3-ae55-419b-981d-d7463f0ce979','allowed-protocol-mapper-types','oidc-usermodel-property-mapper'),
('56bbdc49-5b2c-421a-96ce-911b387538c5','7cb34ca6-8b07-4dc2-83ed-f7b1e48a14b6','keyUse','ENC'),
('592627fb-bbd5-4dcf-99a7-e192a133a688','82b495da-9e8b-4652-b1b9-34a5dd832f9d','max-clients','200'),
('5ff9d970-6339-4a53-87e5-cee999703f65','d64f1292-2bfb-4bb0-99c1-a107973d9252','kid','d12ee285-4aa5-4345-ac77-c38d1621130e'),
('60ef3338-eaed-47ed-916e-f316e1f853bd','65a294d8-e09e-4b79-9429-07e2e73b906e','kid','c0379dba-74a6-4bc2-a51e-1c3b2688528c'),
('62209a79-6142-4dca-b9ea-38af23cbbe85','5a6b3d2e-57dd-4ef9-bd0a-ec62b5d9add1','allowed-protocol-mapper-types','oidc-address-mapper'),
('63a8b591-26ea-440c-9486-7935caad6024','3c8b6695-2ed0-41d6-871d-dcddcfc25c31','host-sending-registration-request-must-match','true'),
('65899005-9a2a-4aeb-a80d-ba822cb256ab','b9b9bb41-a6dc-412d-9015-a1d595e994dd','certificate','MIICmzCCAYMCBgGMbc1EVTANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjMxMjE1MTQwNTE4WhcNMzMxMjE1MTQwNjU4WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFH6UhN1UJ4xvtGgt80ZE2B1EXIlBFcjizH0KxD9GqRgU1HXdS6aPMATOFjsUQpLpMnBbRwJj/u9iCYv75IF7kAdIt02J1IY8SKMwqDHa4O6deryWohK9y3maJGYuxAU4zeZELZBcZ/+avt3NaYe7LcKqgp7K7/jRw7N0mL9O46KpNJyKOSrEeDn+VhmFsqF/hLuSRbgk1nxgdII6qqpbTBaPoSwvsGCiqwkZGWrCDfIE0gs/WOwmw0dGTtMw55kHA3GeNqiBmQ6DFXgV62tk0ysAPK1bj/7YuuR8qmPl81Fzg1/bve5zecGWUilLpCYxh+A7UNrVckXA9gr1W3j2fAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAK4/7mr2Q00ha8O+uqEX0YLbm4r/x96H64k4weeJ0fROcW8bLS6y5yNgwww7Z8/692d5tcISrKUS3gFluqj7kQC+G3P9aetQG4gFg3qYzwrUUM1aACe2mGvmYjjmRCoRB7Hloo0Xc3YMDYsNKT6pbisTnJbxfhfmqBnALNV/N94E50A1xtaIcTcio1VtOE09oObMEsI8bGt7lrNYADmsXphnm2NEET+oaALo8RpWGbkyHuMuJRn1kMpB5V4QxvpIgmB7eS6V77NLrVf/uUzMicE2o6I1lMPBcF0q0mVdFC2MQ8t1KftInpc6P9yS8IqbWKnjWJeYeog+KEH7PaSATl0='),
('68c09040-141a-42b8-ac76-c15e6cf6f538','65a294d8-e09e-4b79-9429-07e2e73b906e','secret','6pVAZb-GtEoozuscbYnEaZNGyf4Fk9KGvGB9qjoQjumf9PBwav4FZOfqCXOHVwmy3RFm3-PLzsdHhJ35REiIJA'),
('6b6feb77-127f-4671-bf01-e7c9630122c6','3666c8cd-f08c-45b7-9bca-da4fc3858680','allowed-protocol-mapper-types','oidc-sha256-pairwise-sub-mapper'),
('73be7387-83b6-4eab-8dae-3c257ea7e82b','5a6b3d2e-57dd-4ef9-bd0a-ec62b5d9add1','allowed-protocol-mapper-types','saml-user-property-mapper'),
('765583dc-e479-404d-a01d-e5adc67aa3cf','3666c8cd-f08c-45b7-9bca-da4fc3858680','allowed-protocol-mapper-types','oidc-full-name-mapper'),
('76e00612-37ed-476e-b63c-45258bf4b245','bd975168-5867-47f4-b1d3-ea2b87c5cf1a','allow-default-scopes','true'),
('781a2af6-735e-40b0-bd77-3bb35cf86442','b9b9bb41-a6dc-412d-9015-a1d595e994dd','algorithm','RSA-OAEP'),
('7886f89c-2500-46be-a2f4-7a4b3a2af18f','65a294d8-e09e-4b79-9429-07e2e73b906e','priority','100'),
('8475ab3a-799a-48a6-b999-364a42ac6aa7','b9b9bb41-a6dc-412d-9015-a1d595e994dd','privateKey','MIIEowIBAAKCAQEAxR+lITdVCeMb7RoLfNGRNgdRFyJQRXI4sx9CsQ/RqkYFNR13UumjzAEzhY7FEKS6TJwW0cCY/7vYgmL++SBe5AHSLdNidSGPEijMKgx2uDunXq8lqISvct5miRmLsQFOM3mRC2QXGf/mr7dzWmHuy3CqoKeyu/40cOzdJi/TuOiqTScijkqxHg5/lYZhbKhf4S7kkW4JNZ8YHSCOqqqW0wWj6EsL7BgoqsJGRlqwg3yBNILP1jsJsNHRk7TMOeZBwNxnjaogZkOgxV4FetrZNMrADytW4/+2LrkfKpj5fNRc4Nf273uc3nBllIpS6QmMYfgO1Da1XJFwPYK9Vt49nwIDAQABAoIBAEKtaZXKuaEWiSOyY6Bc4tl7sBo7KRvUfwlX0Z9C0pDeDnTg+rO5BAbFgT/0AwSWM84mHjHlC9u1Fo9EHSr3oCFP3GBT2EH2kAZ8dlLi1GWNCBgm9n4CI7afM9+8HFxLLMCMpltMB+RrgwR88S/pYHTAL3cYQoUEf4iTFlsMYnlw4d/SpzVhDNzeYVYO6R7bY1yH3Act/lJZKf60y4HA4Hd9GirITF+ghDQc4dofZswzPgVrreRlgGYZr8pccSSmurAEzfSDSROrAAB+pO+Y3rfQzUNz5GvC1YBAqRx1zrGkibyql6MdUtCoNTN9iXmQLTirytExVEpn1+LKNjgmfgECgYEA53Bxmt/PIGDIfRe7NPgzYYx7HgBy3U9Ff5+ehKg3uAEEz1OHxfKLvxIJnPh1yW5ppMZdev4fn/wOGLi8HFy+DI7lfHXtEzy7MNItT7644OstzO+6bmA0o58b+Lh0V5o2ybQf7qljlP0Ai4Sbo9T50Eb3JRPwgrKqw6zpV9rUkP8CgYEA2grxITnMAdfX0I1PwZc790990OyyTujxVbJ1cvnmDKOnYdb5g2l2kLbrODxrOG6p+lsAnbxCh2mhkFgDLa4iZShcwB5IlMvOm5uf4RV+puNZFIRnq9JUV7jWyG5GgFsMfaKNfD52Arr4PMeQHcQ4rPHJt/16VRSO+U6E97QPs2ECgYAQ2ExMe3G155VwFWQYzN/gf7sOSfYSSYzDZzjAawXzLI/PD0NYkvi85XExrZvVF2Y1CgMPyqM+n7fe8MMwRUfH3jaxwluJBOiS+xk1LqqCJFvnCKPHGNV7+z6r8bD2F1FZiPSyCD4pP+jkPridSgkMsb2XQ0ZEHQD00QcCz/icvQKBgDd6Xz4H+atiYuwSeH+WXlCfrjCReRDw3i7i2FVn1ivTHAyd6SCRnfRWRmUpolJafe9QZki8FOVlcBFNA4oE64V3jpnnWqpZbPlU0IoxsOb/o7O/uK0UOBeV1ThsLo4MHJJ+4KcDMX2iWvUEBdw9B/qhDqU83np1X6d5XgW0j+YhAoGBAKdmZdCpMEyu2nmek9HVsf0TiSvjKb1zBSAB0t4K20yfbVU6rlz5fudqhcugyFAFGsDp1ynXD94OFYBHFUIVdTuZCSWqF5f8h1+OEZFgFXtIZLlQUxqtYw3/82YTZFXoasv3yiWwkmtEibRiNLrRYICjfxbfSnvXYd5iaoAu2APN'),
('849bb8fb-a6f9-4c9d-8c28-58dc93fe7d97','ae71b196-de10-479f-b594-2258601ad7f2','allowed-protocol-mapper-types','saml-user-property-mapper'),
('8993083d-221d-4a0d-8d7b-3dff337adfe0','c0a93b52-cdd4-456a-a284-bb843f67f974','allow-default-scopes','true'),
('941989ca-bc36-45e7-a83d-2805cffcc475','7cb34ca6-8b07-4dc2-83ed-f7b1e48a14b6','certificate','MIICnzCCAYcCBgGMbc35NTANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhydWNpb2RldjAeFw0yMzEyMTUxNDA2MDRaFw0zMzEyMTUxNDA3NDRaMBMxETAPBgNVBAMMCHJ1Y2lvZGV2MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuqSSIyxaTzUPt//mWjrcE3xtWJV/7B5oOOdzYwmBrmewajcDD8BCpaxkKIpQACL61lw9yItdez/KFmBDYAGQoJdpccUpAl6pxTk62BuSlTTlul1HQARejBsc6gVXXOE238JSLS1f0w7Ow8gTHZC6OJXcib91QCi0H9UoM7cX5gt3aVqY/NohxmZ/X3ibHHU4Dnf0fwLW0eyCHlinbIt9Lrm4gSV+BwYtUvNxaswDI8m6vYneODf7bYATNKrNG4Y6isXl9Tq0imUi55qZUGljYtKZl3x08jRMcQSFxAPfMIHgIDefaPwb9WkWCzeKxkf6G/LdCoY9r2iFWjiedeZHlQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBRmSRb46JF74GPNh6sF/JU33H/xvOC6FedAJpEjRAZwuvUAdWDSL2vTCAzrs7Ns+Z1VvL0eygCI09EqT/WXb33bC5vkDLR82ChwR1twu48aYK1Bc6thHgmA/6d5+qfhFmMdKalq4cG0qAwY7LPDWzu2JF8C7YnQPRvrHI10jK1qMt3w7L+6xFvcJpgW58r7fsnsfOtcqwbZulekiWOJhmvGNMgJKU5W+dR75vGcHjAx0TcM7c5h/8qH2ERczxbl8BvS7SzSD05r6NivpUJkt+JUyDtwJDyidgWlg0BQUchIGFwLGuR280DYD59L44yfgBP4OYdOtFggXHZaF10WKD/'),
('9422fd46-ace5-4ead-8b19-817b1bd7f86c','6683fbb3-ae55-419b-981d-d7463f0ce979','allowed-protocol-mapper-types','saml-user-property-mapper'),
('942bd52e-7dc6-4c49-8ff3-82e94883f6c2','ae71b196-de10-479f-b594-2258601ad7f2','allowed-protocol-mapper-types','oidc-usermodel-attribute-mapper'),
('9c2797b3-cc35-47db-be76-3193f25994a2','1ac94255-7f50-4520-a7b4-7f6e8641359a','certificate','MIICmzCCAYMCBgGMbc1D3jANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjMxMjE1MTQwNTE4WhcNMzMxMjE1MTQwNjU4WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5TzFXb12IkAVpcelboMMvwqWs3+Td8bXatCo9f2033PyhnFw7B3GC1Wzkc1ofL8wFeog5B/LuPiZYL9m2bsqTCno7+ATyKHKI81A56CsqFPaQQ+XW1mh+rvRivJMTRHMVQgkVQY84H9uNM3d9oevslvptaSvhrJix7FVDuReHrRuobfgHj6b5Fm+R6VjGuUSUPfb4u/3fpI0/LGPxBPY7d2/kXSC7eiuOd561LwhDL9/7/y7IM7jsmn0TiBYysbA4OTSFw/RQJlMxtiGQafByYez0OHhwKtAx7Hgq7rLjOqBnT4uM1Ng8dG9VO4fqX5+wCprMwY+usubAEFju4VUNAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAIVJn2qtWmCDKjpWB2Dkmu7rSrua7B7X+o/3sdymswjjfKoLAxRowGJ76t7odLuoLKbzCWq98nTXW9fUthkFlyVA2R6uOQCgskxAGOtmdRi548kB3yn+Jp9fDNMx+tReeTdg/7stjCi+J/cOuUn+oNip9+HD4bhbxwwYU391Dc0Ba5O8x3VqXpgPr51krBWqlUB/FQkCsIy/IZA0SZPxHrKUya+nNtZHYY2GtJ5IG8j0e8SNuBe34LWB1b9OcBbBgcVVGLfq1Nr8vmkJNwG4M0VSlfMomXs6lMn+06ijO7vrvxFbik8xQek20qdDdc7Xjc22UjnMMTtc7eTgz5D9UBo='),
('9d7cdc9e-a643-4531-b1d3-bb5ac49d3f26','ae71b196-de10-479f-b594-2258601ad7f2','allowed-protocol-mapper-types','oidc-usermodel-property-mapper'),
('9d8605a4-0aa5-446a-8019-acc23f790d8d','3666c8cd-f08c-45b7-9bca-da4fc3858680','allowed-protocol-mapper-types','oidc-usermodel-property-mapper'),
('a0aa256f-5690-4706-b721-e776601cd75e','5a6b3d2e-57dd-4ef9-bd0a-ec62b5d9add1','allowed-protocol-mapper-types','oidc-usermodel-property-mapper'),
('a5103f8b-ebb4-48c1-b9db-3941c7852afa','3666c8cd-f08c-45b7-9bca-da4fc3858680','allowed-protocol-mapper-types','saml-role-list-mapper'),
('a599f288-a920-46fe-83cc-20f0ae28e88f','1ac94255-7f50-4520-a7b4-7f6e8641359a','keyUse','SIG'),
('a9277eba-f51c-417f-a853-d1a034d14c9c','1ac94255-7f50-4520-a7b4-7f6e8641359a','privateKey','MIIEogIBAAKCAQEAuU8xV29diJAFaXHpW6DDL8KlrN/k3fG12rQqPX9tN9z8oZxcOwdxgtVs5HNaHy/MBXqIOQfy7j4mWC/Ztm7Kkwp6O/gE8ihyiPNQOegrKhT2kEPl1tZofq70YryTE0RzFUIJFUGPOB/bjTN3faHr7Jb6bWkr4ayYsexVQ7kXh60bqG34B4+m+RZvkelYxrlElD32+Lv936SNPyxj8QT2O3dv5F0gu3orjneetS8IQy/f+/8uyDO47Jp9E4gWMrGwODk0hcP0UCZTMbYhkGnwcmHs9Dh4cCrQMex4Ku6y4zqgZ0+LjNTYPHRvVTuH6l+fsAqazMGPrrLmwBBY7uFVDQIDAQABAoIBAAcDsyWw4ry+XOIUrIVqJLFMYCqW0ApBscVNUBMDXY5BiHOSoGAgpECUVRqhri3jiIjFjl4ASccQZbGtYAOaloLx4NYfyYokE0/RS/5hJi8h24Jy+4KCG7L96uTI6BVQ4D1UAlWCZYo1lIE4C0QfareKMIEPO9i/SIllnYWifjxFtclrJJpCh3pE+lRIaeXcFzd7hqHd4dmZjnfIMs+g/7+ioGuYqx6MIX2rEpRGKRA/C9xDJtmuYpSruk02+plNHpfIF9DO8ViIitr1+LPhDrExS7ZBRUpRneRCpuEBqYo5nvLZxPqo4dnjzeSOLkIPVVi9B8ZlxvUKl5h1/8YRmakCgYEA/cQ6gYxYV7uZP/wTFs02ZgTWlVZ6AYJHo8/93+JobvP2l8KSRS0nY6KSu3elsPodAEq7+8iJkpnoGYsCEN5hHYO3KB13JFd9yrdjaWYu1Tnpfc/d4+55SADwsLwEWXPfxSZ1dgPFrYbX29ug621cHDpX8leyQDQE2lSE9OkRGNUCgYEAuvC4en15BR2bQcWxtUrNznrlCOXFdYr1c8iH8z3D4k8TPvFBiPPDfcVlXX1+DtOgf1QTls4bYPUlF6pXp3Hot/fzyOBxiKP5D+ufdBkFq4MvQNQExOVJLjfkn47Zk1AfN8UtLF/fg/8LWiOcBg6wc5YP5JnyTU4YP1dVmiQqZ1kCgYAPp6pgUZMlnmoe22MmFfTUKFpAjjwqmannvi4QQLxmk+BTjmpNoDJ84AujSwdKurNNUE72gnGSPLJn2P6Aoedl1blX3TF7aXZWKigU2XvsJY10+Hzc0dpjicNPc9nk1tQoKm42oJbyVI4+fvcXbwCusR650ZUqhssB2RL2tOYcHQKBgBhaqA39LrkF5GYrNT2jIzDVPeVs2c64bcXJyDxePZjMKHu4vorzBvLptoz5fmS8GVq9P1gUPejhxxVQMd80rdbZzL7Mzr24bwgt8DYV1HFFw/A0LvLf1CrbSUOoPpw8gfSoEXyIePwfTAFQRlFbtI06bZOgorqDhBEsdZCBSazxAoGAC7RppKwRa3p3scs0msNPcUcjIg0E9kbZoZJHo4OOEgzjdrgMLxXIXkFamu/ZBZEkZ8WDqXxBfRZN6KAtK+dJxt4nqOEyajdSyI0Cm4VIfjKQm2r+5C10AUlbXY59wuGzy25kZ8R+u1LJYhMtJuwn2h2cRk8qZvAOUDUJzbbHKPg='),
('accadbd1-c78b-4c11-a1ba-e9bf27c70fa0','5a6b3d2e-57dd-4ef9-bd0a-ec62b5d9add1','allowed-protocol-mapper-types','oidc-usermodel-attribute-mapper'),
('ad35812d-4ef5-4110-a571-73209ec677dc','6b37d7d2-2452-44f6-8813-7d38ed717513','kid','e6541f63-7cab-4381-b29e-ad2a8594d8ae'),
('b18e0f44-d715-4178-a0da-343e98020106','ae71b196-de10-479f-b594-2258601ad7f2','allowed-protocol-mapper-types','saml-role-list-mapper'),
('b3bd5c9e-c22d-4dc5-98a1-279f1fbe71cd','b06bc15a-3a9c-49b2-8653-006b5061dde4','max-clients','200'),
('b6ed192a-9b9a-4ae1-aefc-b3a9cf9fffc5','5a6b3d2e-57dd-4ef9-bd0a-ec62b5d9add1','allowed-protocol-mapper-types','oidc-full-name-mapper'),
('ba2f1871-5071-426e-a82e-115be7ffa5c8','d64f1292-2bfb-4bb0-99c1-a107973d9252','secret','jyWhhSK-skVwLGmkUoZbxw'),
('bbb4cbd8-92a2-4586-a070-64fff6049226','ae71b196-de10-479f-b594-2258601ad7f2','allowed-protocol-mapper-types','oidc-full-name-mapper'),
('c14236db-b764-4bcd-8132-f16c6957c0c5','6683fbb3-ae55-419b-981d-d7463f0ce979','allowed-protocol-mapper-types','saml-user-attribute-mapper'),
('c3930409-5a34-4d71-947b-34fabe912bb9','3666c8cd-f08c-45b7-9bca-da4fc3858680','allowed-protocol-mapper-types','saml-user-property-mapper'),
('c79c604b-d7f5-4194-8faa-13bf4e73bd7d','1ac94255-7f50-4520-a7b4-7f6e8641359a','priority','100'),
('c7d4df46-41cc-4272-bdc9-226be805399f','6b37d7d2-2452-44f6-8813-7d38ed717513','algorithm','HS256'),
('cb30f9ff-5bfa-4281-a00c-92d6ff0a306f','fdfbb9c7-a4db-4c5e-be02-4357244b18a1','kid','62a05f4d-acbf-40f1-b2d4-2ca9628bef9d'),
('cb7b8de7-24ed-4d64-be66-03e8a12115d9','6683fbb3-ae55-419b-981d-d7463f0ce979','allowed-protocol-mapper-types','saml-role-list-mapper'),
('cd00b034-8a6c-497b-9670-588d25d6361b','7cb34ca6-8b07-4dc2-83ed-f7b1e48a14b6','algorithm','RSA-OAEP'),
('cd38caf1-3e03-4add-8d03-63350f575e00','7d2dd5c8-aa10-44ea-b702-63f4311a60ab','host-sending-registration-request-must-match','true'),
('d94c48c2-9996-4f27-8db3-2a06ba87994b','6b37d7d2-2452-44f6-8813-7d38ed717513','priority','100'),
('db3d61d1-fc9a-4278-ac44-a6f65d5d5824','7cb34ca6-8b07-4dc2-83ed-f7b1e48a14b6','priority','100'),
('e0c6ebe0-5f43-462e-baa6-7aeac4a0d4b7','fdfbb9c7-a4db-4c5e-be02-4357244b18a1','secret','Kdk1ihnJvM5-Alk5i2Swww'),
('e12747ef-f147-4844-9c30-b40012d38748','3666c8cd-f08c-45b7-9bca-da4fc3858680','allowed-protocol-mapper-types','oidc-address-mapper'),
('e3fed243-eb23-40bb-a2a4-2749ee7834e7','7d2dd5c8-aa10-44ea-b702-63f4311a60ab','client-uris-must-match','true'),
('e8279e7f-ddc7-41f6-9a56-7a2accd6a958','b9b9bb41-a6dc-412d-9015-a1d595e994dd','keyUse','ENC'),
('e843fe86-3c2a-422d-923f-10d6707eb918','b9b9bb41-a6dc-412d-9015-a1d595e994dd','priority','100'),
('e8b9f187-9814-4d7d-ab7f-33064817ebcc','5a6b3d2e-57dd-4ef9-bd0a-ec62b5d9add1','allowed-protocol-mapper-types','oidc-sha256-pairwise-sub-mapper'),
('eb6cb7e3-fe6b-4516-842c-77807099eec7','d8d3528a-e099-4ccf-9d6e-072e57d62fc5','priority','100'),
('eec1cefb-9e2e-4f9c-8428-1f2777a37293','65a294d8-e09e-4b79-9429-07e2e73b906e','algorithm','HS256'),
('f1369257-b656-4874-9d09-ae4462774917','ae71b196-de10-479f-b594-2258601ad7f2','allowed-protocol-mapper-types','saml-user-attribute-mapper'),
('f197b326-0122-43c1-8563-a1b51c69a2cd','3666c8cd-f08c-45b7-9bca-da4fc3858680','allowed-protocol-mapper-types','saml-user-attribute-mapper'),
('f2dc47f6-3323-4c41-b984-5848bef0e776','fdfbb9c7-a4db-4c5e-be02-4357244b18a1','priority','100'),
('f7d74a5f-6005-4653-9ecb-58e97db14e25','60e8da4c-fe52-47c7-9878-821c92dcd603','allow-default-scopes','true'),
('f9a7be62-f7bc-4ae2-aec0-d08c46738a41','d8d3528a-e099-4ccf-9d6e-072e57d62fc5','keyUse','SIG'),
('f9e9a70f-c79e-4e0d-987f-57714d0f0d80','2522770c-bcb0-41ae-8ba5-d8fc67d8a2cf','allow-default-scopes','true');
/*!40000 ALTER TABLE `COMPONENT_CONFIG` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `COMPOSITE_ROLE`
--

DROP TABLE IF EXISTS `COMPOSITE_ROLE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `COMPOSITE_ROLE` (
  `COMPOSITE` varchar(36) NOT NULL,
  `CHILD_ROLE` varchar(36) NOT NULL,
  PRIMARY KEY (`COMPOSITE`,`CHILD_ROLE`),
  KEY `IDX_COMPOSITE` (`COMPOSITE`),
  KEY `IDX_COMPOSITE_CHILD` (`CHILD_ROLE`),
  CONSTRAINT `FK_A63WVEKFTU8JO1PNJ81E7MCE2` FOREIGN KEY (`COMPOSITE`) REFERENCES `KEYCLOAK_ROLE` (`ID`),
  CONSTRAINT `FK_GR7THLLB9LU8Q4VQA4524JJY8` FOREIGN KEY (`CHILD_ROLE`) REFERENCES `KEYCLOAK_ROLE` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `COMPOSITE_ROLE`
--

LOCK TABLES `COMPOSITE_ROLE` WRITE;
/*!40000 ALTER TABLE `COMPOSITE_ROLE` DISABLE KEYS */;
INSERT INTO `COMPOSITE_ROLE` VALUES
('01c07194-f50e-42e2-b4e2-b6a835490ca0','678e41c9-9bea-4f92-a223-c4747aa6ee06'),
('2bfb4c07-96ff-4bee-a320-400149aca314','fba53dd0-041c-4824-acc9-5f1c181d6c4c'),
('36351f76-327c-4f18-bb9d-7213f9ad0443','05174a3b-088b-4002-9c29-07538b027be2'),
('36351f76-327c-4f18-bb9d-7213f9ad0443','73e0c1dc-6c4e-4171-acf8-028331b29e98'),
('38491d89-be33-4e91-8c2d-4faf6a8b269d','89e9a8d0-9511-4ae9-9897-0956de721ef2'),
('4109672e-c529-4d28-88e6-8fedf3c20003','53348c67-aca5-4c1c-8752-2952e9aab11f'),
('6fbdc1e8-af2f-402c-9f73-5594291adc5d','1795c388-e345-4ebd-a1d7-446b280ac328'),
('6fd3938c-9f28-423a-b49a-9b7059b52b42','5a4942b6-9d9c-42e3-8acf-f394a4c8653b'),
('714a6f1e-de37-4768-b6c5-f4792079b510','7ee50819-d0a6-4f02-8f14-173ca69f1e88'),
('714a6f1e-de37-4768-b6c5-f4792079b510','cd82ab55-5d73-49a5-b659-3bc83bc4e06b'),
('714a6f1e-de37-4768-b6c5-f4792079b510','ddeca6bf-8e98-491c-b9bd-52a60e03b019'),
('714a6f1e-de37-4768-b6c5-f4792079b510','f83d7f0a-9b46-440e-aebe-e3c1fb78d0f4'),
('a8f531c2-32e6-4497-9418-4f32191c1511','92cd6f9f-d95e-4429-b351-fcf91d487831'),
('a8f531c2-32e6-4497-9418-4f32191c1511','c34bdf52-2dc2-49ba-ab5c-f6f4f41ea594'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','01c07194-f50e-42e2-b4e2-b6a835490ca0'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','20704d30-91d2-411f-9196-55c499d695e5'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','3867b96c-2e58-49f9-8f96-947baf448f06'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','42a33d3d-706d-4ae7-bf4d-46b34e1f6f5a'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','58a0e65c-2c32-4d65-8262-109da2df0be2'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','609171eb-cfe0-4357-bf64-f226b7bf0120'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','678e41c9-9bea-4f92-a223-c4747aa6ee06'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','6ffb1dfd-3599-4020-9d72-a985752c38b5'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','82172a02-4770-4cac-9b17-662296c219a4'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','a99f8c3b-b9cc-474d-88da-b81278c8a540'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','b3fc8427-4555-4e10-89e5-7dac86a0b949'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','b5ff560b-85bd-4754-91c9-d2cc0f4e84dd'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','bef34cd4-1605-4b4f-be25-e2947ab173ad'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','c0728a25-e2bf-409b-adc0-144daffad036'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','e52971bb-c676-44ef-a300-ddea4045558d'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','e6b9c690-17a2-40d7-8aac-2e0893e42b33'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','ef4ebfff-60b0-4e62-b978-bc70ba8f981e'),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','f46ad52d-a078-407f-bd62-1708245a4449'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','009151c1-73fb-49a1-aaac-4fad108e35a6'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','05174a3b-088b-4002-9c29-07538b027be2'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','052dca65-a7ac-40c0-bb1f-44364166a074'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','1185008a-2fc8-4130-a739-6bea4b2c5c42'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','16f17961-625d-40ab-b126-75d204f36f47'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','205450af-538d-40bc-b603-6c3f397a38b8'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','33db5e49-04dc-4308-8482-8f21e65d6d38'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','353d13e0-1758-44c8-935b-033310bb9986'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','36351f76-327c-4f18-bb9d-7213f9ad0443'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','38491d89-be33-4e91-8c2d-4faf6a8b269d'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','4637444f-6a2a-4110-8522-f8b54d0e883b'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','4a691081-0cec-4c8b-bb10-b74cd59896f6'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','4add9c78-35c6-484a-a58c-b71a30d02088'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','5095e6ed-ecea-4edb-af97-4d68dbe60131'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','5a4942b6-9d9c-42e3-8acf-f394a4c8653b'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','640f2839-b2f1-49fa-bb7e-605793c08de8'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','6442256b-075e-446a-80d3-bf6f4e2e1280'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','6b3487ba-98af-4992-a798-40f499258d5a'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','6fd3938c-9f28-423a-b49a-9b7059b52b42'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','73e0c1dc-6c4e-4171-acf8-028331b29e98'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','7dfc3803-4c51-4482-a1cf-a0917a3827cb'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','7e750a3e-d379-47a4-be5d-7837288f5183'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','83406e1d-a189-4b0f-8ec5-81bbeae69990'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','89e9a8d0-9511-4ae9-9897-0956de721ef2'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','8aa9d67b-3631-41b4-928f-8d6e35b53ad4'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','8d7973a1-8d62-4add-91e8-1a6676fc9ecd'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','8f1f8106-eae4-4213-8aa5-1480597cdec0'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','92cd6f9f-d95e-4429-b351-fcf91d487831'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','9cc50a6b-3f60-4fc4-8bd0-43bf1d9d73a0'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','a30019cc-a32c-414c-a159-4bdbff80e001'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','a8f531c2-32e6-4497-9418-4f32191c1511'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','ae7725b3-9a0b-407f-a946-ad3dd390e4f7'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','b5be4df0-94bc-4f40-ae24-5ddba4b46bc8'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','c020bf25-1d76-4643-a446-73d175effe97'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','c120de31-e61d-41b1-a174-5e0fdf6c0ab9'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','c34bdf52-2dc2-49ba-ab5c-f6f4f41ea594'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','f385ab65-af3b-4440-9735-c30448b45280'),
('cd82ab55-5d73-49a5-b659-3bc83bc4e06b','fad25aed-3ae5-4f8a-924e-36378e01b241'),
('df76e680-bebc-4b85-a723-c5adf7ef86c6','00548d93-c95b-4b4e-935f-dc7350eeab18'),
('df76e680-bebc-4b85-a723-c5adf7ef86c6','4109672e-c529-4d28-88e6-8fedf3c20003'),
('df76e680-bebc-4b85-a723-c5adf7ef86c6','4d8aa6fc-a874-4c90-a7d3-07e1799ed673'),
('df76e680-bebc-4b85-a723-c5adf7ef86c6','7a3dbc3a-e26c-4c0e-850b-be0dfc351c45'),
('e6b9c690-17a2-40d7-8aac-2e0893e42b33','42a33d3d-706d-4ae7-bf4d-46b34e1f6f5a'),
('e6b9c690-17a2-40d7-8aac-2e0893e42b33','b5ff560b-85bd-4754-91c9-d2cc0f4e84dd');
/*!40000 ALTER TABLE `COMPOSITE_ROLE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `CREDENTIAL`
--

DROP TABLE IF EXISTS `CREDENTIAL`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CREDENTIAL` (
  `ID` varchar(36) NOT NULL,
  `SALT` tinyblob DEFAULT NULL,
  `TYPE` varchar(255) DEFAULT NULL,
  `USER_ID` varchar(36) DEFAULT NULL,
  `CREATED_DATE` bigint(20) DEFAULT NULL,
  `USER_LABEL` varchar(255) DEFAULT NULL,
  `SECRET_DATA` longtext DEFAULT NULL,
  `CREDENTIAL_DATA` longtext DEFAULT NULL,
  `PRIORITY` int(11) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_USER_CREDENTIAL` (`USER_ID`),
  CONSTRAINT `FK_PFYR0GLASQYL0DEI3KL69R6V0` FOREIGN KEY (`USER_ID`) REFERENCES `USER_ENTITY` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `CREDENTIAL`
--

LOCK TABLES `CREDENTIAL` WRITE;
/*!40000 ALTER TABLE `CREDENTIAL` DISABLE KEYS */;
INSERT INTO `CREDENTIAL` VALUES
('3af6e7f7-55c8-4b88-826d-ca187bc31d6f',NULL,'password','bb803a13-3a2a-417e-a6c8-fe7abfb69983',1702649218556,NULL,'{\"value\":\"tHT6b4rKj6yClfvyjpS1HUPCKAvmLTwj1d2a5qvdifo=\",\"salt\":\"HtMh2i7a/xIsPKcciJH5VQ==\",\"additionalParameters\":{}}','{\"hashIterations\":27500,\"algorithm\":\"pbkdf2-sha256\",\"additionalParameters\":{}}',10);
/*!40000 ALTER TABLE `CREDENTIAL` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `DATABASECHANGELOG`
--

DROP TABLE IF EXISTS `DATABASECHANGELOG`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `DATABASECHANGELOG` (
  `ID` varchar(255) NOT NULL,
  `AUTHOR` varchar(255) NOT NULL,
  `FILENAME` varchar(255) NOT NULL,
  `DATEEXECUTED` datetime NOT NULL,
  `ORDEREXECUTED` int(11) NOT NULL,
  `EXECTYPE` varchar(10) NOT NULL,
  `MD5SUM` varchar(35) DEFAULT NULL,
  `DESCRIPTION` varchar(255) DEFAULT NULL,
  `COMMENTS` varchar(255) DEFAULT NULL,
  `TAG` varchar(255) DEFAULT NULL,
  `LIQUIBASE` varchar(20) DEFAULT NULL,
  `CONTEXTS` varchar(255) DEFAULT NULL,
  `LABELS` varchar(255) DEFAULT NULL,
  `DEPLOYMENT_ID` varchar(10) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `DATABASECHANGELOG`
--

LOCK TABLES `DATABASECHANGELOG` WRITE;
/*!40000 ALTER TABLE `DATABASECHANGELOG` DISABLE KEYS */;
INSERT INTO `DATABASECHANGELOG` VALUES
('1.0.0.Final-KEYCLOAK-5461','sthorger@redhat.com','META-INF/jpa-changelog-1.0.0.Final.xml','2023-12-15 15:06:43',1,'EXECUTED','9:6f1016664e21e16d26517a4418f5e3df','createTable tableName=APPLICATION_DEFAULT_ROLES; createTable tableName=CLIENT; createTable tableName=CLIENT_SESSION; createTable tableName=CLIENT_SESSION_ROLE; createTable tableName=COMPOSITE_ROLE; createTable tableName=CREDENTIAL; createTable tab...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.0.0.Final-KEYCLOAK-5461','sthorger@redhat.com','META-INF/db2-jpa-changelog-1.0.0.Final.xml','2023-12-15 15:06:43',2,'MARK_RAN','9:828775b1596a07d1200ba1d49e5e3941','createTable tableName=APPLICATION_DEFAULT_ROLES; createTable tableName=CLIENT; createTable tableName=CLIENT_SESSION; createTable tableName=CLIENT_SESSION_ROLE; createTable tableName=COMPOSITE_ROLE; createTable tableName=CREDENTIAL; createTable tab...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.1.0.Beta1','sthorger@redhat.com','META-INF/jpa-changelog-1.1.0.Beta1.xml','2023-12-15 15:06:44',3,'EXECUTED','9:5f090e44a7d595883c1fb61f4b41fd38','delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=CLIENT_ATTRIBUTES; createTable tableName=CLIENT_SESSION_NOTE; createTable tableName=APP_NODE_REGISTRATIONS; addColumn table...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.1.0.Final','sthorger@redhat.com','META-INF/jpa-changelog-1.1.0.Final.xml','2023-12-15 15:06:44',4,'EXECUTED','9:c07e577387a3d2c04d1adc9aaad8730e','renameColumn newColumnName=EVENT_TIME, oldColumnName=TIME, tableName=EVENT_ENTITY','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.2.0.Beta1','psilva@redhat.com','META-INF/jpa-changelog-1.2.0.Beta1.xml','2023-12-15 15:06:44',5,'EXECUTED','9:b68ce996c655922dbcd2fe6b6ae72686','delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=PROTOCOL_MAPPER; createTable tableName=PROTOCOL_MAPPER_CONFIG; createTable tableName=...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.2.0.Beta1','psilva@redhat.com','META-INF/db2-jpa-changelog-1.2.0.Beta1.xml','2023-12-15 15:06:44',6,'MARK_RAN','9:543b5c9989f024fe35c6f6c5a97de88e','delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=PROTOCOL_MAPPER; createTable tableName=PROTOCOL_MAPPER_CONFIG; createTable tableName=...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.2.0.RC1','bburke@redhat.com','META-INF/jpa-changelog-1.2.0.CR1.xml','2023-12-15 15:06:45',7,'EXECUTED','9:765afebbe21cf5bbca048e632df38336','delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=MIGRATION_MODEL; createTable tableName=IDENTITY_P...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.2.0.RC1','bburke@redhat.com','META-INF/db2-jpa-changelog-1.2.0.CR1.xml','2023-12-15 15:06:45',8,'MARK_RAN','9:db4a145ba11a6fdaefb397f6dbf829a1','delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=MIGRATION_MODEL; createTable tableName=IDENTITY_P...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.2.0.Final','keycloak','META-INF/jpa-changelog-1.2.0.Final.xml','2023-12-15 15:06:45',9,'EXECUTED','9:9d05c7be10cdb873f8bcb41bc3a8ab23','update tableName=CLIENT; update tableName=CLIENT; update tableName=CLIENT','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.3.0','bburke@redhat.com','META-INF/jpa-changelog-1.3.0.xml','2023-12-15 15:06:46',10,'EXECUTED','9:18593702353128d53111f9b1ff0b82b8','delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=ADMI...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.4.0','bburke@redhat.com','META-INF/jpa-changelog-1.4.0.xml','2023-12-15 15:06:46',11,'EXECUTED','9:6122efe5f090e41a85c0f1c9e52cbb62','delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.4.0','bburke@redhat.com','META-INF/db2-jpa-changelog-1.4.0.xml','2023-12-15 15:06:46',12,'MARK_RAN','9:e1ff28bf7568451453f844c5d54bb0b5','delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.5.0','bburke@redhat.com','META-INF/jpa-changelog-1.5.0.xml','2023-12-15 15:06:47',13,'EXECUTED','9:7af32cd8957fbc069f796b61217483fd','delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.6.1_from15','mposolda@redhat.com','META-INF/jpa-changelog-1.6.1.xml','2023-12-15 15:06:47',14,'EXECUTED','9:6005e15e84714cd83226bf7879f54190','addColumn tableName=REALM; addColumn tableName=KEYCLOAK_ROLE; addColumn tableName=CLIENT; createTable tableName=OFFLINE_USER_SESSION; createTable tableName=OFFLINE_CLIENT_SESSION; addPrimaryKey constraintName=CONSTRAINT_OFFL_US_SES_PK2, tableName=...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.6.1_from16-pre','mposolda@redhat.com','META-INF/jpa-changelog-1.6.1.xml','2023-12-15 15:06:47',15,'MARK_RAN','9:bf656f5a2b055d07f314431cae76f06c','delete tableName=OFFLINE_CLIENT_SESSION; delete tableName=OFFLINE_USER_SESSION','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.6.1_from16','mposolda@redhat.com','META-INF/jpa-changelog-1.6.1.xml','2023-12-15 15:06:47',16,'MARK_RAN','9:f8dadc9284440469dcf71e25ca6ab99b','dropPrimaryKey constraintName=CONSTRAINT_OFFLINE_US_SES_PK, tableName=OFFLINE_USER_SESSION; dropPrimaryKey constraintName=CONSTRAINT_OFFLINE_CL_SES_PK, tableName=OFFLINE_CLIENT_SESSION; addColumn tableName=OFFLINE_USER_SESSION; update tableName=OF...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.6.1','mposolda@redhat.com','META-INF/jpa-changelog-1.6.1.xml','2023-12-15 15:06:47',17,'EXECUTED','9:d41d8cd98f00b204e9800998ecf8427e','empty','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.7.0','bburke@redhat.com','META-INF/jpa-changelog-1.7.0.xml','2023-12-15 15:06:47',18,'EXECUTED','9:3368ff0be4c2855ee2dd9ca813b38d8e','createTable tableName=KEYCLOAK_GROUP; createTable tableName=GROUP_ROLE_MAPPING; createTable tableName=GROUP_ATTRIBUTE; createTable tableName=USER_GROUP_MEMBERSHIP; createTable tableName=REALM_DEFAULT_GROUPS; addColumn tableName=IDENTITY_PROVIDER; ...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.8.0','mposolda@redhat.com','META-INF/jpa-changelog-1.8.0.xml','2023-12-15 15:06:48',19,'EXECUTED','9:8ac2fb5dd030b24c0570a763ed75ed20','addColumn tableName=IDENTITY_PROVIDER; createTable tableName=CLIENT_TEMPLATE; createTable tableName=CLIENT_TEMPLATE_ATTRIBUTES; createTable tableName=TEMPLATE_SCOPE_MAPPING; dropNotNullConstraint columnName=CLIENT_ID, tableName=PROTOCOL_MAPPER; ad...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.8.0-2','keycloak','META-INF/jpa-changelog-1.8.0.xml','2023-12-15 15:06:48',20,'EXECUTED','9:f91ddca9b19743db60e3057679810e6c','dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; update tableName=CREDENTIAL','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.8.0','mposolda@redhat.com','META-INF/db2-jpa-changelog-1.8.0.xml','2023-12-15 15:06:48',21,'MARK_RAN','9:831e82914316dc8a57dc09d755f23c51','addColumn tableName=IDENTITY_PROVIDER; createTable tableName=CLIENT_TEMPLATE; createTable tableName=CLIENT_TEMPLATE_ATTRIBUTES; createTable tableName=TEMPLATE_SCOPE_MAPPING; dropNotNullConstraint columnName=CLIENT_ID, tableName=PROTOCOL_MAPPER; ad...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.8.0-2','keycloak','META-INF/db2-jpa-changelog-1.8.0.xml','2023-12-15 15:06:48',22,'MARK_RAN','9:f91ddca9b19743db60e3057679810e6c','dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; update tableName=CREDENTIAL','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.9.0','mposolda@redhat.com','META-INF/jpa-changelog-1.9.0.xml','2023-12-15 15:06:48',23,'EXECUTED','9:bc3d0f9e823a69dc21e23e94c7a94bb1','update tableName=REALM; update tableName=REALM; update tableName=REALM; update tableName=REALM; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=REALM; update tableName=REALM; customChange; dr...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.9.1','keycloak','META-INF/jpa-changelog-1.9.1.xml','2023-12-15 15:06:48',24,'EXECUTED','9:c9999da42f543575ab790e76439a2679','modifyDataType columnName=PRIVATE_KEY, tableName=REALM; modifyDataType columnName=PUBLIC_KEY, tableName=REALM; modifyDataType columnName=CERTIFICATE, tableName=REALM','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.9.1','keycloak','META-INF/db2-jpa-changelog-1.9.1.xml','2023-12-15 15:06:48',25,'MARK_RAN','9:0d6c65c6f58732d81569e77b10ba301d','modifyDataType columnName=PRIVATE_KEY, tableName=REALM; modifyDataType columnName=CERTIFICATE, tableName=REALM','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('1.9.2','keycloak','META-INF/jpa-changelog-1.9.2.xml','2023-12-15 15:06:48',26,'EXECUTED','9:fc576660fc016ae53d2d4778d84d86d0','createIndex indexName=IDX_USER_EMAIL, tableName=USER_ENTITY; createIndex indexName=IDX_USER_ROLE_MAPPING, tableName=USER_ROLE_MAPPING; createIndex indexName=IDX_USER_GROUP_MAPPING, tableName=USER_GROUP_MEMBERSHIP; createIndex indexName=IDX_USER_CO...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('authz-2.0.0','psilva@redhat.com','META-INF/jpa-changelog-authz-2.0.0.xml','2023-12-15 15:06:49',27,'EXECUTED','9:43ed6b0da89ff77206289e87eaa9c024','createTable tableName=RESOURCE_SERVER; addPrimaryKey constraintName=CONSTRAINT_FARS, tableName=RESOURCE_SERVER; addUniqueConstraint constraintName=UK_AU8TT6T700S9V50BU18WS5HA6, tableName=RESOURCE_SERVER; createTable tableName=RESOURCE_SERVER_RESOU...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('authz-2.5.1','psilva@redhat.com','META-INF/jpa-changelog-authz-2.5.1.xml','2023-12-15 15:06:49',28,'EXECUTED','9:44bae577f551b3738740281eceb4ea70','update tableName=RESOURCE_SERVER_POLICY','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('2.1.0-KEYCLOAK-5461','bburke@redhat.com','META-INF/jpa-changelog-2.1.0.xml','2023-12-15 15:06:49',29,'EXECUTED','9:bd88e1f833df0420b01e114533aee5e8','createTable tableName=BROKER_LINK; createTable tableName=FED_USER_ATTRIBUTE; createTable tableName=FED_USER_CONSENT; createTable tableName=FED_USER_CONSENT_ROLE; createTable tableName=FED_USER_CONSENT_PROT_MAPPER; createTable tableName=FED_USER_CR...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('2.2.0','bburke@redhat.com','META-INF/jpa-changelog-2.2.0.xml','2023-12-15 15:06:49',30,'EXECUTED','9:a7022af5267f019d020edfe316ef4371','addColumn tableName=ADMIN_EVENT_ENTITY; createTable tableName=CREDENTIAL_ATTRIBUTE; createTable tableName=FED_CREDENTIAL_ATTRIBUTE; modifyDataType columnName=VALUE, tableName=CREDENTIAL; addForeignKeyConstraint baseTableName=FED_CREDENTIAL_ATTRIBU...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('2.3.0','bburke@redhat.com','META-INF/jpa-changelog-2.3.0.xml','2023-12-15 15:06:49',31,'EXECUTED','9:fc155c394040654d6a79227e56f5e25a','createTable tableName=FEDERATED_USER; addPrimaryKey constraintName=CONSTR_FEDERATED_USER, tableName=FEDERATED_USER; dropDefaultValue columnName=TOTP, tableName=USER_ENTITY; dropColumn columnName=TOTP, tableName=USER_ENTITY; addColumn tableName=IDE...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('2.4.0','bburke@redhat.com','META-INF/jpa-changelog-2.4.0.xml','2023-12-15 15:06:49',32,'EXECUTED','9:eac4ffb2a14795e5dc7b426063e54d88','customChange','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('2.5.0','bburke@redhat.com','META-INF/jpa-changelog-2.5.0.xml','2023-12-15 15:06:49',33,'EXECUTED','9:54937c05672568c4c64fc9524c1e9462','customChange; modifyDataType columnName=USER_ID, tableName=OFFLINE_USER_SESSION','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('2.5.0-unicode-oracle','hmlnarik@redhat.com','META-INF/jpa-changelog-2.5.0.xml','2023-12-15 15:06:49',34,'MARK_RAN','9:3a32bace77c84d7678d035a7f5a8084e','modifyDataType columnName=DESCRIPTION, tableName=AUTHENTICATION_FLOW; modifyDataType columnName=DESCRIPTION, tableName=CLIENT_TEMPLATE; modifyDataType columnName=DESCRIPTION, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=DESCRIPTION,...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('2.5.0-unicode-other-dbs','hmlnarik@redhat.com','META-INF/jpa-changelog-2.5.0.xml','2023-12-15 15:06:50',35,'EXECUTED','9:33d72168746f81f98ae3a1e8e0ca3554','modifyDataType columnName=DESCRIPTION, tableName=AUTHENTICATION_FLOW; modifyDataType columnName=DESCRIPTION, tableName=CLIENT_TEMPLATE; modifyDataType columnName=DESCRIPTION, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=DESCRIPTION,...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('2.5.0-duplicate-email-support','slawomir@dabek.name','META-INF/jpa-changelog-2.5.0.xml','2023-12-15 15:06:50',36,'EXECUTED','9:61b6d3d7a4c0e0024b0c839da283da0c','addColumn tableName=REALM','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('2.5.0-unique-group-names','hmlnarik@redhat.com','META-INF/jpa-changelog-2.5.0.xml','2023-12-15 15:06:50',37,'EXECUTED','9:8dcac7bdf7378e7d823cdfddebf72fda','addUniqueConstraint constraintName=SIBLING_NAMES, tableName=KEYCLOAK_GROUP','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('2.5.1','bburke@redhat.com','META-INF/jpa-changelog-2.5.1.xml','2023-12-15 15:06:50',38,'EXECUTED','9:a2b870802540cb3faa72098db5388af3','addColumn tableName=FED_USER_CONSENT','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('3.0.0','bburke@redhat.com','META-INF/jpa-changelog-3.0.0.xml','2023-12-15 15:06:50',39,'EXECUTED','9:132a67499ba24bcc54fb5cbdcfe7e4c0','addColumn tableName=IDENTITY_PROVIDER','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('3.2.0-fix','keycloak','META-INF/jpa-changelog-3.2.0.xml','2023-12-15 15:06:50',40,'MARK_RAN','9:938f894c032f5430f2b0fafb1a243462','addNotNullConstraint columnName=REALM_ID, tableName=CLIENT_INITIAL_ACCESS','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('3.2.0-fix-with-keycloak-5416','keycloak','META-INF/jpa-changelog-3.2.0.xml','2023-12-15 15:06:50',41,'MARK_RAN','9:845c332ff1874dc5d35974b0babf3006','dropIndex indexName=IDX_CLIENT_INIT_ACC_REALM, tableName=CLIENT_INITIAL_ACCESS; addNotNullConstraint columnName=REALM_ID, tableName=CLIENT_INITIAL_ACCESS; createIndex indexName=IDX_CLIENT_INIT_ACC_REALM, tableName=CLIENT_INITIAL_ACCESS','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('3.2.0-fix-offline-sessions','hmlnarik','META-INF/jpa-changelog-3.2.0.xml','2023-12-15 15:06:50',42,'EXECUTED','9:fc86359c079781adc577c5a217e4d04c','customChange','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('3.2.0-fixed','keycloak','META-INF/jpa-changelog-3.2.0.xml','2023-12-15 15:06:51',43,'EXECUTED','9:59a64800e3c0d09b825f8a3b444fa8f4','addColumn tableName=REALM; dropPrimaryKey constraintName=CONSTRAINT_OFFL_CL_SES_PK2, tableName=OFFLINE_CLIENT_SESSION; dropColumn columnName=CLIENT_SESSION_ID, tableName=OFFLINE_CLIENT_SESSION; addPrimaryKey constraintName=CONSTRAINT_OFFL_CL_SES_P...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('3.3.0','keycloak','META-INF/jpa-changelog-3.3.0.xml','2023-12-15 15:06:51',44,'EXECUTED','9:d48d6da5c6ccf667807f633fe489ce88','addColumn tableName=USER_ENTITY','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('authz-3.4.0.CR1-resource-server-pk-change-part1','glavoie@gmail.com','META-INF/jpa-changelog-authz-3.4.0.CR1.xml','2023-12-15 15:06:51',45,'EXECUTED','9:dde36f7973e80d71fceee683bc5d2951','addColumn tableName=RESOURCE_SERVER_POLICY; addColumn tableName=RESOURCE_SERVER_RESOURCE; addColumn tableName=RESOURCE_SERVER_SCOPE','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('authz-3.4.0.CR1-resource-server-pk-change-part2-KEYCLOAK-6095','hmlnarik@redhat.com','META-INF/jpa-changelog-authz-3.4.0.CR1.xml','2023-12-15 15:06:51',46,'EXECUTED','9:b855e9b0a406b34fa323235a0cf4f640','customChange','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('authz-3.4.0.CR1-resource-server-pk-change-part3-fixed','glavoie@gmail.com','META-INF/jpa-changelog-authz-3.4.0.CR1.xml','2023-12-15 15:06:51',47,'MARK_RAN','9:51abbacd7b416c50c4421a8cabf7927e','dropIndex indexName=IDX_RES_SERV_POL_RES_SERV, tableName=RESOURCE_SERVER_POLICY; dropIndex indexName=IDX_RES_SRV_RES_RES_SRV, tableName=RESOURCE_SERVER_RESOURCE; dropIndex indexName=IDX_RES_SRV_SCOPE_RES_SRV, tableName=RESOURCE_SERVER_SCOPE','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('authz-3.4.0.CR1-resource-server-pk-change-part3-fixed-nodropindex','glavoie@gmail.com','META-INF/jpa-changelog-authz-3.4.0.CR1.xml','2023-12-15 15:06:52',48,'EXECUTED','9:bdc99e567b3398bac83263d375aad143','addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, tableName=RESOURCE_SERVER_POLICY; addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, tableName=RESOURCE_SERVER_RESOURCE; addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, ...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('authn-3.4.0.CR1-refresh-token-max-reuse','glavoie@gmail.com','META-INF/jpa-changelog-authz-3.4.0.CR1.xml','2023-12-15 15:06:52',49,'EXECUTED','9:d198654156881c46bfba39abd7769e69','addColumn tableName=REALM','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('3.4.0','keycloak','META-INF/jpa-changelog-3.4.0.xml','2023-12-15 15:06:52',50,'EXECUTED','9:cfdd8736332ccdd72c5256ccb42335db','addPrimaryKey constraintName=CONSTRAINT_REALM_DEFAULT_ROLES, tableName=REALM_DEFAULT_ROLES; addPrimaryKey constraintName=CONSTRAINT_COMPOSITE_ROLE, tableName=COMPOSITE_ROLE; addPrimaryKey constraintName=CONSTR_REALM_DEFAULT_GROUPS, tableName=REALM...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('3.4.0-KEYCLOAK-5230','hmlnarik@redhat.com','META-INF/jpa-changelog-3.4.0.xml','2023-12-15 15:06:52',51,'EXECUTED','9:7c84de3d9bd84d7f077607c1a4dcb714','createIndex indexName=IDX_FU_ATTRIBUTE, tableName=FED_USER_ATTRIBUTE; createIndex indexName=IDX_FU_CONSENT, tableName=FED_USER_CONSENT; createIndex indexName=IDX_FU_CONSENT_RU, tableName=FED_USER_CONSENT; createIndex indexName=IDX_FU_CREDENTIAL, t...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('3.4.1','psilva@redhat.com','META-INF/jpa-changelog-3.4.1.xml','2023-12-15 15:06:52',52,'EXECUTED','9:5a6bb36cbefb6a9d6928452c0852af2d','modifyDataType columnName=VALUE, tableName=CLIENT_ATTRIBUTES','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('3.4.2','keycloak','META-INF/jpa-changelog-3.4.2.xml','2023-12-15 15:06:52',53,'EXECUTED','9:8f23e334dbc59f82e0a328373ca6ced0','update tableName=REALM','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('3.4.2-KEYCLOAK-5172','mkanis@redhat.com','META-INF/jpa-changelog-3.4.2.xml','2023-12-15 15:06:52',54,'EXECUTED','9:9156214268f09d970cdf0e1564d866af','update tableName=CLIENT','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('4.0.0-KEYCLOAK-6335','bburke@redhat.com','META-INF/jpa-changelog-4.0.0.xml','2023-12-15 15:06:53',55,'EXECUTED','9:db806613b1ed154826c02610b7dbdf74','createTable tableName=CLIENT_AUTH_FLOW_BINDINGS; addPrimaryKey constraintName=C_CLI_FLOW_BIND, tableName=CLIENT_AUTH_FLOW_BINDINGS','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('4.0.0-CLEANUP-UNUSED-TABLE','bburke@redhat.com','META-INF/jpa-changelog-4.0.0.xml','2023-12-15 15:06:53',56,'EXECUTED','9:229a041fb72d5beac76bb94a5fa709de','dropTable tableName=CLIENT_IDENTITY_PROV_MAPPING','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('4.0.0-KEYCLOAK-6228','bburke@redhat.com','META-INF/jpa-changelog-4.0.0.xml','2023-12-15 15:06:53',57,'EXECUTED','9:079899dade9c1e683f26b2aa9ca6ff04','dropUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHOGM8UEWRT, tableName=USER_CONSENT; dropNotNullConstraint columnName=CLIENT_ID, tableName=USER_CONSENT; addColumn tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHO...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('4.0.0-KEYCLOAK-5579-fixed','mposolda@redhat.com','META-INF/jpa-changelog-4.0.0.xml','2023-12-15 15:06:54',58,'EXECUTED','9:139b79bcbbfe903bb1c2d2a4dbf001d9','dropForeignKeyConstraint baseTableName=CLIENT_TEMPLATE_ATTRIBUTES, constraintName=FK_CL_TEMPL_ATTR_TEMPL; renameTable newTableName=CLIENT_SCOPE_ATTRIBUTES, oldTableName=CLIENT_TEMPLATE_ATTRIBUTES; renameColumn newColumnName=SCOPE_ID, oldColumnName...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('authz-4.0.0.CR1','psilva@redhat.com','META-INF/jpa-changelog-authz-4.0.0.CR1.xml','2023-12-15 15:06:54',59,'EXECUTED','9:b55738ad889860c625ba2bf483495a04','createTable tableName=RESOURCE_SERVER_PERM_TICKET; addPrimaryKey constraintName=CONSTRAINT_FAPMT, tableName=RESOURCE_SERVER_PERM_TICKET; addForeignKeyConstraint baseTableName=RESOURCE_SERVER_PERM_TICKET, constraintName=FK_FRSRHO213XCX4WNKOG82SSPMT...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('authz-4.0.0.Beta3','psilva@redhat.com','META-INF/jpa-changelog-authz-4.0.0.Beta3.xml','2023-12-15 15:06:54',60,'EXECUTED','9:e0057eac39aa8fc8e09ac6cfa4ae15fe','addColumn tableName=RESOURCE_SERVER_POLICY; addColumn tableName=RESOURCE_SERVER_PERM_TICKET; addForeignKeyConstraint baseTableName=RESOURCE_SERVER_PERM_TICKET, constraintName=FK_FRSRPO2128CX4WNKOG82SSRFY, referencedTableName=RESOURCE_SERVER_POLICY','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('authz-4.2.0.Final','mhajas@redhat.com','META-INF/jpa-changelog-authz-4.2.0.Final.xml','2023-12-15 15:06:54',61,'EXECUTED','9:42a33806f3a0443fe0e7feeec821326c','createTable tableName=RESOURCE_URIS; addForeignKeyConstraint baseTableName=RESOURCE_URIS, constraintName=FK_RESOURCE_SERVER_URIS, referencedTableName=RESOURCE_SERVER_RESOURCE; customChange; dropColumn columnName=URI, tableName=RESOURCE_SERVER_RESO...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('authz-4.2.0.Final-KEYCLOAK-9944','hmlnarik@redhat.com','META-INF/jpa-changelog-authz-4.2.0.Final.xml','2023-12-15 15:06:54',62,'EXECUTED','9:9968206fca46eecc1f51db9c024bfe56','addPrimaryKey constraintName=CONSTRAINT_RESOUR_URIS_PK, tableName=RESOURCE_URIS','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('4.2.0-KEYCLOAK-6313','wadahiro@gmail.com','META-INF/jpa-changelog-4.2.0.xml','2023-12-15 15:06:54',63,'EXECUTED','9:92143a6daea0a3f3b8f598c97ce55c3d','addColumn tableName=REQUIRED_ACTION_PROVIDER','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('4.3.0-KEYCLOAK-7984','wadahiro@gmail.com','META-INF/jpa-changelog-4.3.0.xml','2023-12-15 15:06:54',64,'EXECUTED','9:82bab26a27195d889fb0429003b18f40','update tableName=REQUIRED_ACTION_PROVIDER','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('4.6.0-KEYCLOAK-7950','psilva@redhat.com','META-INF/jpa-changelog-4.6.0.xml','2023-12-15 15:06:54',65,'EXECUTED','9:e590c88ddc0b38b0ae4249bbfcb5abc3','update tableName=RESOURCE_SERVER_RESOURCE','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('4.6.0-KEYCLOAK-8377','keycloak','META-INF/jpa-changelog-4.6.0.xml','2023-12-15 15:06:54',66,'EXECUTED','9:5c1f475536118dbdc38d5d7977950cc0','createTable tableName=ROLE_ATTRIBUTE; addPrimaryKey constraintName=CONSTRAINT_ROLE_ATTRIBUTE_PK, tableName=ROLE_ATTRIBUTE; addForeignKeyConstraint baseTableName=ROLE_ATTRIBUTE, constraintName=FK_ROLE_ATTRIBUTE_ID, referencedTableName=KEYCLOAK_ROLE...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('4.6.0-KEYCLOAK-8555','gideonray@gmail.com','META-INF/jpa-changelog-4.6.0.xml','2023-12-15 15:06:54',67,'EXECUTED','9:e7c9f5f9c4d67ccbbcc215440c718a17','createIndex indexName=IDX_COMPONENT_PROVIDER_TYPE, tableName=COMPONENT','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('4.7.0-KEYCLOAK-1267','sguilhen@redhat.com','META-INF/jpa-changelog-4.7.0.xml','2023-12-15 15:06:55',68,'EXECUTED','9:88e0bfdda924690d6f4e430c53447dd5','addColumn tableName=REALM','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('4.7.0-KEYCLOAK-7275','keycloak','META-INF/jpa-changelog-4.7.0.xml','2023-12-15 15:06:55',69,'EXECUTED','9:f53177f137e1c46b6a88c59ec1cb5218','renameColumn newColumnName=CREATED_ON, oldColumnName=LAST_SESSION_REFRESH, tableName=OFFLINE_USER_SESSION; addNotNullConstraint columnName=CREATED_ON, tableName=OFFLINE_USER_SESSION; addColumn tableName=OFFLINE_USER_SESSION; customChange; createIn...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('4.8.0-KEYCLOAK-8835','sguilhen@redhat.com','META-INF/jpa-changelog-4.8.0.xml','2023-12-15 15:06:55',70,'EXECUTED','9:a74d33da4dc42a37ec27121580d1459f','addNotNullConstraint columnName=SSO_MAX_LIFESPAN_REMEMBER_ME, tableName=REALM; addNotNullConstraint columnName=SSO_IDLE_TIMEOUT_REMEMBER_ME, tableName=REALM','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('authz-7.0.0-KEYCLOAK-10443','psilva@redhat.com','META-INF/jpa-changelog-authz-7.0.0.xml','2023-12-15 15:06:55',71,'EXECUTED','9:fd4ade7b90c3b67fae0bfcfcb42dfb5f','addColumn tableName=RESOURCE_SERVER','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('8.0.0-adding-credential-columns','keycloak','META-INF/jpa-changelog-8.0.0.xml','2023-12-15 15:06:55',72,'EXECUTED','9:aa072ad090bbba210d8f18781b8cebf4','addColumn tableName=CREDENTIAL; addColumn tableName=FED_USER_CREDENTIAL','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('8.0.0-updating-credential-data-not-oracle-fixed','keycloak','META-INF/jpa-changelog-8.0.0.xml','2023-12-15 15:06:55',73,'EXECUTED','9:1ae6be29bab7c2aa376f6983b932be37','update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=FED_USER_CREDENTIAL; update tableName=FED_USER_CREDENTIAL; update tableName=FED_USER_CREDENTIAL','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('8.0.0-updating-credential-data-oracle-fixed','keycloak','META-INF/jpa-changelog-8.0.0.xml','2023-12-15 15:06:55',74,'MARK_RAN','9:14706f286953fc9a25286dbd8fb30d97','update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=FED_USER_CREDENTIAL; update tableName=FED_USER_CREDENTIAL; update tableName=FED_USER_CREDENTIAL','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('8.0.0-credential-cleanup-fixed','keycloak','META-INF/jpa-changelog-8.0.0.xml','2023-12-15 15:06:55',75,'EXECUTED','9:2b9cc12779be32c5b40e2e67711a218b','dropDefaultValue columnName=COUNTER, tableName=CREDENTIAL; dropDefaultValue columnName=DIGITS, tableName=CREDENTIAL; dropDefaultValue columnName=PERIOD, tableName=CREDENTIAL; dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; dropColumn ...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('8.0.0-resource-tag-support','keycloak','META-INF/jpa-changelog-8.0.0.xml','2023-12-15 15:06:55',76,'EXECUTED','9:91fa186ce7a5af127a2d7a91ee083cc5','addColumn tableName=MIGRATION_MODEL; createIndex indexName=IDX_UPDATE_TIME, tableName=MIGRATION_MODEL','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('9.0.0-always-display-client','keycloak','META-INF/jpa-changelog-9.0.0.xml','2023-12-15 15:06:55',77,'EXECUTED','9:6335e5c94e83a2639ccd68dd24e2e5ad','addColumn tableName=CLIENT','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('9.0.0-drop-constraints-for-column-increase','keycloak','META-INF/jpa-changelog-9.0.0.xml','2023-12-15 15:06:55',78,'MARK_RAN','9:6bdb5658951e028bfe16fa0a8228b530','dropUniqueConstraint constraintName=UK_FRSR6T700S9V50BU18WS5PMT, tableName=RESOURCE_SERVER_PERM_TICKET; dropUniqueConstraint constraintName=UK_FRSR6T700S9V50BU18WS5HA6, tableName=RESOURCE_SERVER_RESOURCE; dropPrimaryKey constraintName=CONSTRAINT_O...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('9.0.0-increase-column-size-federated-fk','keycloak','META-INF/jpa-changelog-9.0.0.xml','2023-12-15 15:06:55',79,'EXECUTED','9:d5bc15a64117ccad481ce8792d4c608f','modifyDataType columnName=CLIENT_ID, tableName=FED_USER_CONSENT; modifyDataType columnName=CLIENT_REALM_CONSTRAINT, tableName=KEYCLOAK_ROLE; modifyDataType columnName=OWNER, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=CLIENT_ID, ta...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('9.0.0-recreate-constraints-after-column-increase','keycloak','META-INF/jpa-changelog-9.0.0.xml','2023-12-15 15:06:55',80,'MARK_RAN','9:077cba51999515f4d3e7ad5619ab592c','addNotNullConstraint columnName=CLIENT_ID, tableName=OFFLINE_CLIENT_SESSION; addNotNullConstraint columnName=OWNER, tableName=RESOURCE_SERVER_PERM_TICKET; addNotNullConstraint columnName=REQUESTER, tableName=RESOURCE_SERVER_PERM_TICKET; addNotNull...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('9.0.1-add-index-to-client.client_id','keycloak','META-INF/jpa-changelog-9.0.1.xml','2023-12-15 15:06:55',81,'EXECUTED','9:be969f08a163bf47c6b9e9ead8ac2afb','createIndex indexName=IDX_CLIENT_ID, tableName=CLIENT','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('9.0.1-KEYCLOAK-12579-drop-constraints','keycloak','META-INF/jpa-changelog-9.0.1.xml','2023-12-15 15:06:55',82,'MARK_RAN','9:6d3bb4408ba5a72f39bd8a0b301ec6e3','dropUniqueConstraint constraintName=SIBLING_NAMES, tableName=KEYCLOAK_GROUP','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('9.0.1-KEYCLOAK-12579-add-not-null-constraint','keycloak','META-INF/jpa-changelog-9.0.1.xml','2023-12-15 15:06:55',83,'EXECUTED','9:966bda61e46bebf3cc39518fbed52fa7','addNotNullConstraint columnName=PARENT_GROUP, tableName=KEYCLOAK_GROUP','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('9.0.1-KEYCLOAK-12579-recreate-constraints','keycloak','META-INF/jpa-changelog-9.0.1.xml','2023-12-15 15:06:55',84,'MARK_RAN','9:8dcac7bdf7378e7d823cdfddebf72fda','addUniqueConstraint constraintName=SIBLING_NAMES, tableName=KEYCLOAK_GROUP','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('9.0.1-add-index-to-events','keycloak','META-INF/jpa-changelog-9.0.1.xml','2023-12-15 15:06:55',85,'EXECUTED','9:7d93d602352a30c0c317e6a609b56599','createIndex indexName=IDX_EVENT_TIME, tableName=EVENT_ENTITY','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('map-remove-ri','keycloak','META-INF/jpa-changelog-11.0.0.xml','2023-12-15 15:06:56',86,'EXECUTED','9:71c5969e6cdd8d7b6f47cebc86d37627','dropForeignKeyConstraint baseTableName=REALM, constraintName=FK_TRAF444KK6QRKMS7N56AIWQ5Y; dropForeignKeyConstraint baseTableName=KEYCLOAK_ROLE, constraintName=FK_KJHO5LE2C0RAL09FL8CM9WFW9','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('map-remove-ri','keycloak','META-INF/jpa-changelog-12.0.0.xml','2023-12-15 15:06:56',87,'EXECUTED','9:a9ba7d47f065f041b7da856a81762021','dropForeignKeyConstraint baseTableName=REALM_DEFAULT_GROUPS, constraintName=FK_DEF_GROUPS_GROUP; dropForeignKeyConstraint baseTableName=REALM_DEFAULT_ROLES, constraintName=FK_H4WPD7W4HSOOLNI3H0SW7BTJE; dropForeignKeyConstraint baseTableName=CLIENT...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('12.1.0-add-realm-localization-table','keycloak','META-INF/jpa-changelog-12.0.0.xml','2023-12-15 15:06:56',88,'EXECUTED','9:fffabce2bc01e1a8f5110d5278500065','createTable tableName=REALM_LOCALIZATIONS; addPrimaryKey tableName=REALM_LOCALIZATIONS','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('default-roles','keycloak','META-INF/jpa-changelog-13.0.0.xml','2023-12-15 15:06:56',89,'EXECUTED','9:fa8a5b5445e3857f4b010bafb5009957','addColumn tableName=REALM; customChange','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('default-roles-cleanup','keycloak','META-INF/jpa-changelog-13.0.0.xml','2023-12-15 15:06:56',90,'EXECUTED','9:67ac3241df9a8582d591c5ed87125f39','dropTable tableName=REALM_DEFAULT_ROLES; dropTable tableName=CLIENT_DEFAULT_ROLES','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('13.0.0-KEYCLOAK-16844','keycloak','META-INF/jpa-changelog-13.0.0.xml','2023-12-15 15:06:56',91,'EXECUTED','9:ad1194d66c937e3ffc82386c050ba089','createIndex indexName=IDX_OFFLINE_USS_PRELOAD, tableName=OFFLINE_USER_SESSION','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('map-remove-ri-13.0.0','keycloak','META-INF/jpa-changelog-13.0.0.xml','2023-12-15 15:06:56',92,'EXECUTED','9:d9be619d94af5a2f5d07b9f003543b91','dropForeignKeyConstraint baseTableName=DEFAULT_CLIENT_SCOPE, constraintName=FK_R_DEF_CLI_SCOPE_SCOPE; dropForeignKeyConstraint baseTableName=CLIENT_SCOPE_CLIENT, constraintName=FK_C_CLI_SCOPE_SCOPE; dropForeignKeyConstraint baseTableName=CLIENT_SC...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('13.0.0-KEYCLOAK-17992-drop-constraints','keycloak','META-INF/jpa-changelog-13.0.0.xml','2023-12-15 15:06:56',93,'MARK_RAN','9:544d201116a0fcc5a5da0925fbbc3bde','dropPrimaryKey constraintName=C_CLI_SCOPE_BIND, tableName=CLIENT_SCOPE_CLIENT; dropIndex indexName=IDX_CLSCOPE_CL, tableName=CLIENT_SCOPE_CLIENT; dropIndex indexName=IDX_CL_CLSCOPE, tableName=CLIENT_SCOPE_CLIENT','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('13.0.0-increase-column-size-federated','keycloak','META-INF/jpa-changelog-13.0.0.xml','2023-12-15 15:06:56',94,'EXECUTED','9:43c0c1055b6761b4b3e89de76d612ccf','modifyDataType columnName=CLIENT_ID, tableName=CLIENT_SCOPE_CLIENT; modifyDataType columnName=SCOPE_ID, tableName=CLIENT_SCOPE_CLIENT','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('13.0.0-KEYCLOAK-17992-recreate-constraints','keycloak','META-INF/jpa-changelog-13.0.0.xml','2023-12-15 15:06:56',95,'MARK_RAN','9:8bd711fd0330f4fe980494ca43ab1139','addNotNullConstraint columnName=CLIENT_ID, tableName=CLIENT_SCOPE_CLIENT; addNotNullConstraint columnName=SCOPE_ID, tableName=CLIENT_SCOPE_CLIENT; addPrimaryKey constraintName=C_CLI_SCOPE_BIND, tableName=CLIENT_SCOPE_CLIENT; createIndex indexName=...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('json-string-accomodation-fixed','keycloak','META-INF/jpa-changelog-13.0.0.xml','2023-12-15 15:06:56',96,'EXECUTED','9:e07d2bc0970c348bb06fb63b1f82ddbf','addColumn tableName=REALM_ATTRIBUTE; update tableName=REALM_ATTRIBUTE; dropColumn columnName=VALUE, tableName=REALM_ATTRIBUTE; renameColumn newColumnName=VALUE, oldColumnName=VALUE_NEW, tableName=REALM_ATTRIBUTE','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('14.0.0-KEYCLOAK-11019','keycloak','META-INF/jpa-changelog-14.0.0.xml','2023-12-15 15:06:56',97,'EXECUTED','9:24fb8611e97f29989bea412aa38d12b7','createIndex indexName=IDX_OFFLINE_CSS_PRELOAD, tableName=OFFLINE_CLIENT_SESSION; createIndex indexName=IDX_OFFLINE_USS_BY_USER, tableName=OFFLINE_USER_SESSION; createIndex indexName=IDX_OFFLINE_USS_BY_USERSESS, tableName=OFFLINE_USER_SESSION','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('14.0.0-KEYCLOAK-18286','keycloak','META-INF/jpa-changelog-14.0.0.xml','2023-12-15 15:06:56',98,'MARK_RAN','9:259f89014ce2506ee84740cbf7163aa7','createIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('14.0.0-KEYCLOAK-18286-revert','keycloak','META-INF/jpa-changelog-14.0.0.xml','2023-12-15 15:06:56',99,'MARK_RAN','9:04baaf56c116ed19951cbc2cca584022','dropIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('14.0.0-KEYCLOAK-18286-supported-dbs','keycloak','META-INF/jpa-changelog-14.0.0.xml','2023-12-15 15:06:56',100,'EXECUTED','9:bd2bd0fc7768cf0845ac96a8786fa735','createIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('14.0.0-KEYCLOAK-18286-unsupported-dbs','keycloak','META-INF/jpa-changelog-14.0.0.xml','2023-12-15 15:06:56',101,'MARK_RAN','9:d3d977031d431db16e2c181ce49d73e9','createIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('KEYCLOAK-17267-add-index-to-user-attributes','keycloak','META-INF/jpa-changelog-14.0.0.xml','2023-12-15 15:06:56',102,'EXECUTED','9:0b305d8d1277f3a89a0a53a659ad274c','createIndex indexName=IDX_USER_ATTRIBUTE_NAME, tableName=USER_ATTRIBUTE','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('KEYCLOAK-18146-add-saml-art-binding-identifier','keycloak','META-INF/jpa-changelog-14.0.0.xml','2023-12-15 15:06:56',103,'EXECUTED','9:2c374ad2cdfe20e2905a84c8fac48460','customChange','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('15.0.0-KEYCLOAK-18467','keycloak','META-INF/jpa-changelog-15.0.0.xml','2023-12-15 15:06:56',104,'EXECUTED','9:47a760639ac597360a8219f5b768b4de','addColumn tableName=REALM_LOCALIZATIONS; update tableName=REALM_LOCALIZATIONS; dropColumn columnName=TEXTS, tableName=REALM_LOCALIZATIONS; renameColumn newColumnName=TEXTS, oldColumnName=TEXTS_NEW, tableName=REALM_LOCALIZATIONS; addNotNullConstrai...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('17.0.0-9562','keycloak','META-INF/jpa-changelog-17.0.0.xml','2023-12-15 15:06:56',105,'EXECUTED','9:a6272f0576727dd8cad2522335f5d99e','createIndex indexName=IDX_USER_SERVICE_ACCOUNT, tableName=USER_ENTITY','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('18.0.0-10625-IDX_ADMIN_EVENT_TIME','keycloak','META-INF/jpa-changelog-18.0.0.xml','2023-12-15 15:06:56',106,'EXECUTED','9:015479dbd691d9cc8669282f4828c41d','createIndex indexName=IDX_ADMIN_EVENT_TIME, tableName=ADMIN_EVENT_ENTITY','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('19.0.0-10135','keycloak','META-INF/jpa-changelog-19.0.0.xml','2023-12-15 15:06:56',107,'EXECUTED','9:9518e495fdd22f78ad6425cc30630221','customChange','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('20.0.0-12964-supported-dbs','keycloak','META-INF/jpa-changelog-20.0.0.xml','2023-12-15 15:06:56',108,'EXECUTED','9:f2e1331a71e0aa85e5608fe42f7f681c','createIndex indexName=IDX_GROUP_ATT_BY_NAME_VALUE, tableName=GROUP_ATTRIBUTE','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('20.0.0-12964-unsupported-dbs','keycloak','META-INF/jpa-changelog-20.0.0.xml','2023-12-15 15:06:56',109,'MARK_RAN','9:1a6fcaa85e20bdeae0a9ce49b41946a5','createIndex indexName=IDX_GROUP_ATT_BY_NAME_VALUE, tableName=GROUP_ATTRIBUTE','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('client-attributes-string-accomodation-fixed','keycloak','META-INF/jpa-changelog-20.0.0.xml','2023-12-15 15:06:56',110,'EXECUTED','9:3f332e13e90739ed0c35b0b25b7822ca','addColumn tableName=CLIENT_ATTRIBUTES; update tableName=CLIENT_ATTRIBUTES; dropColumn columnName=VALUE, tableName=CLIENT_ATTRIBUTES; renameColumn newColumnName=VALUE, oldColumnName=VALUE_NEW, tableName=CLIENT_ATTRIBUTES','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('21.0.2-17277','keycloak','META-INF/jpa-changelog-21.0.2.xml','2023-12-15 15:06:56',111,'EXECUTED','9:7ee1f7a3fb8f5588f171fb9a6ab623c0','customChange','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('21.1.0-19404','keycloak','META-INF/jpa-changelog-21.1.0.xml','2023-12-15 15:06:56',112,'EXECUTED','9:3d7e830b52f33676b9d64f7f2b2ea634','modifyDataType columnName=DECISION_STRATEGY, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=LOGIC, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=POLICY_ENFORCE_MODE, tableName=RESOURCE_SERVER','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('21.1.0-19404-2','keycloak','META-INF/jpa-changelog-21.1.0.xml','2023-12-15 15:06:56',113,'MARK_RAN','9:627d032e3ef2c06c0e1f73d2ae25c26c','addColumn tableName=RESOURCE_SERVER_POLICY; update tableName=RESOURCE_SERVER_POLICY; dropColumn columnName=DECISION_STRATEGY, tableName=RESOURCE_SERVER_POLICY; renameColumn newColumnName=DECISION_STRATEGY, oldColumnName=DECISION_STRATEGY_NEW, tabl...','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('22.0.0-17484-updated','keycloak','META-INF/jpa-changelog-22.0.0.xml','2023-12-15 15:06:56',114,'EXECUTED','9:90af0bfd30cafc17b9f4d6eccd92b8b3','customChange','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('22.0.5-24031','keycloak','META-INF/jpa-changelog-22.0.0.xml','2023-12-15 15:06:56',115,'MARK_RAN','9:a60d2d7b315ec2d3eba9e2f145f9df28','customChange','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('23.0.0-12062','keycloak','META-INF/jpa-changelog-23.0.0.xml','2023-12-15 15:06:56',116,'EXECUTED','9:2168fbe728fec46ae9baf15bf80927b8','addColumn tableName=COMPONENT_CONFIG; update tableName=COMPONENT_CONFIG; dropColumn columnName=VALUE, tableName=COMPONENT_CONFIG; renameColumn newColumnName=VALUE, oldColumnName=VALUE_NEW, tableName=COMPONENT_CONFIG','',NULL,'4.23.2',NULL,NULL,'2649201796'),
('23.0.0-17258','keycloak','META-INF/jpa-changelog-23.0.0.xml','2023-12-15 15:06:56',117,'EXECUTED','9:36506d679a83bbfda85a27ea1864dca8','addColumn tableName=EVENT_ENTITY','',NULL,'4.23.2',NULL,NULL,'2649201796');
/*!40000 ALTER TABLE `DATABASECHANGELOG` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `DATABASECHANGELOGLOCK`
--

DROP TABLE IF EXISTS `DATABASECHANGELOGLOCK`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `DATABASECHANGELOGLOCK` (
  `ID` int(11) NOT NULL,
  `LOCKED` bit(1) NOT NULL,
  `LOCKGRANTED` datetime DEFAULT NULL,
  `LOCKEDBY` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `DATABASECHANGELOGLOCK`
--

LOCK TABLES `DATABASECHANGELOGLOCK` WRITE;
/*!40000 ALTER TABLE `DATABASECHANGELOGLOCK` DISABLE KEYS */;
INSERT INTO `DATABASECHANGELOGLOCK` VALUES
(1,'\0',NULL,NULL),
(1000,'\0',NULL,NULL),
(1001,'\0',NULL,NULL);
/*!40000 ALTER TABLE `DATABASECHANGELOGLOCK` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `DEFAULT_CLIENT_SCOPE`
--

DROP TABLE IF EXISTS `DEFAULT_CLIENT_SCOPE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `DEFAULT_CLIENT_SCOPE` (
  `REALM_ID` varchar(36) NOT NULL,
  `SCOPE_ID` varchar(36) NOT NULL,
  `DEFAULT_SCOPE` bit(1) NOT NULL DEFAULT b'0',
  PRIMARY KEY (`REALM_ID`,`SCOPE_ID`),
  KEY `IDX_DEFCLS_REALM` (`REALM_ID`),
  KEY `IDX_DEFCLS_SCOPE` (`SCOPE_ID`),
  CONSTRAINT `FK_R_DEF_CLI_SCOPE_REALM` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `DEFAULT_CLIENT_SCOPE`
--

LOCK TABLES `DEFAULT_CLIENT_SCOPE` WRITE;
/*!40000 ALTER TABLE `DEFAULT_CLIENT_SCOPE` DISABLE KEYS */;
INSERT INTO `DEFAULT_CLIENT_SCOPE` VALUES
('139c1488-d000-4061-922b-0c0b518a57db','0c885a01-891a-481f-9087-f6567af22b13',''),
('139c1488-d000-4061-922b-0c0b518a57db','434407ef-1d7f-45e8-b91c-7db10210760a','\0'),
('139c1488-d000-4061-922b-0c0b518a57db','4e882685-31e1-451b-9006-cd4ff0dcf750',''),
('139c1488-d000-4061-922b-0c0b518a57db','5019c5be-c7bd-47b0-a5b3-403a98162efe','\0'),
('139c1488-d000-4061-922b-0c0b518a57db','596a6555-3ee8-4aa9-8168-b8f0de92dbb1','\0'),
('139c1488-d000-4061-922b-0c0b518a57db','781fbb54-8552-44a0-9ea2-fab43dcf0b24',''),
('139c1488-d000-4061-922b-0c0b518a57db','78975493-67a3-4819-a933-47b99c7c7e60',''),
('139c1488-d000-4061-922b-0c0b518a57db','7c7de55b-c72a-4006-9b14-db1398fed22f',''),
('139c1488-d000-4061-922b-0c0b518a57db','ccb9d5ba-bf89-4762-81c1-c9c87da7d1e8','\0'),
('139c1488-d000-4061-922b-0c0b518a57db','d6da6000-2013-417d-ad33-33f0804b5b80',''),
('61c254e2-095d-42b9-b8cc-4546b124e548','0526da56-aab3-455b-9cc8-2d3d8b0457d6',''),
('61c254e2-095d-42b9-b8cc-4546b124e548','0b211c52-ca02-4f22-b786-5a0b5085fc78','\0'),
('61c254e2-095d-42b9-b8cc-4546b124e548','21ce4324-232a-46b2-b113-9407b67de017',''),
('61c254e2-095d-42b9-b8cc-4546b124e548','4e38235f-7289-4fa2-9840-d4a4fbcd2e0e','\0'),
('61c254e2-095d-42b9-b8cc-4546b124e548','8920b300-1b2f-4d18-ab8a-e975974fd013',''),
('61c254e2-095d-42b9-b8cc-4546b124e548','afc839cc-2307-4260-9924-338375d22c2b',''),
('61c254e2-095d-42b9-b8cc-4546b124e548','c945998b-68b7-4894-9561-7863799cc667','\0'),
('61c254e2-095d-42b9-b8cc-4546b124e548','d0262425-28ca-4dba-8f8d-12d1146cd725','\0'),
('61c254e2-095d-42b9-b8cc-4546b124e548','e0711367-7927-43ef-9419-42e57c1d7dd4',''),
('61c254e2-095d-42b9-b8cc-4546b124e548','ede179a5-d38e-4943-98f9-627b3b05848d','');
/*!40000 ALTER TABLE `DEFAULT_CLIENT_SCOPE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `EVENT_ENTITY`
--

DROP TABLE IF EXISTS `EVENT_ENTITY`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `EVENT_ENTITY` (
  `ID` varchar(36) NOT NULL,
  `CLIENT_ID` varchar(255) DEFAULT NULL,
  `DETAILS_JSON` text DEFAULT NULL,
  `ERROR` varchar(255) DEFAULT NULL,
  `IP_ADDRESS` varchar(255) DEFAULT NULL,
  `REALM_ID` varchar(255) DEFAULT NULL,
  `SESSION_ID` varchar(255) DEFAULT NULL,
  `EVENT_TIME` bigint(20) DEFAULT NULL,
  `TYPE` varchar(255) DEFAULT NULL,
  `USER_ID` varchar(255) DEFAULT NULL,
  `DETAILS_JSON_LONG_VALUE` longtext CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_EVENT_TIME` (`REALM_ID`,`EVENT_TIME`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `EVENT_ENTITY`
--

LOCK TABLES `EVENT_ENTITY` WRITE;
/*!40000 ALTER TABLE `EVENT_ENTITY` DISABLE KEYS */;
/*!40000 ALTER TABLE `EVENT_ENTITY` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `FEDERATED_IDENTITY`
--

DROP TABLE IF EXISTS `FEDERATED_IDENTITY`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `FEDERATED_IDENTITY` (
  `IDENTITY_PROVIDER` varchar(255) NOT NULL,
  `REALM_ID` varchar(36) DEFAULT NULL,
  `FEDERATED_USER_ID` varchar(255) DEFAULT NULL,
  `FEDERATED_USERNAME` varchar(255) DEFAULT NULL,
  `TOKEN` text DEFAULT NULL,
  `USER_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`IDENTITY_PROVIDER`,`USER_ID`),
  KEY `IDX_FEDIDENTITY_USER` (`USER_ID`),
  KEY `IDX_FEDIDENTITY_FEDUSER` (`FEDERATED_USER_ID`),
  CONSTRAINT `FK404288B92EF007A6` FOREIGN KEY (`USER_ID`) REFERENCES `USER_ENTITY` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `FEDERATED_IDENTITY`
--

LOCK TABLES `FEDERATED_IDENTITY` WRITE;
/*!40000 ALTER TABLE `FEDERATED_IDENTITY` DISABLE KEYS */;
/*!40000 ALTER TABLE `FEDERATED_IDENTITY` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `FEDERATED_USER`
--

DROP TABLE IF EXISTS `FEDERATED_USER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `FEDERATED_USER` (
  `ID` varchar(255) NOT NULL,
  `STORAGE_PROVIDER_ID` varchar(255) DEFAULT NULL,
  `REALM_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `FEDERATED_USER`
--

LOCK TABLES `FEDERATED_USER` WRITE;
/*!40000 ALTER TABLE `FEDERATED_USER` DISABLE KEYS */;
/*!40000 ALTER TABLE `FEDERATED_USER` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `FED_USER_ATTRIBUTE`
--

DROP TABLE IF EXISTS `FED_USER_ATTRIBUTE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `FED_USER_ATTRIBUTE` (
  `ID` varchar(36) NOT NULL,
  `NAME` varchar(255) NOT NULL,
  `USER_ID` varchar(255) NOT NULL,
  `REALM_ID` varchar(36) NOT NULL,
  `STORAGE_PROVIDER_ID` varchar(36) DEFAULT NULL,
  `VALUE` text DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_FU_ATTRIBUTE` (`USER_ID`,`REALM_ID`,`NAME`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `FED_USER_ATTRIBUTE`
--

LOCK TABLES `FED_USER_ATTRIBUTE` WRITE;
/*!40000 ALTER TABLE `FED_USER_ATTRIBUTE` DISABLE KEYS */;
/*!40000 ALTER TABLE `FED_USER_ATTRIBUTE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `FED_USER_CONSENT`
--

DROP TABLE IF EXISTS `FED_USER_CONSENT`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `FED_USER_CONSENT` (
  `ID` varchar(36) NOT NULL,
  `CLIENT_ID` varchar(255) DEFAULT NULL,
  `USER_ID` varchar(255) NOT NULL,
  `REALM_ID` varchar(36) NOT NULL,
  `STORAGE_PROVIDER_ID` varchar(36) DEFAULT NULL,
  `CREATED_DATE` bigint(20) DEFAULT NULL,
  `LAST_UPDATED_DATE` bigint(20) DEFAULT NULL,
  `CLIENT_STORAGE_PROVIDER` varchar(36) DEFAULT NULL,
  `EXTERNAL_CLIENT_ID` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_FU_CONSENT` (`USER_ID`,`CLIENT_ID`),
  KEY `IDX_FU_CONSENT_RU` (`REALM_ID`,`USER_ID`),
  KEY `IDX_FU_CNSNT_EXT` (`USER_ID`,`CLIENT_STORAGE_PROVIDER`,`EXTERNAL_CLIENT_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `FED_USER_CONSENT`
--

LOCK TABLES `FED_USER_CONSENT` WRITE;
/*!40000 ALTER TABLE `FED_USER_CONSENT` DISABLE KEYS */;
/*!40000 ALTER TABLE `FED_USER_CONSENT` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `FED_USER_CONSENT_CL_SCOPE`
--

DROP TABLE IF EXISTS `FED_USER_CONSENT_CL_SCOPE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `FED_USER_CONSENT_CL_SCOPE` (
  `USER_CONSENT_ID` varchar(36) NOT NULL,
  `SCOPE_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`USER_CONSENT_ID`,`SCOPE_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `FED_USER_CONSENT_CL_SCOPE`
--

LOCK TABLES `FED_USER_CONSENT_CL_SCOPE` WRITE;
/*!40000 ALTER TABLE `FED_USER_CONSENT_CL_SCOPE` DISABLE KEYS */;
/*!40000 ALTER TABLE `FED_USER_CONSENT_CL_SCOPE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `FED_USER_CREDENTIAL`
--

DROP TABLE IF EXISTS `FED_USER_CREDENTIAL`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `FED_USER_CREDENTIAL` (
  `ID` varchar(36) NOT NULL,
  `SALT` tinyblob DEFAULT NULL,
  `TYPE` varchar(255) DEFAULT NULL,
  `CREATED_DATE` bigint(20) DEFAULT NULL,
  `USER_ID` varchar(255) NOT NULL,
  `REALM_ID` varchar(36) NOT NULL,
  `STORAGE_PROVIDER_ID` varchar(36) DEFAULT NULL,
  `USER_LABEL` varchar(255) DEFAULT NULL,
  `SECRET_DATA` longtext DEFAULT NULL,
  `CREDENTIAL_DATA` longtext DEFAULT NULL,
  `PRIORITY` int(11) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_FU_CREDENTIAL` (`USER_ID`,`TYPE`),
  KEY `IDX_FU_CREDENTIAL_RU` (`REALM_ID`,`USER_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `FED_USER_CREDENTIAL`
--

LOCK TABLES `FED_USER_CREDENTIAL` WRITE;
/*!40000 ALTER TABLE `FED_USER_CREDENTIAL` DISABLE KEYS */;
/*!40000 ALTER TABLE `FED_USER_CREDENTIAL` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `FED_USER_GROUP_MEMBERSHIP`
--

DROP TABLE IF EXISTS `FED_USER_GROUP_MEMBERSHIP`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `FED_USER_GROUP_MEMBERSHIP` (
  `GROUP_ID` varchar(36) NOT NULL,
  `USER_ID` varchar(255) NOT NULL,
  `REALM_ID` varchar(36) NOT NULL,
  `STORAGE_PROVIDER_ID` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`GROUP_ID`,`USER_ID`),
  KEY `IDX_FU_GROUP_MEMBERSHIP` (`USER_ID`,`GROUP_ID`),
  KEY `IDX_FU_GROUP_MEMBERSHIP_RU` (`REALM_ID`,`USER_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `FED_USER_GROUP_MEMBERSHIP`
--

LOCK TABLES `FED_USER_GROUP_MEMBERSHIP` WRITE;
/*!40000 ALTER TABLE `FED_USER_GROUP_MEMBERSHIP` DISABLE KEYS */;
/*!40000 ALTER TABLE `FED_USER_GROUP_MEMBERSHIP` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `FED_USER_REQUIRED_ACTION`
--

DROP TABLE IF EXISTS `FED_USER_REQUIRED_ACTION`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `FED_USER_REQUIRED_ACTION` (
  `REQUIRED_ACTION` varchar(255) NOT NULL DEFAULT ' ',
  `USER_ID` varchar(255) NOT NULL,
  `REALM_ID` varchar(36) NOT NULL,
  `STORAGE_PROVIDER_ID` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`REQUIRED_ACTION`,`USER_ID`),
  KEY `IDX_FU_REQUIRED_ACTION` (`USER_ID`,`REQUIRED_ACTION`),
  KEY `IDX_FU_REQUIRED_ACTION_RU` (`REALM_ID`,`USER_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `FED_USER_REQUIRED_ACTION`
--

LOCK TABLES `FED_USER_REQUIRED_ACTION` WRITE;
/*!40000 ALTER TABLE `FED_USER_REQUIRED_ACTION` DISABLE KEYS */;
/*!40000 ALTER TABLE `FED_USER_REQUIRED_ACTION` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `FED_USER_ROLE_MAPPING`
--

DROP TABLE IF EXISTS `FED_USER_ROLE_MAPPING`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `FED_USER_ROLE_MAPPING` (
  `ROLE_ID` varchar(36) NOT NULL,
  `USER_ID` varchar(255) NOT NULL,
  `REALM_ID` varchar(36) NOT NULL,
  `STORAGE_PROVIDER_ID` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`ROLE_ID`,`USER_ID`),
  KEY `IDX_FU_ROLE_MAPPING` (`USER_ID`,`ROLE_ID`),
  KEY `IDX_FU_ROLE_MAPPING_RU` (`REALM_ID`,`USER_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `FED_USER_ROLE_MAPPING`
--

LOCK TABLES `FED_USER_ROLE_MAPPING` WRITE;
/*!40000 ALTER TABLE `FED_USER_ROLE_MAPPING` DISABLE KEYS */;
/*!40000 ALTER TABLE `FED_USER_ROLE_MAPPING` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `GROUP_ATTRIBUTE`
--

DROP TABLE IF EXISTS `GROUP_ATTRIBUTE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `GROUP_ATTRIBUTE` (
  `ID` varchar(36) NOT NULL DEFAULT 'sybase-needs-something-here',
  `NAME` varchar(255) NOT NULL,
  `VALUE` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `GROUP_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_GROUP_ATTR_GROUP` (`GROUP_ID`),
  KEY `IDX_GROUP_ATT_BY_NAME_VALUE` (`NAME`,`VALUE`),
  CONSTRAINT `FK_GROUP_ATTRIBUTE_GROUP` FOREIGN KEY (`GROUP_ID`) REFERENCES `KEYCLOAK_GROUP` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `GROUP_ATTRIBUTE`
--

LOCK TABLES `GROUP_ATTRIBUTE` WRITE;
/*!40000 ALTER TABLE `GROUP_ATTRIBUTE` DISABLE KEYS */;
/*!40000 ALTER TABLE `GROUP_ATTRIBUTE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `GROUP_ROLE_MAPPING`
--

DROP TABLE IF EXISTS `GROUP_ROLE_MAPPING`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `GROUP_ROLE_MAPPING` (
  `ROLE_ID` varchar(36) NOT NULL,
  `GROUP_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`ROLE_ID`,`GROUP_ID`),
  KEY `IDX_GROUP_ROLE_MAPP_GROUP` (`GROUP_ID`),
  CONSTRAINT `FK_GROUP_ROLE_GROUP` FOREIGN KEY (`GROUP_ID`) REFERENCES `KEYCLOAK_GROUP` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `GROUP_ROLE_MAPPING`
--

LOCK TABLES `GROUP_ROLE_MAPPING` WRITE;
/*!40000 ALTER TABLE `GROUP_ROLE_MAPPING` DISABLE KEYS */;
/*!40000 ALTER TABLE `GROUP_ROLE_MAPPING` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `IDENTITY_PROVIDER`
--

DROP TABLE IF EXISTS `IDENTITY_PROVIDER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `IDENTITY_PROVIDER` (
  `INTERNAL_ID` varchar(36) NOT NULL,
  `ENABLED` bit(1) NOT NULL DEFAULT b'0',
  `PROVIDER_ALIAS` varchar(255) DEFAULT NULL,
  `PROVIDER_ID` varchar(255) DEFAULT NULL,
  `STORE_TOKEN` bit(1) NOT NULL DEFAULT b'0',
  `AUTHENTICATE_BY_DEFAULT` bit(1) NOT NULL DEFAULT b'0',
  `REALM_ID` varchar(36) DEFAULT NULL,
  `ADD_TOKEN_ROLE` bit(1) NOT NULL DEFAULT b'1',
  `TRUST_EMAIL` bit(1) NOT NULL DEFAULT b'0',
  `FIRST_BROKER_LOGIN_FLOW_ID` varchar(36) DEFAULT NULL,
  `POST_BROKER_LOGIN_FLOW_ID` varchar(36) DEFAULT NULL,
  `PROVIDER_DISPLAY_NAME` varchar(255) DEFAULT NULL,
  `LINK_ONLY` bit(1) NOT NULL DEFAULT b'0',
  PRIMARY KEY (`INTERNAL_ID`),
  UNIQUE KEY `UK_2DAELWNIBJI49AVXSRTUF6XJ33` (`PROVIDER_ALIAS`,`REALM_ID`),
  KEY `IDX_IDENT_PROV_REALM` (`REALM_ID`),
  CONSTRAINT `FK2B4EBC52AE5C3B34` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `IDENTITY_PROVIDER`
--

LOCK TABLES `IDENTITY_PROVIDER` WRITE;
/*!40000 ALTER TABLE `IDENTITY_PROVIDER` DISABLE KEYS */;
/*!40000 ALTER TABLE `IDENTITY_PROVIDER` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `IDENTITY_PROVIDER_CONFIG`
--

DROP TABLE IF EXISTS `IDENTITY_PROVIDER_CONFIG`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `IDENTITY_PROVIDER_CONFIG` (
  `IDENTITY_PROVIDER_ID` varchar(36) NOT NULL,
  `VALUE` longtext DEFAULT NULL,
  `NAME` varchar(255) NOT NULL,
  PRIMARY KEY (`IDENTITY_PROVIDER_ID`,`NAME`),
  CONSTRAINT `FKDC4897CF864C4E43` FOREIGN KEY (`IDENTITY_PROVIDER_ID`) REFERENCES `IDENTITY_PROVIDER` (`INTERNAL_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `IDENTITY_PROVIDER_CONFIG`
--

LOCK TABLES `IDENTITY_PROVIDER_CONFIG` WRITE;
/*!40000 ALTER TABLE `IDENTITY_PROVIDER_CONFIG` DISABLE KEYS */;
/*!40000 ALTER TABLE `IDENTITY_PROVIDER_CONFIG` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `IDENTITY_PROVIDER_MAPPER`
--

DROP TABLE IF EXISTS `IDENTITY_PROVIDER_MAPPER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `IDENTITY_PROVIDER_MAPPER` (
  `ID` varchar(36) NOT NULL,
  `NAME` varchar(255) NOT NULL,
  `IDP_ALIAS` varchar(255) NOT NULL,
  `IDP_MAPPER_NAME` varchar(255) NOT NULL,
  `REALM_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_ID_PROV_MAPP_REALM` (`REALM_ID`),
  CONSTRAINT `FK_IDPM_REALM` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `IDENTITY_PROVIDER_MAPPER`
--

LOCK TABLES `IDENTITY_PROVIDER_MAPPER` WRITE;
/*!40000 ALTER TABLE `IDENTITY_PROVIDER_MAPPER` DISABLE KEYS */;
/*!40000 ALTER TABLE `IDENTITY_PROVIDER_MAPPER` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `IDP_MAPPER_CONFIG`
--

DROP TABLE IF EXISTS `IDP_MAPPER_CONFIG`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `IDP_MAPPER_CONFIG` (
  `IDP_MAPPER_ID` varchar(36) NOT NULL,
  `VALUE` longtext DEFAULT NULL,
  `NAME` varchar(255) NOT NULL,
  PRIMARY KEY (`IDP_MAPPER_ID`,`NAME`),
  CONSTRAINT `FK_IDPMCONFIG` FOREIGN KEY (`IDP_MAPPER_ID`) REFERENCES `IDENTITY_PROVIDER_MAPPER` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `IDP_MAPPER_CONFIG`
--

LOCK TABLES `IDP_MAPPER_CONFIG` WRITE;
/*!40000 ALTER TABLE `IDP_MAPPER_CONFIG` DISABLE KEYS */;
/*!40000 ALTER TABLE `IDP_MAPPER_CONFIG` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `KEYCLOAK_GROUP`
--

DROP TABLE IF EXISTS `KEYCLOAK_GROUP`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `KEYCLOAK_GROUP` (
  `ID` varchar(36) NOT NULL,
  `NAME` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `PARENT_GROUP` varchar(36) NOT NULL,
  `REALM_ID` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `SIBLING_NAMES` (`REALM_ID`,`PARENT_GROUP`,`NAME`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `KEYCLOAK_GROUP`
--

LOCK TABLES `KEYCLOAK_GROUP` WRITE;
/*!40000 ALTER TABLE `KEYCLOAK_GROUP` DISABLE KEYS */;
/*!40000 ALTER TABLE `KEYCLOAK_GROUP` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `KEYCLOAK_ROLE`
--

DROP TABLE IF EXISTS `KEYCLOAK_ROLE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `KEYCLOAK_ROLE` (
  `ID` varchar(36) NOT NULL,
  `CLIENT_REALM_CONSTRAINT` varchar(255) DEFAULT NULL,
  `CLIENT_ROLE` bit(1) DEFAULT NULL,
  `DESCRIPTION` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `NAME` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `REALM_ID` varchar(255) DEFAULT NULL,
  `CLIENT` varchar(36) DEFAULT NULL,
  `REALM` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK_J3RWUVD56ONTGSUHOGM184WW2-2` (`NAME`,`CLIENT_REALM_CONSTRAINT`),
  KEY `IDX_KEYCLOAK_ROLE_CLIENT` (`CLIENT`),
  KEY `IDX_KEYCLOAK_ROLE_REALM` (`REALM`),
  CONSTRAINT `FK_6VYQFE4CN4WLQ8R6KT5VDSJ5C` FOREIGN KEY (`REALM`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `KEYCLOAK_ROLE`
--

LOCK TABLES `KEYCLOAK_ROLE` WRITE;
/*!40000 ALTER TABLE `KEYCLOAK_ROLE` DISABLE KEYS */;
INSERT INTO `KEYCLOAK_ROLE` VALUES
('00548d93-c95b-4b4e-935f-dc7350eeab18','61c254e2-095d-42b9-b8cc-4546b124e548','\0','${role_offline-access}','offline_access','61c254e2-095d-42b9-b8cc-4546b124e548',NULL,NULL),
('009151c1-73fb-49a1-aaac-4fad108e35a6','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_view-identity-providers}','view-identity-providers','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('01c07194-f50e-42e2-b4e2-b6a835490ca0','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_view-clients}','view-clients','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('05174a3b-088b-4002-9c29-07538b027be2','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_query-groups}','query-groups','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('052dca65-a7ac-40c0-bb1f-44364166a074','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_create-client}','create-client','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('1185008a-2fc8-4130-a739-6bea4b2c5c42','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_view-realm}','view-realm','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('16f17961-625d-40ab-b126-75d204f36f47','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_manage-events}','manage-events','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('1795c388-e345-4ebd-a1d7-446b280ac328','e32dde36-fa71-4648-aa46-ad822a2b51b6','','${role_view-consent}','view-consent','61c254e2-095d-42b9-b8cc-4546b124e548','e32dde36-fa71-4648-aa46-ad822a2b51b6',NULL),
('1fa32b1c-f9e1-4d29-b3e5-104941bbb22d','e32dde36-fa71-4648-aa46-ad822a2b51b6','','${role_view-groups}','view-groups','61c254e2-095d-42b9-b8cc-4546b124e548','e32dde36-fa71-4648-aa46-ad822a2b51b6',NULL),
('205450af-538d-40bc-b603-6c3f397a38b8','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_query-realms}','query-realms','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('20704d30-91d2-411f-9196-55c499d695e5','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_query-realms}','query-realms','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('232975a2-7616-4265-9a53-263371bf3dba','a4c24db6-3fe8-4b9c-a183-42a75148d531','','${role_delete-account}','delete-account','139c1488-d000-4061-922b-0c0b518a57db','a4c24db6-3fe8-4b9c-a183-42a75148d531',NULL),
('2bfb4c07-96ff-4bee-a320-400149aca314','a4c24db6-3fe8-4b9c-a183-42a75148d531','','${role_manage-consent}','manage-consent','139c1488-d000-4061-922b-0c0b518a57db','a4c24db6-3fe8-4b9c-a183-42a75148d531',NULL),
('33db5e49-04dc-4308-8482-8f21e65d6d38','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_impersonation}','impersonation','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('353d13e0-1758-44c8-935b-033310bb9986','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_view-events}','view-events','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('36351f76-327c-4f18-bb9d-7213f9ad0443','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_view-users}','view-users','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('38491d89-be33-4e91-8c2d-4faf6a8b269d','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_view-clients}','view-clients','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('3867b96c-2e58-49f9-8f96-947baf448f06','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_impersonation}','impersonation','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('4109672e-c529-4d28-88e6-8fedf3c20003','e32dde36-fa71-4648-aa46-ad822a2b51b6','','${role_manage-account}','manage-account','61c254e2-095d-42b9-b8cc-4546b124e548','e32dde36-fa71-4648-aa46-ad822a2b51b6',NULL),
('42a33d3d-706d-4ae7-bf4d-46b34e1f6f5a','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_query-groups}','query-groups','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('4637444f-6a2a-4110-8522-f8b54d0e883b','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_manage-users}','manage-users','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('4a691081-0cec-4c8b-bb10-b74cd59896f6','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_view-identity-providers}','view-identity-providers','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('4add9c78-35c6-484a-a58c-b71a30d02088','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_view-authorization}','view-authorization','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('4d8aa6fc-a874-4c90-a7d3-07e1799ed673','e32dde36-fa71-4648-aa46-ad822a2b51b6','','${role_view-profile}','view-profile','61c254e2-095d-42b9-b8cc-4546b124e548','e32dde36-fa71-4648-aa46-ad822a2b51b6',NULL),
('5095e6ed-ecea-4edb-af97-4d68dbe60131','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_manage-authorization}','manage-authorization','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('53348c67-aca5-4c1c-8752-2952e9aab11f','e32dde36-fa71-4648-aa46-ad822a2b51b6','','${role_manage-account-links}','manage-account-links','61c254e2-095d-42b9-b8cc-4546b124e548','e32dde36-fa71-4648-aa46-ad822a2b51b6',NULL),
('58a0e65c-2c32-4d65-8262-109da2df0be2','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_manage-users}','manage-users','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('5a4942b6-9d9c-42e3-8acf-f394a4c8653b','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_query-clients}','query-clients','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('609171eb-cfe0-4357-bf64-f226b7bf0120','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_manage-identity-providers}','manage-identity-providers','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('640f2839-b2f1-49fa-bb7e-605793c08de8','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_view-realm}','view-realm','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('6442256b-075e-446a-80d3-bf6f4e2e1280','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_manage-clients}','manage-clients','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('678e41c9-9bea-4f92-a223-c4747aa6ee06','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_query-clients}','query-clients','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('6a0f13ce-eb85-4218-b1ac-1a0bc41e3f34','e32dde36-fa71-4648-aa46-ad822a2b51b6','','${role_delete-account}','delete-account','61c254e2-095d-42b9-b8cc-4546b124e548','e32dde36-fa71-4648-aa46-ad822a2b51b6',NULL),
('6b3487ba-98af-4992-a798-40f499258d5a','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_manage-clients}','manage-clients','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('6fbdc1e8-af2f-402c-9f73-5594291adc5d','e32dde36-fa71-4648-aa46-ad822a2b51b6','','${role_manage-consent}','manage-consent','61c254e2-095d-42b9-b8cc-4546b124e548','e32dde36-fa71-4648-aa46-ad822a2b51b6',NULL),
('6fd3938c-9f28-423a-b49a-9b7059b52b42','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_view-clients}','view-clients','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('6ffb1dfd-3599-4020-9d72-a985752c38b5','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_manage-clients}','manage-clients','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('714a6f1e-de37-4768-b6c5-f4792079b510','139c1488-d000-4061-922b-0c0b518a57db','\0','${role_default-roles}','default-roles-ruciodev','139c1488-d000-4061-922b-0c0b518a57db',NULL,NULL),
('714f833e-ed29-4000-b932-273a246d4dd6','a4c24db6-3fe8-4b9c-a183-42a75148d531','','${role_view-groups}','view-groups','139c1488-d000-4061-922b-0c0b518a57db','a4c24db6-3fe8-4b9c-a183-42a75148d531',NULL),
('73e0c1dc-6c4e-4171-acf8-028331b29e98','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_query-users}','query-users','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('7a3dbc3a-e26c-4c0e-850b-be0dfc351c45','61c254e2-095d-42b9-b8cc-4546b124e548','\0','${role_uma_authorization}','uma_authorization','61c254e2-095d-42b9-b8cc-4546b124e548',NULL,NULL),
('7dfc3803-4c51-4482-a1cf-a0917a3827cb','61c254e2-095d-42b9-b8cc-4546b124e548','\0','${role_create-realm}','create-realm','61c254e2-095d-42b9-b8cc-4546b124e548',NULL,NULL),
('7e750a3e-d379-47a4-be5d-7837288f5183','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_query-realms}','query-realms','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('7ee50819-d0a6-4f02-8f14-173ca69f1e88','a4c24db6-3fe8-4b9c-a183-42a75148d531','','${role_view-profile}','view-profile','139c1488-d000-4061-922b-0c0b518a57db','a4c24db6-3fe8-4b9c-a183-42a75148d531',NULL),
('82172a02-4770-4cac-9b17-662296c219a4','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_view-realm}','view-realm','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('83406e1d-a189-4b0f-8ec5-81bbeae69990','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_view-authorization}','view-authorization','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('89e9a8d0-9511-4ae9-9897-0956de721ef2','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_query-clients}','query-clients','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('8aa9d67b-3631-41b4-928f-8d6e35b53ad4','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_impersonation}','impersonation','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('8d7973a1-8d62-4add-91e8-1a6676fc9ecd','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_create-client}','create-client','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('8f1f8106-eae4-4213-8aa5-1480597cdec0','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_view-events}','view-events','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('92cd6f9f-d95e-4429-b351-fcf91d487831','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_query-users}','query-users','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('939a1da5-c2f9-4e25-a1af-4e50b50bdb70','a4c24db6-3fe8-4b9c-a183-42a75148d531','','${role_view-applications}','view-applications','139c1488-d000-4061-922b-0c0b518a57db','a4c24db6-3fe8-4b9c-a183-42a75148d531',NULL),
('9cc50a6b-3f60-4fc4-8bd0-43bf1d9d73a0','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_manage-identity-providers}','manage-identity-providers','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('a30019cc-a32c-414c-a159-4bdbff80e001','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_manage-authorization}','manage-authorization','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('a8f531c2-32e6-4497-9418-4f32191c1511','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_view-users}','view-users','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('a99f8c3b-b9cc-474d-88da-b81278c8a540','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_create-client}','create-client','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('ae7725b3-9a0b-407f-a946-ad3dd390e4f7','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_manage-realm}','manage-realm','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('b3fc8427-4555-4e10-89e5-7dac86a0b949','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_view-identity-providers}','view-identity-providers','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('b5be4df0-94bc-4f40-ae24-5ddba4b46bc8','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_manage-events}','manage-events','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('b5ff560b-85bd-4754-91c9-d2cc0f4e84dd','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_query-users}','query-users','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('bbbaba4f-8c07-4814-b88f-e50950dcb720','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_realm-admin}','realm-admin','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('bef34cd4-1605-4b4f-be25-e2947ab173ad','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_manage-realm}','manage-realm','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('c020bf25-1d76-4643-a446-73d175effe97','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_manage-identity-providers}','manage-identity-providers','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('c0728a25-e2bf-409b-adc0-144daffad036','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_manage-events}','manage-events','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('c120de31-e61d-41b1-a174-5e0fdf6c0ab9','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_manage-realm}','manage-realm','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('c34bdf52-2dc2-49ba-ab5c-f6f4f41ea594','6fcc4ef0-a82c-453e-90ba-0753d2c11c58','','${role_query-groups}','query-groups','61c254e2-095d-42b9-b8cc-4546b124e548','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',NULL),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','61c254e2-095d-42b9-b8cc-4546b124e548','\0','${role_admin}','admin','61c254e2-095d-42b9-b8cc-4546b124e548',NULL,NULL),
('c61a6a3e-226d-490d-99fc-8cb2bac6c7ae','e32dde36-fa71-4648-aa46-ad822a2b51b6','','${role_view-applications}','view-applications','61c254e2-095d-42b9-b8cc-4546b124e548','e32dde36-fa71-4648-aa46-ad822a2b51b6',NULL),
('c998f25f-8e0c-49bd-8263-51997f7a5ffe','c620e22e-74cc-43ed-aa93-92eceaf14f6d','','${role_read-token}','read-token','61c254e2-095d-42b9-b8cc-4546b124e548','c620e22e-74cc-43ed-aa93-92eceaf14f6d',NULL),
('cd82ab55-5d73-49a5-b659-3bc83bc4e06b','a4c24db6-3fe8-4b9c-a183-42a75148d531','','${role_manage-account}','manage-account','139c1488-d000-4061-922b-0c0b518a57db','a4c24db6-3fe8-4b9c-a183-42a75148d531',NULL),
('ddeca6bf-8e98-491c-b9bd-52a60e03b019','139c1488-d000-4061-922b-0c0b518a57db','\0','${role_offline-access}','offline_access','139c1488-d000-4061-922b-0c0b518a57db',NULL,NULL),
('df76e680-bebc-4b85-a723-c5adf7ef86c6','61c254e2-095d-42b9-b8cc-4546b124e548','\0','${role_default-roles}','default-roles-master','61c254e2-095d-42b9-b8cc-4546b124e548',NULL,NULL),
('e33cb259-285b-4ebd-af96-3be259c3b84e','53ef6db9-271e-46c5-bd72-2f12ea045014','',NULL,'uma_protection','139c1488-d000-4061-922b-0c0b518a57db','53ef6db9-271e-46c5-bd72-2f12ea045014',NULL),
('e52971bb-c676-44ef-a300-ddea4045558d','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_view-events}','view-events','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('e6b9c690-17a2-40d7-8aac-2e0893e42b33','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_view-users}','view-users','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('ef4ebfff-60b0-4e62-b978-bc70ba8f981e','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_view-authorization}','view-authorization','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('f385ab65-af3b-4440-9735-c30448b45280','e7416090-7f37-401b-b69f-a10a8f8a9a46','','${role_manage-users}','manage-users','61c254e2-095d-42b9-b8cc-4546b124e548','e7416090-7f37-401b-b69f-a10a8f8a9a46',NULL),
('f46ad52d-a078-407f-bd62-1708245a4449','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','','${role_manage-authorization}','manage-authorization','139c1488-d000-4061-922b-0c0b518a57db','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('f83d7f0a-9b46-440e-aebe-e3c1fb78d0f4','139c1488-d000-4061-922b-0c0b518a57db','\0','${role_uma_authorization}','uma_authorization','139c1488-d000-4061-922b-0c0b518a57db',NULL,NULL),
('fad25aed-3ae5-4f8a-924e-36378e01b241','a4c24db6-3fe8-4b9c-a183-42a75148d531','','${role_manage-account-links}','manage-account-links','139c1488-d000-4061-922b-0c0b518a57db','a4c24db6-3fe8-4b9c-a183-42a75148d531',NULL),
('fba53dd0-041c-4824-acc9-5f1c181d6c4c','a4c24db6-3fe8-4b9c-a183-42a75148d531','','${role_view-consent}','view-consent','139c1488-d000-4061-922b-0c0b518a57db','a4c24db6-3fe8-4b9c-a183-42a75148d531',NULL),
('fed233f6-b3a0-4dc9-8759-e8be1bdf07f3','8d0348ea-8e2b-47bf-a95b-69df3d711ebf','','${role_read-token}','read-token','139c1488-d000-4061-922b-0c0b518a57db','8d0348ea-8e2b-47bf-a95b-69df3d711ebf',NULL);
/*!40000 ALTER TABLE `KEYCLOAK_ROLE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `MIGRATION_MODEL`
--

DROP TABLE IF EXISTS `MIGRATION_MODEL`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `MIGRATION_MODEL` (
  `ID` varchar(36) NOT NULL,
  `VERSION` varchar(36) DEFAULT NULL,
  `UPDATE_TIME` bigint(20) NOT NULL DEFAULT 0,
  PRIMARY KEY (`ID`),
  KEY `IDX_UPDATE_TIME` (`UPDATE_TIME`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `MIGRATION_MODEL`
--

LOCK TABLES `MIGRATION_MODEL` WRITE;
/*!40000 ALTER TABLE `MIGRATION_MODEL` DISABLE KEYS */;
INSERT INTO `MIGRATION_MODEL` VALUES
('y35a5','23.0.1',1702649217);
/*!40000 ALTER TABLE `MIGRATION_MODEL` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `OFFLINE_CLIENT_SESSION`
--

DROP TABLE IF EXISTS `OFFLINE_CLIENT_SESSION`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `OFFLINE_CLIENT_SESSION` (
  `USER_SESSION_ID` varchar(36) NOT NULL,
  `CLIENT_ID` varchar(255) NOT NULL,
  `OFFLINE_FLAG` varchar(4) NOT NULL,
  `TIMESTAMP` int(11) DEFAULT NULL,
  `DATA` longtext DEFAULT NULL,
  `CLIENT_STORAGE_PROVIDER` varchar(36) NOT NULL DEFAULT 'local',
  `EXTERNAL_CLIENT_ID` varchar(255) NOT NULL DEFAULT 'local',
  PRIMARY KEY (`USER_SESSION_ID`,`CLIENT_ID`,`CLIENT_STORAGE_PROVIDER`,`EXTERNAL_CLIENT_ID`,`OFFLINE_FLAG`),
  KEY `IDX_US_SESS_ID_ON_CL_SESS` (`USER_SESSION_ID`),
  KEY `IDX_OFFLINE_CSS_PRELOAD` (`CLIENT_ID`,`OFFLINE_FLAG`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `OFFLINE_CLIENT_SESSION`
--

LOCK TABLES `OFFLINE_CLIENT_SESSION` WRITE;
/*!40000 ALTER TABLE `OFFLINE_CLIENT_SESSION` DISABLE KEYS */;
/*!40000 ALTER TABLE `OFFLINE_CLIENT_SESSION` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `OFFLINE_USER_SESSION`
--

DROP TABLE IF EXISTS `OFFLINE_USER_SESSION`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `OFFLINE_USER_SESSION` (
  `USER_SESSION_ID` varchar(36) NOT NULL,
  `USER_ID` varchar(255) DEFAULT NULL,
  `REALM_ID` varchar(36) NOT NULL,
  `CREATED_ON` int(11) NOT NULL,
  `OFFLINE_FLAG` varchar(4) NOT NULL,
  `DATA` longtext DEFAULT NULL,
  `LAST_SESSION_REFRESH` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`USER_SESSION_ID`,`OFFLINE_FLAG`),
  KEY `IDX_OFFLINE_USS_CREATEDON` (`CREATED_ON`),
  KEY `IDX_OFFLINE_USS_PRELOAD` (`OFFLINE_FLAG`,`CREATED_ON`,`USER_SESSION_ID`),
  KEY `IDX_OFFLINE_USS_BY_USER` (`USER_ID`,`REALM_ID`,`OFFLINE_FLAG`),
  KEY `IDX_OFFLINE_USS_BY_USERSESS` (`REALM_ID`,`OFFLINE_FLAG`,`USER_SESSION_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `OFFLINE_USER_SESSION`
--

LOCK TABLES `OFFLINE_USER_SESSION` WRITE;
/*!40000 ALTER TABLE `OFFLINE_USER_SESSION` DISABLE KEYS */;
/*!40000 ALTER TABLE `OFFLINE_USER_SESSION` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `POLICY_CONFIG`
--

DROP TABLE IF EXISTS `POLICY_CONFIG`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `POLICY_CONFIG` (
  `POLICY_ID` varchar(36) NOT NULL,
  `NAME` varchar(255) NOT NULL,
  `VALUE` longtext DEFAULT NULL,
  PRIMARY KEY (`POLICY_ID`,`NAME`),
  CONSTRAINT `FKDC34197CF864C4E43` FOREIGN KEY (`POLICY_ID`) REFERENCES `RESOURCE_SERVER_POLICY` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `POLICY_CONFIG`
--

LOCK TABLES `POLICY_CONFIG` WRITE;
/*!40000 ALTER TABLE `POLICY_CONFIG` DISABLE KEYS */;
INSERT INTO `POLICY_CONFIG` VALUES
('71dd1617-3f3b-41d1-8ea7-a2a9f48e5d12','defaultResourceType','urn:rucio:resources:default'),
('a53eb10e-0623-4586-a482-7a41666a4c68','clients','[\"53ef6db9-271e-46c5-bd72-2f12ea045014\"]'),
('cd2e5ea5-10ef-4aed-8871-a8d31296c40b','code','// by default, grants any permission associated with this policy\n$evaluation.grant();\n');
/*!40000 ALTER TABLE `POLICY_CONFIG` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `PROTOCOL_MAPPER`
--

DROP TABLE IF EXISTS `PROTOCOL_MAPPER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `PROTOCOL_MAPPER` (
  `ID` varchar(36) NOT NULL,
  `NAME` varchar(255) NOT NULL,
  `PROTOCOL` varchar(255) NOT NULL,
  `PROTOCOL_MAPPER_NAME` varchar(255) NOT NULL,
  `CLIENT_ID` varchar(36) DEFAULT NULL,
  `CLIENT_SCOPE_ID` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_PROTOCOL_MAPPER_CLIENT` (`CLIENT_ID`),
  KEY `IDX_CLSCOPE_PROTMAP` (`CLIENT_SCOPE_ID`),
  CONSTRAINT `FK_CLI_SCOPE_MAPPER` FOREIGN KEY (`CLIENT_SCOPE_ID`) REFERENCES `CLIENT_SCOPE` (`ID`),
  CONSTRAINT `FK_PCM_REALM` FOREIGN KEY (`CLIENT_ID`) REFERENCES `CLIENT` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `PROTOCOL_MAPPER`
--

LOCK TABLES `PROTOCOL_MAPPER` WRITE;
/*!40000 ALTER TABLE `PROTOCOL_MAPPER` DISABLE KEYS */;
INSERT INTO `PROTOCOL_MAPPER` VALUES
('01608a55-6aa1-475f-be1b-4e1f029baefd','phone number verified','openid-connect','oidc-usermodel-attribute-mapper',NULL,'0b211c52-ca02-4f22-b786-5a0b5085fc78'),
('0c89d6e5-00f2-4623-b1d7-529b1c66a375','role list','saml','saml-role-list-mapper',NULL,'8920b300-1b2f-4d18-ab8a-e975974fd013'),
('0dbf3f93-ee43-43e4-8c68-d3385ab248d8','address','openid-connect','oidc-address-mapper',NULL,'4e38235f-7289-4fa2-9840-d4a4fbcd2e0e'),
('18a60d34-ec09-4d8a-a845-24030b74c123','updated at','openid-connect','oidc-usermodel-attribute-mapper',NULL,'78975493-67a3-4819-a933-47b99c7c7e60'),
('1daa5ef3-bb79-4d77-b06d-add8569936d9','picture','openid-connect','oidc-usermodel-attribute-mapper',NULL,'78975493-67a3-4819-a933-47b99c7c7e60'),
('22d85363-1a89-42e1-93bf-5f6840fdbe49','family name','openid-connect','oidc-usermodel-attribute-mapper',NULL,'0526da56-aab3-455b-9cc8-2d3d8b0457d6'),
('2ab53293-9cb2-455c-9843-0289ecd02d9f','audience resolve','openid-connect','oidc-audience-resolve-mapper','9c1f7e9e-8703-4cca-82b0-d944dbf29287',NULL),
('2e3f66cb-169f-41bd-ba65-eff34aaecece','nickname','openid-connect','oidc-usermodel-attribute-mapper',NULL,'0526da56-aab3-455b-9cc8-2d3d8b0457d6'),
('38429562-4941-486d-8004-74fe49a6246a','client roles','openid-connect','oidc-usermodel-client-role-mapper',NULL,'d6da6000-2013-417d-ad33-33f0804b5b80'),
('3c9ddb32-0ffa-4c2e-a358-0d2a53d8c13e','family name','openid-connect','oidc-usermodel-attribute-mapper',NULL,'78975493-67a3-4819-a933-47b99c7c7e60'),
('416a5ba2-0bb4-4648-8ee9-c957b00b91a2','fake WLCG','openid-connect','oidc-hardcoded-claim-mapper',NULL,'5e32d7b8-50b7-4a49-90d4-8c1e467a427c'),
('470385c7-0a22-4b7b-a577-08cee38a1b1c','Client ID','openid-connect','oidc-usersessionmodel-note-mapper','53ef6db9-271e-46c5-bd72-2f12ea045014',NULL),
('48db3c6f-dc97-44ab-81be-4ddd9897cf04','locale','openid-connect','oidc-usermodel-attribute-mapper','79748e7e-06c2-4915-988c-0e30b15d12db',NULL),
('49ad759d-468b-4143-92db-4dc0f46013a0','profile','openid-connect','oidc-usermodel-attribute-mapper',NULL,'0526da56-aab3-455b-9cc8-2d3d8b0457d6'),
('56533a62-aabe-4ae9-b8e6-e38b9a6fd3c3','given name','openid-connect','oidc-usermodel-attribute-mapper',NULL,'78975493-67a3-4819-a933-47b99c7c7e60'),
('58e80442-f8c7-4314-bfdf-233027e87352','updated at','openid-connect','oidc-usermodel-attribute-mapper',NULL,'0526da56-aab3-455b-9cc8-2d3d8b0457d6'),
('5eaffc1b-395b-44f8-8b64-76e82c20947d','email','openid-connect','oidc-usermodel-attribute-mapper',NULL,'0c885a01-891a-481f-9087-f6567af22b13'),
('60d49624-fb89-42de-91de-ebb416c9fad5','picture','openid-connect','oidc-usermodel-attribute-mapper',NULL,'0526da56-aab3-455b-9cc8-2d3d8b0457d6'),
('60f0e13a-df86-40c1-83e0-946d9a7b886b','phone number','openid-connect','oidc-usermodel-attribute-mapper',NULL,'5019c5be-c7bd-47b0-a5b3-403a98162efe'),
('66cb7058-f6d8-4c6b-b209-7f12aa53c3a1','allowed web origins','openid-connect','oidc-allowed-origins-mapper',NULL,'781fbb54-8552-44a0-9ea2-fab43dcf0b24'),
('6bc39891-e7b6-4d10-9503-7be24762becb','audience resolve','openid-connect','oidc-audience-resolve-mapper','2f7d86a0-e8ba-4b75-9009-2048c5611177',NULL),
('71e07291-04c9-434d-b074-46ec1efd64c7','Client Host','openid-connect','oidc-usersessionmodel-note-mapper','53ef6db9-271e-46c5-bd72-2f12ea045014',NULL),
('769ed209-c1b1-43ab-9b22-61a86a90320a','locale','openid-connect','oidc-usermodel-attribute-mapper',NULL,'0526da56-aab3-455b-9cc8-2d3d8b0457d6'),
('783b43e8-4cc2-42c6-a088-8a4843808d77','upn','openid-connect','oidc-usermodel-attribute-mapper',NULL,'c945998b-68b7-4894-9561-7863799cc667'),
('78d1bef3-0c11-455f-8267-ec0a034c6d83','profile','openid-connect','oidc-usermodel-attribute-mapper',NULL,'78975493-67a3-4819-a933-47b99c7c7e60'),
('7a10a289-352f-46b7-9b70-f1c66213876a','birthdate','openid-connect','oidc-usermodel-attribute-mapper',NULL,'0526da56-aab3-455b-9cc8-2d3d8b0457d6'),
('830ba79a-d2e0-4681-b5f4-cfdbd93fe96c','birthdate','openid-connect','oidc-usermodel-attribute-mapper',NULL,'78975493-67a3-4819-a933-47b99c7c7e60'),
('84f39479-8dc5-4d83-8610-c4235297230d','locale','openid-connect','oidc-usermodel-attribute-mapper','8b2528fe-d14e-4b36-8b3d-4a44b89bd6dc',NULL),
('85e51600-dc92-474a-ad36-8844b4387adf','gender','openid-connect','oidc-usermodel-attribute-mapper',NULL,'78975493-67a3-4819-a933-47b99c7c7e60'),
('865e5a79-a1c3-41c2-b065-0eaa3e49df0d','zoneinfo','openid-connect','oidc-usermodel-attribute-mapper',NULL,'78975493-67a3-4819-a933-47b99c7c7e60'),
('8bb1286e-e063-4050-9e8f-965c41819b03','email','openid-connect','oidc-usermodel-attribute-mapper',NULL,'afc839cc-2307-4260-9924-338375d22c2b'),
('8c1d0e40-ce2d-4261-b70e-e88e361a8913','username','openid-connect','oidc-usermodel-attribute-mapper',NULL,'0526da56-aab3-455b-9cc8-2d3d8b0457d6'),
('8faf27d9-7a46-42a0-9995-a474a476cfe1','groups','openid-connect','oidc-usermodel-realm-role-mapper',NULL,'c945998b-68b7-4894-9561-7863799cc667'),
('92bad947-1587-4810-98fa-15ecf6f84771','upn','openid-connect','oidc-usermodel-attribute-mapper',NULL,'ccb9d5ba-bf89-4762-81c1-c9c87da7d1e8'),
('9c9a48cc-0746-45bc-8609-4650a7e656b6','given name','openid-connect','oidc-usermodel-attribute-mapper',NULL,'0526da56-aab3-455b-9cc8-2d3d8b0457d6'),
('9f7e6fd4-a29f-428a-b3a6-bad7d1ef9b37','phone number verified','openid-connect','oidc-usermodel-attribute-mapper',NULL,'5019c5be-c7bd-47b0-a5b3-403a98162efe'),
('9f912bc4-e8af-4908-9d79-f0f536325310','phone number','openid-connect','oidc-usermodel-attribute-mapper',NULL,'0b211c52-ca02-4f22-b786-5a0b5085fc78'),
('a04e74fc-2155-4b1f-afab-e01efd93bc45','middle name','openid-connect','oidc-usermodel-attribute-mapper',NULL,'78975493-67a3-4819-a933-47b99c7c7e60'),
('a4a85ba9-400a-4c7c-8a8b-d7f77958dfe0','full name','openid-connect','oidc-full-name-mapper',NULL,'0526da56-aab3-455b-9cc8-2d3d8b0457d6'),
('a9f06dc0-6493-4843-94b9-a30d2301e0dd','zoneinfo','openid-connect','oidc-usermodel-attribute-mapper',NULL,'0526da56-aab3-455b-9cc8-2d3d8b0457d6'),
('b02135db-6b29-4d73-9e19-4ab35d0c21aa','full name','openid-connect','oidc-full-name-mapper',NULL,'78975493-67a3-4819-a933-47b99c7c7e60'),
('b5a9a8d1-c6ce-458b-ad1f-66f4576979d1','address','openid-connect','oidc-address-mapper',NULL,'434407ef-1d7f-45e8-b91c-7db10210760a'),
('b86d89b9-4914-4a9a-93c3-8aac4f1e0716','acr loa level','openid-connect','oidc-acr-mapper',NULL,'e0711367-7927-43ef-9419-42e57c1d7dd4'),
('bfaabf99-700b-4960-b732-b89db862c423','realm roles','openid-connect','oidc-usermodel-realm-role-mapper',NULL,'d6da6000-2013-417d-ad33-33f0804b5b80'),
('c072bc17-d43f-40e3-9f09-00d3e11aec63','email verified','openid-connect','oidc-usermodel-property-mapper',NULL,'afc839cc-2307-4260-9924-338375d22c2b'),
('d39b4063-b5ed-475e-a88d-d6f0b0ebdf6b','email verified','openid-connect','oidc-usermodel-property-mapper',NULL,'0c885a01-891a-481f-9087-f6567af22b13'),
('d45fc134-3030-4aff-b162-c7b139cc94f3','client roles','openid-connect','oidc-usermodel-client-role-mapper',NULL,'21ce4324-232a-46b2-b113-9407b67de017'),
('d9ad77a8-6411-437b-9aaf-c4f92b8a1b2d','role list','saml','saml-role-list-mapper',NULL,'7c7de55b-c72a-4006-9b14-db1398fed22f'),
('d9c98c62-6649-4f94-8ed4-db3634e5326a','Client IP Address','openid-connect','oidc-usersessionmodel-note-mapper','53ef6db9-271e-46c5-bd72-2f12ea045014',NULL),
('db5ce96a-8bca-4ac2-9f9f-d942c1c1476a','middle name','openid-connect','oidc-usermodel-attribute-mapper',NULL,'0526da56-aab3-455b-9cc8-2d3d8b0457d6'),
('e191d9df-7c0e-45d0-9648-5ef6016c84d1','allowed web origins','openid-connect','oidc-allowed-origins-mapper',NULL,'ede179a5-d38e-4943-98f9-627b3b05848d'),
('e82117a5-b0ee-47da-8142-3f3e8c124efb','groups','openid-connect','oidc-usermodel-realm-role-mapper',NULL,'ccb9d5ba-bf89-4762-81c1-c9c87da7d1e8'),
('ea0bcdd2-6e7e-44c9-8322-cabebf63cdcf','username','openid-connect','oidc-usermodel-attribute-mapper',NULL,'78975493-67a3-4819-a933-47b99c7c7e60'),
('ea60e20b-7a71-47ab-b0e5-dfd0d7a92296','website','openid-connect','oidc-usermodel-attribute-mapper',NULL,'0526da56-aab3-455b-9cc8-2d3d8b0457d6'),
('ec3a2029-4cd0-4fd5-a71d-8e3bbba4fc0a','fake WLCG','openid-connect','oidc-hardcoded-claim-mapper',NULL,'e58db343-7593-4ffb-8791-bf88b0675191'),
('ed0ab82f-49b2-4f62-a326-df94cbf609ce','audience resolve','openid-connect','oidc-audience-resolve-mapper',NULL,'d6da6000-2013-417d-ad33-33f0804b5b80'),
('f184a9a1-8e5b-4e00-9b53-5efb87ab1afb','locale','openid-connect','oidc-usermodel-attribute-mapper',NULL,'78975493-67a3-4819-a933-47b99c7c7e60'),
('f2e0adb0-44af-42d4-a325-b37666ef6d22','realm roles','openid-connect','oidc-usermodel-realm-role-mapper',NULL,'21ce4324-232a-46b2-b113-9407b67de017'),
('f3d922be-96e2-4760-a926-978326494242','audience resolve','openid-connect','oidc-audience-resolve-mapper',NULL,'21ce4324-232a-46b2-b113-9407b67de017'),
('f70a4ab8-f4ed-451f-ae8a-528468842e9e','gender','openid-connect','oidc-usermodel-attribute-mapper',NULL,'0526da56-aab3-455b-9cc8-2d3d8b0457d6'),
('fa2db50f-e3e6-4341-8c33-6cc65e6fba9d','acr loa level','openid-connect','oidc-acr-mapper',NULL,'4e882685-31e1-451b-9006-cd4ff0dcf750'),
('fc8db30d-e396-4276-a21b-d9cb09e4cf44','website','openid-connect','oidc-usermodel-attribute-mapper',NULL,'78975493-67a3-4819-a933-47b99c7c7e60'),
('fe24a55a-eaf1-4ce4-b38c-860e8189342d','nickname','openid-connect','oidc-usermodel-attribute-mapper',NULL,'78975493-67a3-4819-a933-47b99c7c7e60');
/*!40000 ALTER TABLE `PROTOCOL_MAPPER` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `PROTOCOL_MAPPER_CONFIG`
--

DROP TABLE IF EXISTS `PROTOCOL_MAPPER_CONFIG`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `PROTOCOL_MAPPER_CONFIG` (
  `PROTOCOL_MAPPER_ID` varchar(36) NOT NULL,
  `VALUE` longtext DEFAULT NULL,
  `NAME` varchar(255) NOT NULL,
  PRIMARY KEY (`PROTOCOL_MAPPER_ID`,`NAME`),
  CONSTRAINT `FK_PMCONFIG` FOREIGN KEY (`PROTOCOL_MAPPER_ID`) REFERENCES `PROTOCOL_MAPPER` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `PROTOCOL_MAPPER_CONFIG`
--

LOCK TABLES `PROTOCOL_MAPPER_CONFIG` WRITE;
/*!40000 ALTER TABLE `PROTOCOL_MAPPER_CONFIG` DISABLE KEYS */;
INSERT INTO `PROTOCOL_MAPPER_CONFIG` VALUES
('01608a55-6aa1-475f-be1b-4e1f029baefd','true','access.token.claim'),
('01608a55-6aa1-475f-be1b-4e1f029baefd','phone_number_verified','claim.name'),
('01608a55-6aa1-475f-be1b-4e1f029baefd','true','id.token.claim'),
('01608a55-6aa1-475f-be1b-4e1f029baefd','true','introspection.token.claim'),
('01608a55-6aa1-475f-be1b-4e1f029baefd','boolean','jsonType.label'),
('01608a55-6aa1-475f-be1b-4e1f029baefd','phoneNumberVerified','user.attribute'),
('01608a55-6aa1-475f-be1b-4e1f029baefd','true','userinfo.token.claim'),
('0c89d6e5-00f2-4623-b1d7-529b1c66a375','Role','attribute.name'),
('0c89d6e5-00f2-4623-b1d7-529b1c66a375','Basic','attribute.nameformat'),
('0c89d6e5-00f2-4623-b1d7-529b1c66a375','false','single'),
('0dbf3f93-ee43-43e4-8c68-d3385ab248d8','true','access.token.claim'),
('0dbf3f93-ee43-43e4-8c68-d3385ab248d8','true','id.token.claim'),
('0dbf3f93-ee43-43e4-8c68-d3385ab248d8','true','introspection.token.claim'),
('0dbf3f93-ee43-43e4-8c68-d3385ab248d8','country','user.attribute.country'),
('0dbf3f93-ee43-43e4-8c68-d3385ab248d8','formatted','user.attribute.formatted'),
('0dbf3f93-ee43-43e4-8c68-d3385ab248d8','locality','user.attribute.locality'),
('0dbf3f93-ee43-43e4-8c68-d3385ab248d8','postal_code','user.attribute.postal_code'),
('0dbf3f93-ee43-43e4-8c68-d3385ab248d8','region','user.attribute.region'),
('0dbf3f93-ee43-43e4-8c68-d3385ab248d8','street','user.attribute.street'),
('0dbf3f93-ee43-43e4-8c68-d3385ab248d8','true','userinfo.token.claim'),
('18a60d34-ec09-4d8a-a845-24030b74c123','true','access.token.claim'),
('18a60d34-ec09-4d8a-a845-24030b74c123','updated_at','claim.name'),
('18a60d34-ec09-4d8a-a845-24030b74c123','true','id.token.claim'),
('18a60d34-ec09-4d8a-a845-24030b74c123','true','introspection.token.claim'),
('18a60d34-ec09-4d8a-a845-24030b74c123','long','jsonType.label'),
('18a60d34-ec09-4d8a-a845-24030b74c123','updatedAt','user.attribute'),
('18a60d34-ec09-4d8a-a845-24030b74c123','true','userinfo.token.claim'),
('1daa5ef3-bb79-4d77-b06d-add8569936d9','true','access.token.claim'),
('1daa5ef3-bb79-4d77-b06d-add8569936d9','picture','claim.name'),
('1daa5ef3-bb79-4d77-b06d-add8569936d9','true','id.token.claim'),
('1daa5ef3-bb79-4d77-b06d-add8569936d9','true','introspection.token.claim'),
('1daa5ef3-bb79-4d77-b06d-add8569936d9','String','jsonType.label'),
('1daa5ef3-bb79-4d77-b06d-add8569936d9','picture','user.attribute'),
('1daa5ef3-bb79-4d77-b06d-add8569936d9','true','userinfo.token.claim'),
('22d85363-1a89-42e1-93bf-5f6840fdbe49','true','access.token.claim'),
('22d85363-1a89-42e1-93bf-5f6840fdbe49','family_name','claim.name'),
('22d85363-1a89-42e1-93bf-5f6840fdbe49','true','id.token.claim'),
('22d85363-1a89-42e1-93bf-5f6840fdbe49','true','introspection.token.claim'),
('22d85363-1a89-42e1-93bf-5f6840fdbe49','String','jsonType.label'),
('22d85363-1a89-42e1-93bf-5f6840fdbe49','lastName','user.attribute'),
('22d85363-1a89-42e1-93bf-5f6840fdbe49','true','userinfo.token.claim'),
('2e3f66cb-169f-41bd-ba65-eff34aaecece','true','access.token.claim'),
('2e3f66cb-169f-41bd-ba65-eff34aaecece','nickname','claim.name'),
('2e3f66cb-169f-41bd-ba65-eff34aaecece','true','id.token.claim'),
('2e3f66cb-169f-41bd-ba65-eff34aaecece','true','introspection.token.claim'),
('2e3f66cb-169f-41bd-ba65-eff34aaecece','String','jsonType.label'),
('2e3f66cb-169f-41bd-ba65-eff34aaecece','nickname','user.attribute'),
('2e3f66cb-169f-41bd-ba65-eff34aaecece','true','userinfo.token.claim'),
('38429562-4941-486d-8004-74fe49a6246a','true','access.token.claim'),
('38429562-4941-486d-8004-74fe49a6246a','resource_access.${client_id}.roles','claim.name'),
('38429562-4941-486d-8004-74fe49a6246a','true','introspection.token.claim'),
('38429562-4941-486d-8004-74fe49a6246a','String','jsonType.label'),
('38429562-4941-486d-8004-74fe49a6246a','true','multivalued'),
('38429562-4941-486d-8004-74fe49a6246a','foo','user.attribute'),
('3c9ddb32-0ffa-4c2e-a358-0d2a53d8c13e','true','access.token.claim'),
('3c9ddb32-0ffa-4c2e-a358-0d2a53d8c13e','family_name','claim.name'),
('3c9ddb32-0ffa-4c2e-a358-0d2a53d8c13e','true','id.token.claim'),
('3c9ddb32-0ffa-4c2e-a358-0d2a53d8c13e','true','introspection.token.claim'),
('3c9ddb32-0ffa-4c2e-a358-0d2a53d8c13e','String','jsonType.label'),
('3c9ddb32-0ffa-4c2e-a358-0d2a53d8c13e','lastName','user.attribute'),
('3c9ddb32-0ffa-4c2e-a358-0d2a53d8c13e','true','userinfo.token.claim'),
('416a5ba2-0bb4-4648-8ee9-c957b00b91a2','true','access.token.claim'),
('416a5ba2-0bb4-4648-8ee9-c957b00b91a2','false','access.tokenResponse.claim'),
('416a5ba2-0bb4-4648-8ee9-c957b00b91a2','wlcg.ver','claim.name'),
('416a5ba2-0bb4-4648-8ee9-c957b00b91a2','1.0','claim.value'),
('416a5ba2-0bb4-4648-8ee9-c957b00b91a2','true','id.token.claim'),
('416a5ba2-0bb4-4648-8ee9-c957b00b91a2','true','introspection.token.claim'),
('416a5ba2-0bb4-4648-8ee9-c957b00b91a2','String','jsonType.label'),
('416a5ba2-0bb4-4648-8ee9-c957b00b91a2','true','userinfo.token.claim'),
('470385c7-0a22-4b7b-a577-08cee38a1b1c','true','access.token.claim'),
('470385c7-0a22-4b7b-a577-08cee38a1b1c','client_id','claim.name'),
('470385c7-0a22-4b7b-a577-08cee38a1b1c','true','id.token.claim'),
('470385c7-0a22-4b7b-a577-08cee38a1b1c','true','introspection.token.claim'),
('470385c7-0a22-4b7b-a577-08cee38a1b1c','String','jsonType.label'),
('470385c7-0a22-4b7b-a577-08cee38a1b1c','client_id','user.session.note'),
('48db3c6f-dc97-44ab-81be-4ddd9897cf04','true','access.token.claim'),
('48db3c6f-dc97-44ab-81be-4ddd9897cf04','locale','claim.name'),
('48db3c6f-dc97-44ab-81be-4ddd9897cf04','true','id.token.claim'),
('48db3c6f-dc97-44ab-81be-4ddd9897cf04','true','introspection.token.claim'),
('48db3c6f-dc97-44ab-81be-4ddd9897cf04','String','jsonType.label'),
('48db3c6f-dc97-44ab-81be-4ddd9897cf04','locale','user.attribute'),
('48db3c6f-dc97-44ab-81be-4ddd9897cf04','true','userinfo.token.claim'),
('49ad759d-468b-4143-92db-4dc0f46013a0','true','access.token.claim'),
('49ad759d-468b-4143-92db-4dc0f46013a0','profile','claim.name'),
('49ad759d-468b-4143-92db-4dc0f46013a0','true','id.token.claim'),
('49ad759d-468b-4143-92db-4dc0f46013a0','true','introspection.token.claim'),
('49ad759d-468b-4143-92db-4dc0f46013a0','String','jsonType.label'),
('49ad759d-468b-4143-92db-4dc0f46013a0','profile','user.attribute'),
('49ad759d-468b-4143-92db-4dc0f46013a0','true','userinfo.token.claim'),
('56533a62-aabe-4ae9-b8e6-e38b9a6fd3c3','true','access.token.claim'),
('56533a62-aabe-4ae9-b8e6-e38b9a6fd3c3','given_name','claim.name'),
('56533a62-aabe-4ae9-b8e6-e38b9a6fd3c3','true','id.token.claim'),
('56533a62-aabe-4ae9-b8e6-e38b9a6fd3c3','true','introspection.token.claim'),
('56533a62-aabe-4ae9-b8e6-e38b9a6fd3c3','String','jsonType.label'),
('56533a62-aabe-4ae9-b8e6-e38b9a6fd3c3','firstName','user.attribute'),
('56533a62-aabe-4ae9-b8e6-e38b9a6fd3c3','true','userinfo.token.claim'),
('58e80442-f8c7-4314-bfdf-233027e87352','true','access.token.claim'),
('58e80442-f8c7-4314-bfdf-233027e87352','updated_at','claim.name'),
('58e80442-f8c7-4314-bfdf-233027e87352','true','id.token.claim'),
('58e80442-f8c7-4314-bfdf-233027e87352','true','introspection.token.claim'),
('58e80442-f8c7-4314-bfdf-233027e87352','long','jsonType.label'),
('58e80442-f8c7-4314-bfdf-233027e87352','updatedAt','user.attribute'),
('58e80442-f8c7-4314-bfdf-233027e87352','true','userinfo.token.claim'),
('5eaffc1b-395b-44f8-8b64-76e82c20947d','true','access.token.claim'),
('5eaffc1b-395b-44f8-8b64-76e82c20947d','email','claim.name'),
('5eaffc1b-395b-44f8-8b64-76e82c20947d','true','id.token.claim'),
('5eaffc1b-395b-44f8-8b64-76e82c20947d','true','introspection.token.claim'),
('5eaffc1b-395b-44f8-8b64-76e82c20947d','String','jsonType.label'),
('5eaffc1b-395b-44f8-8b64-76e82c20947d','email','user.attribute'),
('5eaffc1b-395b-44f8-8b64-76e82c20947d','true','userinfo.token.claim'),
('60d49624-fb89-42de-91de-ebb416c9fad5','true','access.token.claim'),
('60d49624-fb89-42de-91de-ebb416c9fad5','picture','claim.name'),
('60d49624-fb89-42de-91de-ebb416c9fad5','true','id.token.claim'),
('60d49624-fb89-42de-91de-ebb416c9fad5','true','introspection.token.claim'),
('60d49624-fb89-42de-91de-ebb416c9fad5','String','jsonType.label'),
('60d49624-fb89-42de-91de-ebb416c9fad5','picture','user.attribute'),
('60d49624-fb89-42de-91de-ebb416c9fad5','true','userinfo.token.claim'),
('60f0e13a-df86-40c1-83e0-946d9a7b886b','true','access.token.claim'),
('60f0e13a-df86-40c1-83e0-946d9a7b886b','phone_number','claim.name'),
('60f0e13a-df86-40c1-83e0-946d9a7b886b','true','id.token.claim'),
('60f0e13a-df86-40c1-83e0-946d9a7b886b','true','introspection.token.claim'),
('60f0e13a-df86-40c1-83e0-946d9a7b886b','String','jsonType.label'),
('60f0e13a-df86-40c1-83e0-946d9a7b886b','phoneNumber','user.attribute'),
('60f0e13a-df86-40c1-83e0-946d9a7b886b','true','userinfo.token.claim'),
('66cb7058-f6d8-4c6b-b209-7f12aa53c3a1','true','access.token.claim'),
('66cb7058-f6d8-4c6b-b209-7f12aa53c3a1','true','introspection.token.claim'),
('71e07291-04c9-434d-b074-46ec1efd64c7','true','access.token.claim'),
('71e07291-04c9-434d-b074-46ec1efd64c7','clientHost','claim.name'),
('71e07291-04c9-434d-b074-46ec1efd64c7','true','id.token.claim'),
('71e07291-04c9-434d-b074-46ec1efd64c7','true','introspection.token.claim'),
('71e07291-04c9-434d-b074-46ec1efd64c7','String','jsonType.label'),
('71e07291-04c9-434d-b074-46ec1efd64c7','clientHost','user.session.note'),
('769ed209-c1b1-43ab-9b22-61a86a90320a','true','access.token.claim'),
('769ed209-c1b1-43ab-9b22-61a86a90320a','locale','claim.name'),
('769ed209-c1b1-43ab-9b22-61a86a90320a','true','id.token.claim'),
('769ed209-c1b1-43ab-9b22-61a86a90320a','true','introspection.token.claim'),
('769ed209-c1b1-43ab-9b22-61a86a90320a','String','jsonType.label'),
('769ed209-c1b1-43ab-9b22-61a86a90320a','locale','user.attribute'),
('769ed209-c1b1-43ab-9b22-61a86a90320a','true','userinfo.token.claim'),
('783b43e8-4cc2-42c6-a088-8a4843808d77','true','access.token.claim'),
('783b43e8-4cc2-42c6-a088-8a4843808d77','upn','claim.name'),
('783b43e8-4cc2-42c6-a088-8a4843808d77','true','id.token.claim'),
('783b43e8-4cc2-42c6-a088-8a4843808d77','true','introspection.token.claim'),
('783b43e8-4cc2-42c6-a088-8a4843808d77','String','jsonType.label'),
('783b43e8-4cc2-42c6-a088-8a4843808d77','username','user.attribute'),
('783b43e8-4cc2-42c6-a088-8a4843808d77','true','userinfo.token.claim'),
('78d1bef3-0c11-455f-8267-ec0a034c6d83','true','access.token.claim'),
('78d1bef3-0c11-455f-8267-ec0a034c6d83','profile','claim.name'),
('78d1bef3-0c11-455f-8267-ec0a034c6d83','true','id.token.claim'),
('78d1bef3-0c11-455f-8267-ec0a034c6d83','true','introspection.token.claim'),
('78d1bef3-0c11-455f-8267-ec0a034c6d83','String','jsonType.label'),
('78d1bef3-0c11-455f-8267-ec0a034c6d83','profile','user.attribute'),
('78d1bef3-0c11-455f-8267-ec0a034c6d83','true','userinfo.token.claim'),
('7a10a289-352f-46b7-9b70-f1c66213876a','true','access.token.claim'),
('7a10a289-352f-46b7-9b70-f1c66213876a','birthdate','claim.name'),
('7a10a289-352f-46b7-9b70-f1c66213876a','true','id.token.claim'),
('7a10a289-352f-46b7-9b70-f1c66213876a','true','introspection.token.claim'),
('7a10a289-352f-46b7-9b70-f1c66213876a','String','jsonType.label'),
('7a10a289-352f-46b7-9b70-f1c66213876a','birthdate','user.attribute'),
('7a10a289-352f-46b7-9b70-f1c66213876a','true','userinfo.token.claim'),
('830ba79a-d2e0-4681-b5f4-cfdbd93fe96c','true','access.token.claim'),
('830ba79a-d2e0-4681-b5f4-cfdbd93fe96c','birthdate','claim.name'),
('830ba79a-d2e0-4681-b5f4-cfdbd93fe96c','true','id.token.claim'),
('830ba79a-d2e0-4681-b5f4-cfdbd93fe96c','true','introspection.token.claim'),
('830ba79a-d2e0-4681-b5f4-cfdbd93fe96c','String','jsonType.label'),
('830ba79a-d2e0-4681-b5f4-cfdbd93fe96c','birthdate','user.attribute'),
('830ba79a-d2e0-4681-b5f4-cfdbd93fe96c','true','userinfo.token.claim'),
('84f39479-8dc5-4d83-8610-c4235297230d','true','access.token.claim'),
('84f39479-8dc5-4d83-8610-c4235297230d','locale','claim.name'),
('84f39479-8dc5-4d83-8610-c4235297230d','true','id.token.claim'),
('84f39479-8dc5-4d83-8610-c4235297230d','true','introspection.token.claim'),
('84f39479-8dc5-4d83-8610-c4235297230d','String','jsonType.label'),
('84f39479-8dc5-4d83-8610-c4235297230d','locale','user.attribute'),
('84f39479-8dc5-4d83-8610-c4235297230d','true','userinfo.token.claim'),
('85e51600-dc92-474a-ad36-8844b4387adf','true','access.token.claim'),
('85e51600-dc92-474a-ad36-8844b4387adf','gender','claim.name'),
('85e51600-dc92-474a-ad36-8844b4387adf','true','id.token.claim'),
('85e51600-dc92-474a-ad36-8844b4387adf','true','introspection.token.claim'),
('85e51600-dc92-474a-ad36-8844b4387adf','String','jsonType.label'),
('85e51600-dc92-474a-ad36-8844b4387adf','gender','user.attribute'),
('85e51600-dc92-474a-ad36-8844b4387adf','true','userinfo.token.claim'),
('865e5a79-a1c3-41c2-b065-0eaa3e49df0d','true','access.token.claim'),
('865e5a79-a1c3-41c2-b065-0eaa3e49df0d','zoneinfo','claim.name'),
('865e5a79-a1c3-41c2-b065-0eaa3e49df0d','true','id.token.claim'),
('865e5a79-a1c3-41c2-b065-0eaa3e49df0d','true','introspection.token.claim'),
('865e5a79-a1c3-41c2-b065-0eaa3e49df0d','String','jsonType.label'),
('865e5a79-a1c3-41c2-b065-0eaa3e49df0d','zoneinfo','user.attribute'),
('865e5a79-a1c3-41c2-b065-0eaa3e49df0d','true','userinfo.token.claim'),
('8bb1286e-e063-4050-9e8f-965c41819b03','true','access.token.claim'),
('8bb1286e-e063-4050-9e8f-965c41819b03','email','claim.name'),
('8bb1286e-e063-4050-9e8f-965c41819b03','true','id.token.claim'),
('8bb1286e-e063-4050-9e8f-965c41819b03','true','introspection.token.claim'),
('8bb1286e-e063-4050-9e8f-965c41819b03','String','jsonType.label'),
('8bb1286e-e063-4050-9e8f-965c41819b03','email','user.attribute'),
('8bb1286e-e063-4050-9e8f-965c41819b03','true','userinfo.token.claim'),
('8c1d0e40-ce2d-4261-b70e-e88e361a8913','true','access.token.claim'),
('8c1d0e40-ce2d-4261-b70e-e88e361a8913','preferred_username','claim.name'),
('8c1d0e40-ce2d-4261-b70e-e88e361a8913','true','id.token.claim'),
('8c1d0e40-ce2d-4261-b70e-e88e361a8913','true','introspection.token.claim'),
('8c1d0e40-ce2d-4261-b70e-e88e361a8913','String','jsonType.label'),
('8c1d0e40-ce2d-4261-b70e-e88e361a8913','username','user.attribute'),
('8c1d0e40-ce2d-4261-b70e-e88e361a8913','true','userinfo.token.claim'),
('8faf27d9-7a46-42a0-9995-a474a476cfe1','true','access.token.claim'),
('8faf27d9-7a46-42a0-9995-a474a476cfe1','groups','claim.name'),
('8faf27d9-7a46-42a0-9995-a474a476cfe1','true','id.token.claim'),
('8faf27d9-7a46-42a0-9995-a474a476cfe1','true','introspection.token.claim'),
('8faf27d9-7a46-42a0-9995-a474a476cfe1','String','jsonType.label'),
('8faf27d9-7a46-42a0-9995-a474a476cfe1','true','multivalued'),
('8faf27d9-7a46-42a0-9995-a474a476cfe1','foo','user.attribute'),
('92bad947-1587-4810-98fa-15ecf6f84771','true','access.token.claim'),
('92bad947-1587-4810-98fa-15ecf6f84771','upn','claim.name'),
('92bad947-1587-4810-98fa-15ecf6f84771','true','id.token.claim'),
('92bad947-1587-4810-98fa-15ecf6f84771','true','introspection.token.claim'),
('92bad947-1587-4810-98fa-15ecf6f84771','String','jsonType.label'),
('92bad947-1587-4810-98fa-15ecf6f84771','username','user.attribute'),
('92bad947-1587-4810-98fa-15ecf6f84771','true','userinfo.token.claim'),
('9c9a48cc-0746-45bc-8609-4650a7e656b6','true','access.token.claim'),
('9c9a48cc-0746-45bc-8609-4650a7e656b6','given_name','claim.name'),
('9c9a48cc-0746-45bc-8609-4650a7e656b6','true','id.token.claim'),
('9c9a48cc-0746-45bc-8609-4650a7e656b6','true','introspection.token.claim'),
('9c9a48cc-0746-45bc-8609-4650a7e656b6','String','jsonType.label'),
('9c9a48cc-0746-45bc-8609-4650a7e656b6','firstName','user.attribute'),
('9c9a48cc-0746-45bc-8609-4650a7e656b6','true','userinfo.token.claim'),
('9f7e6fd4-a29f-428a-b3a6-bad7d1ef9b37','true','access.token.claim'),
('9f7e6fd4-a29f-428a-b3a6-bad7d1ef9b37','phone_number_verified','claim.name'),
('9f7e6fd4-a29f-428a-b3a6-bad7d1ef9b37','true','id.token.claim'),
('9f7e6fd4-a29f-428a-b3a6-bad7d1ef9b37','true','introspection.token.claim'),
('9f7e6fd4-a29f-428a-b3a6-bad7d1ef9b37','boolean','jsonType.label'),
('9f7e6fd4-a29f-428a-b3a6-bad7d1ef9b37','phoneNumberVerified','user.attribute'),
('9f7e6fd4-a29f-428a-b3a6-bad7d1ef9b37','true','userinfo.token.claim'),
('9f912bc4-e8af-4908-9d79-f0f536325310','true','access.token.claim'),
('9f912bc4-e8af-4908-9d79-f0f536325310','phone_number','claim.name'),
('9f912bc4-e8af-4908-9d79-f0f536325310','true','id.token.claim'),
('9f912bc4-e8af-4908-9d79-f0f536325310','true','introspection.token.claim'),
('9f912bc4-e8af-4908-9d79-f0f536325310','String','jsonType.label'),
('9f912bc4-e8af-4908-9d79-f0f536325310','phoneNumber','user.attribute'),
('9f912bc4-e8af-4908-9d79-f0f536325310','true','userinfo.token.claim'),
('a04e74fc-2155-4b1f-afab-e01efd93bc45','true','access.token.claim'),
('a04e74fc-2155-4b1f-afab-e01efd93bc45','middle_name','claim.name'),
('a04e74fc-2155-4b1f-afab-e01efd93bc45','true','id.token.claim'),
('a04e74fc-2155-4b1f-afab-e01efd93bc45','true','introspection.token.claim'),
('a04e74fc-2155-4b1f-afab-e01efd93bc45','String','jsonType.label'),
('a04e74fc-2155-4b1f-afab-e01efd93bc45','middleName','user.attribute'),
('a04e74fc-2155-4b1f-afab-e01efd93bc45','true','userinfo.token.claim'),
('a4a85ba9-400a-4c7c-8a8b-d7f77958dfe0','true','access.token.claim'),
('a4a85ba9-400a-4c7c-8a8b-d7f77958dfe0','true','id.token.claim'),
('a4a85ba9-400a-4c7c-8a8b-d7f77958dfe0','true','introspection.token.claim'),
('a4a85ba9-400a-4c7c-8a8b-d7f77958dfe0','true','userinfo.token.claim'),
('a9f06dc0-6493-4843-94b9-a30d2301e0dd','true','access.token.claim'),
('a9f06dc0-6493-4843-94b9-a30d2301e0dd','zoneinfo','claim.name'),
('a9f06dc0-6493-4843-94b9-a30d2301e0dd','true','id.token.claim'),
('a9f06dc0-6493-4843-94b9-a30d2301e0dd','true','introspection.token.claim'),
('a9f06dc0-6493-4843-94b9-a30d2301e0dd','String','jsonType.label'),
('a9f06dc0-6493-4843-94b9-a30d2301e0dd','zoneinfo','user.attribute'),
('a9f06dc0-6493-4843-94b9-a30d2301e0dd','true','userinfo.token.claim'),
('b02135db-6b29-4d73-9e19-4ab35d0c21aa','true','access.token.claim'),
('b02135db-6b29-4d73-9e19-4ab35d0c21aa','true','id.token.claim'),
('b02135db-6b29-4d73-9e19-4ab35d0c21aa','true','introspection.token.claim'),
('b02135db-6b29-4d73-9e19-4ab35d0c21aa','true','userinfo.token.claim'),
('b5a9a8d1-c6ce-458b-ad1f-66f4576979d1','true','access.token.claim'),
('b5a9a8d1-c6ce-458b-ad1f-66f4576979d1','true','id.token.claim'),
('b5a9a8d1-c6ce-458b-ad1f-66f4576979d1','true','introspection.token.claim'),
('b5a9a8d1-c6ce-458b-ad1f-66f4576979d1','country','user.attribute.country'),
('b5a9a8d1-c6ce-458b-ad1f-66f4576979d1','formatted','user.attribute.formatted'),
('b5a9a8d1-c6ce-458b-ad1f-66f4576979d1','locality','user.attribute.locality'),
('b5a9a8d1-c6ce-458b-ad1f-66f4576979d1','postal_code','user.attribute.postal_code'),
('b5a9a8d1-c6ce-458b-ad1f-66f4576979d1','region','user.attribute.region'),
('b5a9a8d1-c6ce-458b-ad1f-66f4576979d1','street','user.attribute.street'),
('b5a9a8d1-c6ce-458b-ad1f-66f4576979d1','true','userinfo.token.claim'),
('b86d89b9-4914-4a9a-93c3-8aac4f1e0716','true','access.token.claim'),
('b86d89b9-4914-4a9a-93c3-8aac4f1e0716','true','id.token.claim'),
('b86d89b9-4914-4a9a-93c3-8aac4f1e0716','true','introspection.token.claim'),
('bfaabf99-700b-4960-b732-b89db862c423','true','access.token.claim'),
('bfaabf99-700b-4960-b732-b89db862c423','realm_access.roles','claim.name'),
('bfaabf99-700b-4960-b732-b89db862c423','true','introspection.token.claim'),
('bfaabf99-700b-4960-b732-b89db862c423','String','jsonType.label'),
('bfaabf99-700b-4960-b732-b89db862c423','true','multivalued'),
('bfaabf99-700b-4960-b732-b89db862c423','foo','user.attribute'),
('c072bc17-d43f-40e3-9f09-00d3e11aec63','true','access.token.claim'),
('c072bc17-d43f-40e3-9f09-00d3e11aec63','email_verified','claim.name'),
('c072bc17-d43f-40e3-9f09-00d3e11aec63','true','id.token.claim'),
('c072bc17-d43f-40e3-9f09-00d3e11aec63','true','introspection.token.claim'),
('c072bc17-d43f-40e3-9f09-00d3e11aec63','boolean','jsonType.label'),
('c072bc17-d43f-40e3-9f09-00d3e11aec63','emailVerified','user.attribute'),
('c072bc17-d43f-40e3-9f09-00d3e11aec63','true','userinfo.token.claim'),
('d39b4063-b5ed-475e-a88d-d6f0b0ebdf6b','true','access.token.claim'),
('d39b4063-b5ed-475e-a88d-d6f0b0ebdf6b','email_verified','claim.name'),
('d39b4063-b5ed-475e-a88d-d6f0b0ebdf6b','true','id.token.claim'),
('d39b4063-b5ed-475e-a88d-d6f0b0ebdf6b','true','introspection.token.claim'),
('d39b4063-b5ed-475e-a88d-d6f0b0ebdf6b','boolean','jsonType.label'),
('d39b4063-b5ed-475e-a88d-d6f0b0ebdf6b','emailVerified','user.attribute'),
('d39b4063-b5ed-475e-a88d-d6f0b0ebdf6b','true','userinfo.token.claim'),
('d45fc134-3030-4aff-b162-c7b139cc94f3','true','access.token.claim'),
('d45fc134-3030-4aff-b162-c7b139cc94f3','resource_access.${client_id}.roles','claim.name'),
('d45fc134-3030-4aff-b162-c7b139cc94f3','true','introspection.token.claim'),
('d45fc134-3030-4aff-b162-c7b139cc94f3','String','jsonType.label'),
('d45fc134-3030-4aff-b162-c7b139cc94f3','true','multivalued'),
('d45fc134-3030-4aff-b162-c7b139cc94f3','foo','user.attribute'),
('d9ad77a8-6411-437b-9aaf-c4f92b8a1b2d','Role','attribute.name'),
('d9ad77a8-6411-437b-9aaf-c4f92b8a1b2d','Basic','attribute.nameformat'),
('d9ad77a8-6411-437b-9aaf-c4f92b8a1b2d','false','single'),
('d9c98c62-6649-4f94-8ed4-db3634e5326a','true','access.token.claim'),
('d9c98c62-6649-4f94-8ed4-db3634e5326a','clientAddress','claim.name'),
('d9c98c62-6649-4f94-8ed4-db3634e5326a','true','id.token.claim'),
('d9c98c62-6649-4f94-8ed4-db3634e5326a','true','introspection.token.claim'),
('d9c98c62-6649-4f94-8ed4-db3634e5326a','String','jsonType.label'),
('d9c98c62-6649-4f94-8ed4-db3634e5326a','clientAddress','user.session.note'),
('db5ce96a-8bca-4ac2-9f9f-d942c1c1476a','true','access.token.claim'),
('db5ce96a-8bca-4ac2-9f9f-d942c1c1476a','middle_name','claim.name'),
('db5ce96a-8bca-4ac2-9f9f-d942c1c1476a','true','id.token.claim'),
('db5ce96a-8bca-4ac2-9f9f-d942c1c1476a','true','introspection.token.claim'),
('db5ce96a-8bca-4ac2-9f9f-d942c1c1476a','String','jsonType.label'),
('db5ce96a-8bca-4ac2-9f9f-d942c1c1476a','middleName','user.attribute'),
('db5ce96a-8bca-4ac2-9f9f-d942c1c1476a','true','userinfo.token.claim'),
('e191d9df-7c0e-45d0-9648-5ef6016c84d1','true','access.token.claim'),
('e191d9df-7c0e-45d0-9648-5ef6016c84d1','true','introspection.token.claim'),
('e82117a5-b0ee-47da-8142-3f3e8c124efb','true','access.token.claim'),
('e82117a5-b0ee-47da-8142-3f3e8c124efb','groups','claim.name'),
('e82117a5-b0ee-47da-8142-3f3e8c124efb','true','id.token.claim'),
('e82117a5-b0ee-47da-8142-3f3e8c124efb','true','introspection.token.claim'),
('e82117a5-b0ee-47da-8142-3f3e8c124efb','String','jsonType.label'),
('e82117a5-b0ee-47da-8142-3f3e8c124efb','true','multivalued'),
('e82117a5-b0ee-47da-8142-3f3e8c124efb','foo','user.attribute'),
('ea0bcdd2-6e7e-44c9-8322-cabebf63cdcf','true','access.token.claim'),
('ea0bcdd2-6e7e-44c9-8322-cabebf63cdcf','preferred_username','claim.name'),
('ea0bcdd2-6e7e-44c9-8322-cabebf63cdcf','true','id.token.claim'),
('ea0bcdd2-6e7e-44c9-8322-cabebf63cdcf','true','introspection.token.claim'),
('ea0bcdd2-6e7e-44c9-8322-cabebf63cdcf','String','jsonType.label'),
('ea0bcdd2-6e7e-44c9-8322-cabebf63cdcf','username','user.attribute'),
('ea0bcdd2-6e7e-44c9-8322-cabebf63cdcf','true','userinfo.token.claim'),
('ea60e20b-7a71-47ab-b0e5-dfd0d7a92296','true','access.token.claim'),
('ea60e20b-7a71-47ab-b0e5-dfd0d7a92296','website','claim.name'),
('ea60e20b-7a71-47ab-b0e5-dfd0d7a92296','true','id.token.claim'),
('ea60e20b-7a71-47ab-b0e5-dfd0d7a92296','true','introspection.token.claim'),
('ea60e20b-7a71-47ab-b0e5-dfd0d7a92296','String','jsonType.label'),
('ea60e20b-7a71-47ab-b0e5-dfd0d7a92296','website','user.attribute'),
('ea60e20b-7a71-47ab-b0e5-dfd0d7a92296','true','userinfo.token.claim'),
('ec3a2029-4cd0-4fd5-a71d-8e3bbba4fc0a','true','access.token.claim'),
('ec3a2029-4cd0-4fd5-a71d-8e3bbba4fc0a','false','access.tokenResponse.claim'),
('ec3a2029-4cd0-4fd5-a71d-8e3bbba4fc0a','wlcg\\.ver','claim.name'),
('ec3a2029-4cd0-4fd5-a71d-8e3bbba4fc0a','1.0','claim.value'),
('ec3a2029-4cd0-4fd5-a71d-8e3bbba4fc0a','true','id.token.claim'),
('ec3a2029-4cd0-4fd5-a71d-8e3bbba4fc0a','true','introspection.token.claim'),
('ec3a2029-4cd0-4fd5-a71d-8e3bbba4fc0a','String','jsonType.label'),
('ec3a2029-4cd0-4fd5-a71d-8e3bbba4fc0a','true','userinfo.token.claim'),
('ed0ab82f-49b2-4f62-a326-df94cbf609ce','true','access.token.claim'),
('ed0ab82f-49b2-4f62-a326-df94cbf609ce','true','introspection.token.claim'),
('f184a9a1-8e5b-4e00-9b53-5efb87ab1afb','true','access.token.claim'),
('f184a9a1-8e5b-4e00-9b53-5efb87ab1afb','locale','claim.name'),
('f184a9a1-8e5b-4e00-9b53-5efb87ab1afb','true','id.token.claim'),
('f184a9a1-8e5b-4e00-9b53-5efb87ab1afb','true','introspection.token.claim'),
('f184a9a1-8e5b-4e00-9b53-5efb87ab1afb','String','jsonType.label'),
('f184a9a1-8e5b-4e00-9b53-5efb87ab1afb','locale','user.attribute'),
('f184a9a1-8e5b-4e00-9b53-5efb87ab1afb','true','userinfo.token.claim'),
('f2e0adb0-44af-42d4-a325-b37666ef6d22','true','access.token.claim'),
('f2e0adb0-44af-42d4-a325-b37666ef6d22','realm_access.roles','claim.name'),
('f2e0adb0-44af-42d4-a325-b37666ef6d22','true','introspection.token.claim'),
('f2e0adb0-44af-42d4-a325-b37666ef6d22','String','jsonType.label'),
('f2e0adb0-44af-42d4-a325-b37666ef6d22','true','multivalued'),
('f2e0adb0-44af-42d4-a325-b37666ef6d22','foo','user.attribute'),
('f3d922be-96e2-4760-a926-978326494242','true','access.token.claim'),
('f3d922be-96e2-4760-a926-978326494242','true','introspection.token.claim'),
('f70a4ab8-f4ed-451f-ae8a-528468842e9e','true','access.token.claim'),
('f70a4ab8-f4ed-451f-ae8a-528468842e9e','gender','claim.name'),
('f70a4ab8-f4ed-451f-ae8a-528468842e9e','true','id.token.claim'),
('f70a4ab8-f4ed-451f-ae8a-528468842e9e','true','introspection.token.claim'),
('f70a4ab8-f4ed-451f-ae8a-528468842e9e','String','jsonType.label'),
('f70a4ab8-f4ed-451f-ae8a-528468842e9e','gender','user.attribute'),
('f70a4ab8-f4ed-451f-ae8a-528468842e9e','true','userinfo.token.claim'),
('fa2db50f-e3e6-4341-8c33-6cc65e6fba9d','true','access.token.claim'),
('fa2db50f-e3e6-4341-8c33-6cc65e6fba9d','true','id.token.claim'),
('fa2db50f-e3e6-4341-8c33-6cc65e6fba9d','true','introspection.token.claim'),
('fc8db30d-e396-4276-a21b-d9cb09e4cf44','true','access.token.claim'),
('fc8db30d-e396-4276-a21b-d9cb09e4cf44','website','claim.name'),
('fc8db30d-e396-4276-a21b-d9cb09e4cf44','true','id.token.claim'),
('fc8db30d-e396-4276-a21b-d9cb09e4cf44','true','introspection.token.claim'),
('fc8db30d-e396-4276-a21b-d9cb09e4cf44','String','jsonType.label'),
('fc8db30d-e396-4276-a21b-d9cb09e4cf44','website','user.attribute'),
('fc8db30d-e396-4276-a21b-d9cb09e4cf44','true','userinfo.token.claim'),
('fe24a55a-eaf1-4ce4-b38c-860e8189342d','true','access.token.claim'),
('fe24a55a-eaf1-4ce4-b38c-860e8189342d','nickname','claim.name'),
('fe24a55a-eaf1-4ce4-b38c-860e8189342d','true','id.token.claim'),
('fe24a55a-eaf1-4ce4-b38c-860e8189342d','true','introspection.token.claim'),
('fe24a55a-eaf1-4ce4-b38c-860e8189342d','String','jsonType.label'),
('fe24a55a-eaf1-4ce4-b38c-860e8189342d','nickname','user.attribute'),
('fe24a55a-eaf1-4ce4-b38c-860e8189342d','true','userinfo.token.claim');
/*!40000 ALTER TABLE `PROTOCOL_MAPPER_CONFIG` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `REALM`
--

DROP TABLE IF EXISTS `REALM`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `REALM` (
  `ID` varchar(36) NOT NULL,
  `ACCESS_CODE_LIFESPAN` int(11) DEFAULT NULL,
  `USER_ACTION_LIFESPAN` int(11) DEFAULT NULL,
  `ACCESS_TOKEN_LIFESPAN` int(11) DEFAULT NULL,
  `ACCOUNT_THEME` varchar(255) DEFAULT NULL,
  `ADMIN_THEME` varchar(255) DEFAULT NULL,
  `EMAIL_THEME` varchar(255) DEFAULT NULL,
  `ENABLED` bit(1) NOT NULL DEFAULT b'0',
  `EVENTS_ENABLED` bit(1) NOT NULL DEFAULT b'0',
  `EVENTS_EXPIRATION` bigint(20) DEFAULT NULL,
  `LOGIN_THEME` varchar(255) DEFAULT NULL,
  `NAME` varchar(255) DEFAULT NULL,
  `NOT_BEFORE` int(11) DEFAULT NULL,
  `PASSWORD_POLICY` text DEFAULT NULL,
  `REGISTRATION_ALLOWED` bit(1) NOT NULL DEFAULT b'0',
  `REMEMBER_ME` bit(1) NOT NULL DEFAULT b'0',
  `RESET_PASSWORD_ALLOWED` bit(1) NOT NULL DEFAULT b'0',
  `SOCIAL` bit(1) NOT NULL DEFAULT b'0',
  `SSL_REQUIRED` varchar(255) DEFAULT NULL,
  `SSO_IDLE_TIMEOUT` int(11) DEFAULT NULL,
  `SSO_MAX_LIFESPAN` int(11) DEFAULT NULL,
  `UPDATE_PROFILE_ON_SOC_LOGIN` bit(1) NOT NULL DEFAULT b'0',
  `VERIFY_EMAIL` bit(1) NOT NULL DEFAULT b'0',
  `MASTER_ADMIN_CLIENT` varchar(36) DEFAULT NULL,
  `LOGIN_LIFESPAN` int(11) DEFAULT NULL,
  `INTERNATIONALIZATION_ENABLED` bit(1) NOT NULL DEFAULT b'0',
  `DEFAULT_LOCALE` varchar(255) DEFAULT NULL,
  `REG_EMAIL_AS_USERNAME` bit(1) NOT NULL DEFAULT b'0',
  `ADMIN_EVENTS_ENABLED` bit(1) NOT NULL DEFAULT b'0',
  `ADMIN_EVENTS_DETAILS_ENABLED` bit(1) NOT NULL DEFAULT b'0',
  `EDIT_USERNAME_ALLOWED` bit(1) NOT NULL DEFAULT b'0',
  `OTP_POLICY_COUNTER` int(11) DEFAULT 0,
  `OTP_POLICY_WINDOW` int(11) DEFAULT 1,
  `OTP_POLICY_PERIOD` int(11) DEFAULT 30,
  `OTP_POLICY_DIGITS` int(11) DEFAULT 6,
  `OTP_POLICY_ALG` varchar(36) DEFAULT 'HmacSHA1',
  `OTP_POLICY_TYPE` varchar(36) DEFAULT 'totp',
  `BROWSER_FLOW` varchar(36) DEFAULT NULL,
  `REGISTRATION_FLOW` varchar(36) DEFAULT NULL,
  `DIRECT_GRANT_FLOW` varchar(36) DEFAULT NULL,
  `RESET_CREDENTIALS_FLOW` varchar(36) DEFAULT NULL,
  `CLIENT_AUTH_FLOW` varchar(36) DEFAULT NULL,
  `OFFLINE_SESSION_IDLE_TIMEOUT` int(11) DEFAULT 0,
  `REVOKE_REFRESH_TOKEN` bit(1) NOT NULL DEFAULT b'0',
  `ACCESS_TOKEN_LIFE_IMPLICIT` int(11) DEFAULT 0,
  `LOGIN_WITH_EMAIL_ALLOWED` bit(1) NOT NULL DEFAULT b'1',
  `DUPLICATE_EMAILS_ALLOWED` bit(1) NOT NULL DEFAULT b'0',
  `DOCKER_AUTH_FLOW` varchar(36) DEFAULT NULL,
  `REFRESH_TOKEN_MAX_REUSE` int(11) DEFAULT 0,
  `ALLOW_USER_MANAGED_ACCESS` bit(1) NOT NULL DEFAULT b'0',
  `SSO_MAX_LIFESPAN_REMEMBER_ME` int(11) NOT NULL,
  `SSO_IDLE_TIMEOUT_REMEMBER_ME` int(11) NOT NULL,
  `DEFAULT_ROLE` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK_ORVSDMLA56612EAEFIQ6WL5OI` (`NAME`),
  KEY `IDX_REALM_MASTER_ADM_CLI` (`MASTER_ADMIN_CLIENT`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `REALM`
--

LOCK TABLES `REALM` WRITE;
/*!40000 ALTER TABLE `REALM` DISABLE KEYS */;
INSERT INTO `REALM` VALUES
('139c1488-d000-4061-922b-0c0b518a57db',60,300,300,NULL,NULL,NULL,'','\0',0,NULL,'ruciodev',0,NULL,'\0','\0','\0','\0','EXTERNAL',1800,36000,'\0','\0','e7416090-7f37-401b-b69f-a10a8f8a9a46',1800,'\0',NULL,'\0','\0','\0','\0',0,1,30,6,'HmacSHA1','totp','718da82c-570c-4044-8835-40c9a3d7944b','6b278f0f-5511-4a01-8a0a-81d3d147f82e','431dba76-8573-4297-9670-157d884d265f','dc3df143-d1cf-4cba-93c9-f778e9bbb79e','a729e6a9-8b5a-4cdb-96bf-7589c8ea0c8a',2592000,'\0',900,'','\0','f0fe1ce7-0d8b-4ada-9b52-8aa9d2bb8ac1',0,'\0',0,0,'714a6f1e-de37-4768-b6c5-f4792079b510'),
('61c254e2-095d-42b9-b8cc-4546b124e548',60,300,60,NULL,NULL,NULL,'','\0',0,NULL,'master',0,NULL,'\0','\0','\0','\0','EXTERNAL',1800,36000,'\0','\0','6fcc4ef0-a82c-453e-90ba-0753d2c11c58',1800,'\0',NULL,'\0','\0','\0','\0',0,1,30,6,'HmacSHA1','totp','dca5d32d-86b8-4c98-94a5-bb9fce71cc89','41657800-8217-4ac6-af7e-54023e60b888','b43e9e5d-af68-4aa0-8e7a-14fc5755734d','cb65b4c2-ea74-478a-b3bc-e58fa769e356','ea03a723-575b-423a-8993-ee0232e25692',2592000,'\0',900,'','\0','e4fc2888-0400-4daa-a358-70a22443dbda',0,'\0',0,0,'df76e680-bebc-4b85-a723-c5adf7ef86c6');
/*!40000 ALTER TABLE `REALM` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `REALM_ATTRIBUTE`
--

DROP TABLE IF EXISTS `REALM_ATTRIBUTE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `REALM_ATTRIBUTE` (
  `NAME` varchar(255) NOT NULL,
  `REALM_ID` varchar(36) NOT NULL,
  `VALUE` longtext CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  PRIMARY KEY (`NAME`,`REALM_ID`),
  KEY `IDX_REALM_ATTR_REALM` (`REALM_ID`),
  CONSTRAINT `FK_8SHXD6L3E9ATQUKACXGPFFPTW` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `REALM_ATTRIBUTE`
--

LOCK TABLES `REALM_ATTRIBUTE` WRITE;
/*!40000 ALTER TABLE `REALM_ATTRIBUTE` DISABLE KEYS */;
INSERT INTO `REALM_ATTRIBUTE` VALUES
('actionTokenGeneratedByAdminLifespan','139c1488-d000-4061-922b-0c0b518a57db','43200'),
('actionTokenGeneratedByUserLifespan','139c1488-d000-4061-922b-0c0b518a57db','300'),
('bruteForceProtected','139c1488-d000-4061-922b-0c0b518a57db','false'),
('bruteForceProtected','61c254e2-095d-42b9-b8cc-4546b124e548','false'),
('cibaAuthRequestedUserHint','139c1488-d000-4061-922b-0c0b518a57db','login_hint'),
('cibaBackchannelTokenDeliveryMode','139c1488-d000-4061-922b-0c0b518a57db','poll'),
('cibaExpiresIn','139c1488-d000-4061-922b-0c0b518a57db','120'),
('cibaInterval','139c1488-d000-4061-922b-0c0b518a57db','5'),
('defaultSignatureAlgorithm','139c1488-d000-4061-922b-0c0b518a57db','RS256'),
('defaultSignatureAlgorithm','61c254e2-095d-42b9-b8cc-4546b124e548','RS256'),
('displayName','61c254e2-095d-42b9-b8cc-4546b124e548','Keycloak'),
('displayNameHtml','61c254e2-095d-42b9-b8cc-4546b124e548','<div class=\"kc-logo-text\"><span>Keycloak</span></div>'),
('failureFactor','139c1488-d000-4061-922b-0c0b518a57db','30'),
('failureFactor','61c254e2-095d-42b9-b8cc-4546b124e548','30'),
('maxDeltaTimeSeconds','139c1488-d000-4061-922b-0c0b518a57db','43200'),
('maxDeltaTimeSeconds','61c254e2-095d-42b9-b8cc-4546b124e548','43200'),
('maxFailureWaitSeconds','139c1488-d000-4061-922b-0c0b518a57db','900'),
('maxFailureWaitSeconds','61c254e2-095d-42b9-b8cc-4546b124e548','900'),
('minimumQuickLoginWaitSeconds','139c1488-d000-4061-922b-0c0b518a57db','60'),
('minimumQuickLoginWaitSeconds','61c254e2-095d-42b9-b8cc-4546b124e548','60'),
('oauth2DeviceCodeLifespan','139c1488-d000-4061-922b-0c0b518a57db','600'),
('oauth2DevicePollingInterval','139c1488-d000-4061-922b-0c0b518a57db','5'),
('offlineSessionMaxLifespan','139c1488-d000-4061-922b-0c0b518a57db','5184000'),
('offlineSessionMaxLifespan','61c254e2-095d-42b9-b8cc-4546b124e548','5184000'),
('offlineSessionMaxLifespanEnabled','139c1488-d000-4061-922b-0c0b518a57db','false'),
('offlineSessionMaxLifespanEnabled','61c254e2-095d-42b9-b8cc-4546b124e548','false'),
('parRequestUriLifespan','139c1488-d000-4061-922b-0c0b518a57db','60'),
('permanentLockout','139c1488-d000-4061-922b-0c0b518a57db','false'),
('permanentLockout','61c254e2-095d-42b9-b8cc-4546b124e548','false'),
('quickLoginCheckMilliSeconds','139c1488-d000-4061-922b-0c0b518a57db','1000'),
('quickLoginCheckMilliSeconds','61c254e2-095d-42b9-b8cc-4546b124e548','1000'),
('realmReusableOtpCode','139c1488-d000-4061-922b-0c0b518a57db','false'),
('realmReusableOtpCode','61c254e2-095d-42b9-b8cc-4546b124e548','false'),
('waitIncrementSeconds','139c1488-d000-4061-922b-0c0b518a57db','60'),
('waitIncrementSeconds','61c254e2-095d-42b9-b8cc-4546b124e548','60'),
('webAuthnPolicyAttestationConveyancePreference','139c1488-d000-4061-922b-0c0b518a57db','not specified'),
('webAuthnPolicyAttestationConveyancePreferencePasswordless','139c1488-d000-4061-922b-0c0b518a57db','not specified'),
('webAuthnPolicyAuthenticatorAttachment','139c1488-d000-4061-922b-0c0b518a57db','not specified'),
('webAuthnPolicyAuthenticatorAttachmentPasswordless','139c1488-d000-4061-922b-0c0b518a57db','not specified'),
('webAuthnPolicyAvoidSameAuthenticatorRegister','139c1488-d000-4061-922b-0c0b518a57db','false'),
('webAuthnPolicyAvoidSameAuthenticatorRegisterPasswordless','139c1488-d000-4061-922b-0c0b518a57db','false'),
('webAuthnPolicyCreateTimeout','139c1488-d000-4061-922b-0c0b518a57db','0'),
('webAuthnPolicyCreateTimeoutPasswordless','139c1488-d000-4061-922b-0c0b518a57db','0'),
('webAuthnPolicyRequireResidentKey','139c1488-d000-4061-922b-0c0b518a57db','not specified'),
('webAuthnPolicyRequireResidentKeyPasswordless','139c1488-d000-4061-922b-0c0b518a57db','not specified'),
('webAuthnPolicyRpEntityName','139c1488-d000-4061-922b-0c0b518a57db','keycloak'),
('webAuthnPolicyRpEntityNamePasswordless','139c1488-d000-4061-922b-0c0b518a57db','keycloak'),
('webAuthnPolicyRpId','139c1488-d000-4061-922b-0c0b518a57db',''),
('webAuthnPolicyRpIdPasswordless','139c1488-d000-4061-922b-0c0b518a57db',''),
('webAuthnPolicySignatureAlgorithms','139c1488-d000-4061-922b-0c0b518a57db','ES256'),
('webAuthnPolicySignatureAlgorithmsPasswordless','139c1488-d000-4061-922b-0c0b518a57db','ES256'),
('webAuthnPolicyUserVerificationRequirement','139c1488-d000-4061-922b-0c0b518a57db','not specified'),
('webAuthnPolicyUserVerificationRequirementPasswordless','139c1488-d000-4061-922b-0c0b518a57db','not specified'),
('_browser_header.contentSecurityPolicy','139c1488-d000-4061-922b-0c0b518a57db','frame-src \'self\'; frame-ancestors \'self\'; object-src \'none\';'),
('_browser_header.contentSecurityPolicy','61c254e2-095d-42b9-b8cc-4546b124e548','frame-src \'self\'; frame-ancestors \'self\'; object-src \'none\';'),
('_browser_header.contentSecurityPolicyReportOnly','139c1488-d000-4061-922b-0c0b518a57db',''),
('_browser_header.contentSecurityPolicyReportOnly','61c254e2-095d-42b9-b8cc-4546b124e548',''),
('_browser_header.referrerPolicy','139c1488-d000-4061-922b-0c0b518a57db','no-referrer'),
('_browser_header.referrerPolicy','61c254e2-095d-42b9-b8cc-4546b124e548','no-referrer'),
('_browser_header.strictTransportSecurity','139c1488-d000-4061-922b-0c0b518a57db','max-age=31536000; includeSubDomains'),
('_browser_header.strictTransportSecurity','61c254e2-095d-42b9-b8cc-4546b124e548','max-age=31536000; includeSubDomains'),
('_browser_header.xContentTypeOptions','139c1488-d000-4061-922b-0c0b518a57db','nosniff'),
('_browser_header.xContentTypeOptions','61c254e2-095d-42b9-b8cc-4546b124e548','nosniff'),
('_browser_header.xFrameOptions','139c1488-d000-4061-922b-0c0b518a57db','SAMEORIGIN'),
('_browser_header.xFrameOptions','61c254e2-095d-42b9-b8cc-4546b124e548','SAMEORIGIN'),
('_browser_header.xRobotsTag','139c1488-d000-4061-922b-0c0b518a57db','none'),
('_browser_header.xRobotsTag','61c254e2-095d-42b9-b8cc-4546b124e548','none'),
('_browser_header.xXSSProtection','139c1488-d000-4061-922b-0c0b518a57db','1; mode=block'),
('_browser_header.xXSSProtection','61c254e2-095d-42b9-b8cc-4546b124e548','1; mode=block');
/*!40000 ALTER TABLE `REALM_ATTRIBUTE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `REALM_DEFAULT_GROUPS`
--

DROP TABLE IF EXISTS `REALM_DEFAULT_GROUPS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `REALM_DEFAULT_GROUPS` (
  `REALM_ID` varchar(36) NOT NULL,
  `GROUP_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`REALM_ID`,`GROUP_ID`),
  UNIQUE KEY `CON_GROUP_ID_DEF_GROUPS` (`GROUP_ID`),
  KEY `IDX_REALM_DEF_GRP_REALM` (`REALM_ID`),
  CONSTRAINT `FK_DEF_GROUPS_REALM` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `REALM_DEFAULT_GROUPS`
--

LOCK TABLES `REALM_DEFAULT_GROUPS` WRITE;
/*!40000 ALTER TABLE `REALM_DEFAULT_GROUPS` DISABLE KEYS */;
/*!40000 ALTER TABLE `REALM_DEFAULT_GROUPS` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `REALM_ENABLED_EVENT_TYPES`
--

DROP TABLE IF EXISTS `REALM_ENABLED_EVENT_TYPES`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `REALM_ENABLED_EVENT_TYPES` (
  `REALM_ID` varchar(36) NOT NULL,
  `VALUE` varchar(255) NOT NULL,
  PRIMARY KEY (`REALM_ID`,`VALUE`),
  KEY `IDX_REALM_EVT_TYPES_REALM` (`REALM_ID`),
  CONSTRAINT `FK_H846O4H0W8EPX5NWEDRF5Y69J` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `REALM_ENABLED_EVENT_TYPES`
--

LOCK TABLES `REALM_ENABLED_EVENT_TYPES` WRITE;
/*!40000 ALTER TABLE `REALM_ENABLED_EVENT_TYPES` DISABLE KEYS */;
/*!40000 ALTER TABLE `REALM_ENABLED_EVENT_TYPES` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `REALM_EVENTS_LISTENERS`
--

DROP TABLE IF EXISTS `REALM_EVENTS_LISTENERS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `REALM_EVENTS_LISTENERS` (
  `REALM_ID` varchar(36) NOT NULL,
  `VALUE` varchar(255) NOT NULL,
  PRIMARY KEY (`REALM_ID`,`VALUE`),
  KEY `IDX_REALM_EVT_LIST_REALM` (`REALM_ID`),
  CONSTRAINT `FK_H846O4H0W8EPX5NXEV9F5Y69J` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `REALM_EVENTS_LISTENERS`
--

LOCK TABLES `REALM_EVENTS_LISTENERS` WRITE;
/*!40000 ALTER TABLE `REALM_EVENTS_LISTENERS` DISABLE KEYS */;
INSERT INTO `REALM_EVENTS_LISTENERS` VALUES
('139c1488-d000-4061-922b-0c0b518a57db','jboss-logging'),
('61c254e2-095d-42b9-b8cc-4546b124e548','jboss-logging');
/*!40000 ALTER TABLE `REALM_EVENTS_LISTENERS` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `REALM_LOCALIZATIONS`
--

DROP TABLE IF EXISTS `REALM_LOCALIZATIONS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `REALM_LOCALIZATIONS` (
  `REALM_ID` varchar(255) NOT NULL,
  `LOCALE` varchar(255) NOT NULL,
  `TEXTS` longtext CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL,
  PRIMARY KEY (`REALM_ID`,`LOCALE`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `REALM_LOCALIZATIONS`
--

LOCK TABLES `REALM_LOCALIZATIONS` WRITE;
/*!40000 ALTER TABLE `REALM_LOCALIZATIONS` DISABLE KEYS */;
/*!40000 ALTER TABLE `REALM_LOCALIZATIONS` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `REALM_REQUIRED_CREDENTIAL`
--

DROP TABLE IF EXISTS `REALM_REQUIRED_CREDENTIAL`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `REALM_REQUIRED_CREDENTIAL` (
  `TYPE` varchar(255) NOT NULL,
  `FORM_LABEL` varchar(255) DEFAULT NULL,
  `INPUT` bit(1) NOT NULL DEFAULT b'0',
  `SECRET` bit(1) NOT NULL DEFAULT b'0',
  `REALM_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`REALM_ID`,`TYPE`),
  CONSTRAINT `FK_5HG65LYBEVAVKQFKI3KPONH9V` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `REALM_REQUIRED_CREDENTIAL`
--

LOCK TABLES `REALM_REQUIRED_CREDENTIAL` WRITE;
/*!40000 ALTER TABLE `REALM_REQUIRED_CREDENTIAL` DISABLE KEYS */;
INSERT INTO `REALM_REQUIRED_CREDENTIAL` VALUES
('password','password','','','139c1488-d000-4061-922b-0c0b518a57db'),
('password','password','','','61c254e2-095d-42b9-b8cc-4546b124e548');
/*!40000 ALTER TABLE `REALM_REQUIRED_CREDENTIAL` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `REALM_SMTP_CONFIG`
--

DROP TABLE IF EXISTS `REALM_SMTP_CONFIG`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `REALM_SMTP_CONFIG` (
  `REALM_ID` varchar(36) NOT NULL,
  `VALUE` varchar(255) DEFAULT NULL,
  `NAME` varchar(255) NOT NULL,
  PRIMARY KEY (`REALM_ID`,`NAME`),
  CONSTRAINT `FK_70EJ8XDXGXD0B9HH6180IRR0O` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `REALM_SMTP_CONFIG`
--

LOCK TABLES `REALM_SMTP_CONFIG` WRITE;
/*!40000 ALTER TABLE `REALM_SMTP_CONFIG` DISABLE KEYS */;
/*!40000 ALTER TABLE `REALM_SMTP_CONFIG` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `REALM_SUPPORTED_LOCALES`
--

DROP TABLE IF EXISTS `REALM_SUPPORTED_LOCALES`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `REALM_SUPPORTED_LOCALES` (
  `REALM_ID` varchar(36) NOT NULL,
  `VALUE` varchar(255) NOT NULL,
  PRIMARY KEY (`REALM_ID`,`VALUE`),
  KEY `IDX_REALM_SUPP_LOCAL_REALM` (`REALM_ID`),
  CONSTRAINT `FK_SUPPORTED_LOCALES_REALM` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `REALM_SUPPORTED_LOCALES`
--

LOCK TABLES `REALM_SUPPORTED_LOCALES` WRITE;
/*!40000 ALTER TABLE `REALM_SUPPORTED_LOCALES` DISABLE KEYS */;
/*!40000 ALTER TABLE `REALM_SUPPORTED_LOCALES` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `REDIRECT_URIS`
--

DROP TABLE IF EXISTS `REDIRECT_URIS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `REDIRECT_URIS` (
  `CLIENT_ID` varchar(36) NOT NULL,
  `VALUE` varchar(255) NOT NULL,
  PRIMARY KEY (`CLIENT_ID`,`VALUE`),
  KEY `IDX_REDIR_URI_CLIENT` (`CLIENT_ID`),
  CONSTRAINT `FK_1BURS8PB4OUJ97H5WUPPAHV9F` FOREIGN KEY (`CLIENT_ID`) REFERENCES `CLIENT` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `REDIRECT_URIS`
--

LOCK TABLES `REDIRECT_URIS` WRITE;
/*!40000 ALTER TABLE `REDIRECT_URIS` DISABLE KEYS */;
INSERT INTO `REDIRECT_URIS` VALUES
('2f7d86a0-e8ba-4b75-9009-2048c5611177','/realms/master/account/*'),
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','/*'),
('49a49ecd-6045-42e4-9043-edf917f74b18','/*'),
('53ef6db9-271e-46c5-bd72-2f12ea045014','/*'),
('79748e7e-06c2-4915-988c-0e30b15d12db','/admin/master/console/*'),
('8b2528fe-d14e-4b36-8b3d-4a44b89bd6dc','/admin/ruciodev/console/*'),
('9c1f7e9e-8703-4cca-82b0-d944dbf29287','/realms/ruciodev/account/*'),
('a4c24db6-3fe8-4b9c-a183-42a75148d531','/realms/ruciodev/account/*'),
('e32dde36-fa71-4648-aa46-ad822a2b51b6','/realms/master/account/*');
/*!40000 ALTER TABLE `REDIRECT_URIS` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `REQUIRED_ACTION_CONFIG`
--

DROP TABLE IF EXISTS `REQUIRED_ACTION_CONFIG`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `REQUIRED_ACTION_CONFIG` (
  `REQUIRED_ACTION_ID` varchar(36) NOT NULL,
  `VALUE` longtext DEFAULT NULL,
  `NAME` varchar(255) NOT NULL,
  PRIMARY KEY (`REQUIRED_ACTION_ID`,`NAME`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `REQUIRED_ACTION_CONFIG`
--

LOCK TABLES `REQUIRED_ACTION_CONFIG` WRITE;
/*!40000 ALTER TABLE `REQUIRED_ACTION_CONFIG` DISABLE KEYS */;
/*!40000 ALTER TABLE `REQUIRED_ACTION_CONFIG` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `REQUIRED_ACTION_PROVIDER`
--

DROP TABLE IF EXISTS `REQUIRED_ACTION_PROVIDER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `REQUIRED_ACTION_PROVIDER` (
  `ID` varchar(36) NOT NULL,
  `ALIAS` varchar(255) DEFAULT NULL,
  `NAME` varchar(255) DEFAULT NULL,
  `REALM_ID` varchar(36) DEFAULT NULL,
  `ENABLED` bit(1) NOT NULL DEFAULT b'0',
  `DEFAULT_ACTION` bit(1) NOT NULL DEFAULT b'0',
  `PROVIDER_ID` varchar(255) DEFAULT NULL,
  `PRIORITY` int(11) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_REQ_ACT_PROV_REALM` (`REALM_ID`),
  CONSTRAINT `FK_REQ_ACT_REALM` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `REQUIRED_ACTION_PROVIDER`
--

LOCK TABLES `REQUIRED_ACTION_PROVIDER` WRITE;
/*!40000 ALTER TABLE `REQUIRED_ACTION_PROVIDER` DISABLE KEYS */;
INSERT INTO `REQUIRED_ACTION_PROVIDER` VALUES
('0e2b221b-458a-42ac-8f0c-154491a24663','delete_account','Delete Account','61c254e2-095d-42b9-b8cc-4546b124e548','\0','\0','delete_account',60),
('10f17995-c526-4741-9051-c17b9dfc053a','webauthn-register-passwordless','Webauthn Register Passwordless','61c254e2-095d-42b9-b8cc-4546b124e548','','\0','webauthn-register-passwordless',80),
('1ebf9cfb-5998-48e3-a695-6d6e1a23bc3f','VERIFY_EMAIL','Verify Email','139c1488-d000-4061-922b-0c0b518a57db','','\0','VERIFY_EMAIL',50),
('20b60684-4b28-4710-a295-b33e6bc06730','webauthn-register-passwordless','Webauthn Register Passwordless','139c1488-d000-4061-922b-0c0b518a57db','','\0','webauthn-register-passwordless',80),
('28fb4fc8-bc2d-4487-9ba6-ed56168f2d2e','VERIFY_EMAIL','Verify Email','61c254e2-095d-42b9-b8cc-4546b124e548','','\0','VERIFY_EMAIL',50),
('2b914b42-7cd7-4689-b305-44db838287c1','webauthn-register','Webauthn Register','61c254e2-095d-42b9-b8cc-4546b124e548','','\0','webauthn-register',70),
('69e4f13b-7627-43b8-91e6-6b62b679358e','UPDATE_PASSWORD','Update Password','139c1488-d000-4061-922b-0c0b518a57db','','\0','UPDATE_PASSWORD',30),
('803352da-068e-49a7-921c-0cf192437195','UPDATE_PASSWORD','Update Password','61c254e2-095d-42b9-b8cc-4546b124e548','','\0','UPDATE_PASSWORD',30),
('88457408-58f5-4c95-a97d-a11d56f52b25','TERMS_AND_CONDITIONS','Terms and Conditions','139c1488-d000-4061-922b-0c0b518a57db','\0','\0','TERMS_AND_CONDITIONS',20),
('887feb82-3ce3-45af-ae59-5174b763af07','update_user_locale','Update User Locale','61c254e2-095d-42b9-b8cc-4546b124e548','','\0','update_user_locale',1000),
('949f253d-feb2-4521-b447-c75881a640ee','CONFIGURE_TOTP','Configure OTP','139c1488-d000-4061-922b-0c0b518a57db','','\0','CONFIGURE_TOTP',10),
('9c7f4261-b6ba-4e6e-b6bf-06ac3432843b','CONFIGURE_TOTP','Configure OTP','61c254e2-095d-42b9-b8cc-4546b124e548','','\0','CONFIGURE_TOTP',10),
('a0c91d88-ba12-4f4a-9b62-ccb4edd9598e','UPDATE_PROFILE','Update Profile','139c1488-d000-4061-922b-0c0b518a57db','','\0','UPDATE_PROFILE',40),
('a1be9e0c-417e-43f2-a55e-486ba0718c0e','webauthn-register','Webauthn Register','139c1488-d000-4061-922b-0c0b518a57db','','\0','webauthn-register',70),
('aadcbdc0-bc06-4dfc-9f63-b66de9a64681','update_user_locale','Update User Locale','139c1488-d000-4061-922b-0c0b518a57db','','\0','update_user_locale',1000),
('ba04da16-bb88-48d2-8ee3-f51e651c2f71','UPDATE_PROFILE','Update Profile','61c254e2-095d-42b9-b8cc-4546b124e548','','\0','UPDATE_PROFILE',40),
('e78a82c5-8fdf-4041-ba5b-40156bf15980','delete_account','Delete Account','139c1488-d000-4061-922b-0c0b518a57db','\0','\0','delete_account',60),
('fb75b327-6d37-4942-93e5-dd22f301044c','TERMS_AND_CONDITIONS','Terms and Conditions','61c254e2-095d-42b9-b8cc-4546b124e548','\0','\0','TERMS_AND_CONDITIONS',20);
/*!40000 ALTER TABLE `REQUIRED_ACTION_PROVIDER` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `RESOURCE_ATTRIBUTE`
--

DROP TABLE IF EXISTS `RESOURCE_ATTRIBUTE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `RESOURCE_ATTRIBUTE` (
  `ID` varchar(36) NOT NULL DEFAULT 'sybase-needs-something-here',
  `NAME` varchar(255) NOT NULL,
  `VALUE` varchar(255) DEFAULT NULL,
  `RESOURCE_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `FK_5HRM2VLF9QL5FU022KQEPOVBR` (`RESOURCE_ID`),
  CONSTRAINT `FK_5HRM2VLF9QL5FU022KQEPOVBR` FOREIGN KEY (`RESOURCE_ID`) REFERENCES `RESOURCE_SERVER_RESOURCE` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `RESOURCE_ATTRIBUTE`
--

LOCK TABLES `RESOURCE_ATTRIBUTE` WRITE;
/*!40000 ALTER TABLE `RESOURCE_ATTRIBUTE` DISABLE KEYS */;
/*!40000 ALTER TABLE `RESOURCE_ATTRIBUTE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `RESOURCE_POLICY`
--

DROP TABLE IF EXISTS `RESOURCE_POLICY`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `RESOURCE_POLICY` (
  `RESOURCE_ID` varchar(36) NOT NULL,
  `POLICY_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`RESOURCE_ID`,`POLICY_ID`),
  KEY `IDX_RES_POLICY_POLICY` (`POLICY_ID`),
  CONSTRAINT `FK_FRSRPOS53XCX4WNKOG82SSRFY` FOREIGN KEY (`RESOURCE_ID`) REFERENCES `RESOURCE_SERVER_RESOURCE` (`ID`),
  CONSTRAINT `FK_FRSRPP213XCX4WNKOG82SSRFY` FOREIGN KEY (`POLICY_ID`) REFERENCES `RESOURCE_SERVER_POLICY` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `RESOURCE_POLICY`
--

LOCK TABLES `RESOURCE_POLICY` WRITE;
/*!40000 ALTER TABLE `RESOURCE_POLICY` DISABLE KEYS */;
INSERT INTO `RESOURCE_POLICY` VALUES
('46e3249c-7cf7-4090-82f6-2a0099718f18','11c1ddb8-56c6-4047-952a-23c46c1c6659'),
('46e3249c-7cf7-4090-82f6-2a0099718f18','127d7c94-3e76-43f0-976c-2977e2071647'),
('46e3249c-7cf7-4090-82f6-2a0099718f18','db08dfbb-34de-410a-a313-6b50fa0abcdb'),
('46e3249c-7cf7-4090-82f6-2a0099718f18','e6709021-619f-4d3c-9946-6f9e6a04d516'),
('46e3249c-7cf7-4090-82f6-2a0099718f18','ecc9bc08-bedc-4379-9aa1-0e933dfeb635'),
('46e3249c-7cf7-4090-82f6-2a0099718f18','ef70cf4a-cf36-4fcf-90e0-6a73eef7cf8a'),
('46e3249c-7cf7-4090-82f6-2a0099718f18','f597076a-7d9e-4456-92c6-1189f4866149'),
('a673dabb-e69b-4f20-9a1d-f0be2931675f','22a760b8-0868-4e92-98fd-a12bf21b7db5'),
('a673dabb-e69b-4f20-9a1d-f0be2931675f','2473c812-fd93-422e-8a63-4cdbbbd99d10'),
('a673dabb-e69b-4f20-9a1d-f0be2931675f','266a5dbd-e533-4789-b032-985b628826f9'),
('a673dabb-e69b-4f20-9a1d-f0be2931675f','39c718e6-f814-4e59-8d26-4a9fb7d46947'),
('a673dabb-e69b-4f20-9a1d-f0be2931675f','60dbd369-5166-4fb8-b88f-4539461d8114'),
('a673dabb-e69b-4f20-9a1d-f0be2931675f','8ccb48e6-0384-492c-a6c7-13d1642a0e81'),
('a673dabb-e69b-4f20-9a1d-f0be2931675f','9a564341-4b20-4d9e-bd84-f049290d5771');
/*!40000 ALTER TABLE `RESOURCE_POLICY` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `RESOURCE_SCOPE`
--

DROP TABLE IF EXISTS `RESOURCE_SCOPE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `RESOURCE_SCOPE` (
  `RESOURCE_ID` varchar(36) NOT NULL,
  `SCOPE_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`RESOURCE_ID`,`SCOPE_ID`),
  KEY `IDX_RES_SCOPE_SCOPE` (`SCOPE_ID`),
  CONSTRAINT `FK_FRSRPOS13XCX4WNKOG82SSRFY` FOREIGN KEY (`RESOURCE_ID`) REFERENCES `RESOURCE_SERVER_RESOURCE` (`ID`),
  CONSTRAINT `FK_FRSRPS213XCX4WNKOG82SSRFY` FOREIGN KEY (`SCOPE_ID`) REFERENCES `RESOURCE_SERVER_SCOPE` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `RESOURCE_SCOPE`
--

LOCK TABLES `RESOURCE_SCOPE` WRITE;
/*!40000 ALTER TABLE `RESOURCE_SCOPE` DISABLE KEYS */;
INSERT INTO `RESOURCE_SCOPE` VALUES
('46e3249c-7cf7-4090-82f6-2a0099718f18','29ce15a4-9a72-4c86-ba7f-4020fdae2219'),
('46e3249c-7cf7-4090-82f6-2a0099718f18','4c4f527f-c073-4ac5-a714-a0a3f1b8d7c9'),
('46e3249c-7cf7-4090-82f6-2a0099718f18','5130fdf6-0d92-44b9-9369-3fcd1b5d5f0b'),
('46e3249c-7cf7-4090-82f6-2a0099718f18','5449d5a5-fff3-4af4-925b-03a43f55a85f'),
('46e3249c-7cf7-4090-82f6-2a0099718f18','6cd9dd9e-0de9-47ca-a0d9-1db4166bc3c7'),
('46e3249c-7cf7-4090-82f6-2a0099718f18','9dd2004a-889e-44e5-840f-1dbd77b61c5d'),
('46e3249c-7cf7-4090-82f6-2a0099718f18','f32e21c2-c59f-420f-97a4-57f7b74e75f1'),
('a673dabb-e69b-4f20-9a1d-f0be2931675f','29ce15a4-9a72-4c86-ba7f-4020fdae2219'),
('a673dabb-e69b-4f20-9a1d-f0be2931675f','4c4f527f-c073-4ac5-a714-a0a3f1b8d7c9'),
('a673dabb-e69b-4f20-9a1d-f0be2931675f','5130fdf6-0d92-44b9-9369-3fcd1b5d5f0b'),
('a673dabb-e69b-4f20-9a1d-f0be2931675f','5449d5a5-fff3-4af4-925b-03a43f55a85f'),
('a673dabb-e69b-4f20-9a1d-f0be2931675f','6cd9dd9e-0de9-47ca-a0d9-1db4166bc3c7'),
('a673dabb-e69b-4f20-9a1d-f0be2931675f','9dd2004a-889e-44e5-840f-1dbd77b61c5d'),
('a673dabb-e69b-4f20-9a1d-f0be2931675f','f32e21c2-c59f-420f-97a4-57f7b74e75f1');
/*!40000 ALTER TABLE `RESOURCE_SCOPE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `RESOURCE_SERVER`
--

DROP TABLE IF EXISTS `RESOURCE_SERVER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `RESOURCE_SERVER` (
  `ID` varchar(36) NOT NULL,
  `ALLOW_RS_REMOTE_MGMT` bit(1) NOT NULL DEFAULT b'0',
  `POLICY_ENFORCE_MODE` tinyint(4) DEFAULT NULL,
  `DECISION_STRATEGY` tinyint(4) NOT NULL DEFAULT 1,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `RESOURCE_SERVER`
--

LOCK TABLES `RESOURCE_SERVER` WRITE;
/*!40000 ALTER TABLE `RESOURCE_SERVER` DISABLE KEYS */;
INSERT INTO `RESOURCE_SERVER` VALUES
('53ef6db9-271e-46c5-bd72-2f12ea045014','',0,1),
('6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','\0',0,1);
/*!40000 ALTER TABLE `RESOURCE_SERVER` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `RESOURCE_SERVER_PERM_TICKET`
--

DROP TABLE IF EXISTS `RESOURCE_SERVER_PERM_TICKET`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `RESOURCE_SERVER_PERM_TICKET` (
  `ID` varchar(36) NOT NULL,
  `OWNER` varchar(255) DEFAULT NULL,
  `REQUESTER` varchar(255) DEFAULT NULL,
  `CREATED_TIMESTAMP` bigint(20) NOT NULL,
  `GRANTED_TIMESTAMP` bigint(20) DEFAULT NULL,
  `RESOURCE_ID` varchar(36) NOT NULL,
  `SCOPE_ID` varchar(36) DEFAULT NULL,
  `RESOURCE_SERVER_ID` varchar(36) NOT NULL,
  `POLICY_ID` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK_FRSR6T700S9V50BU18WS5PMT` (`OWNER`,`REQUESTER`,`RESOURCE_SERVER_ID`,`RESOURCE_ID`,`SCOPE_ID`),
  KEY `FK_FRSRHO213XCX4WNKOG82SSPMT` (`RESOURCE_SERVER_ID`),
  KEY `FK_FRSRHO213XCX4WNKOG83SSPMT` (`RESOURCE_ID`),
  KEY `FK_FRSRHO213XCX4WNKOG84SSPMT` (`SCOPE_ID`),
  KEY `FK_FRSRPO2128CX4WNKOG82SSRFY` (`POLICY_ID`),
  CONSTRAINT `FK_FRSRHO213XCX4WNKOG82SSPMT` FOREIGN KEY (`RESOURCE_SERVER_ID`) REFERENCES `RESOURCE_SERVER` (`ID`),
  CONSTRAINT `FK_FRSRHO213XCX4WNKOG83SSPMT` FOREIGN KEY (`RESOURCE_ID`) REFERENCES `RESOURCE_SERVER_RESOURCE` (`ID`),
  CONSTRAINT `FK_FRSRHO213XCX4WNKOG84SSPMT` FOREIGN KEY (`SCOPE_ID`) REFERENCES `RESOURCE_SERVER_SCOPE` (`ID`),
  CONSTRAINT `FK_FRSRPO2128CX4WNKOG82SSRFY` FOREIGN KEY (`POLICY_ID`) REFERENCES `RESOURCE_SERVER_POLICY` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `RESOURCE_SERVER_PERM_TICKET`
--

LOCK TABLES `RESOURCE_SERVER_PERM_TICKET` WRITE;
/*!40000 ALTER TABLE `RESOURCE_SERVER_PERM_TICKET` DISABLE KEYS */;
/*!40000 ALTER TABLE `RESOURCE_SERVER_PERM_TICKET` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `RESOURCE_SERVER_POLICY`
--

DROP TABLE IF EXISTS `RESOURCE_SERVER_POLICY`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `RESOURCE_SERVER_POLICY` (
  `ID` varchar(36) NOT NULL,
  `NAME` varchar(255) NOT NULL,
  `DESCRIPTION` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `TYPE` varchar(255) NOT NULL,
  `DECISION_STRATEGY` tinyint(4) DEFAULT NULL,
  `LOGIC` tinyint(4) DEFAULT NULL,
  `RESOURCE_SERVER_ID` varchar(36) DEFAULT NULL,
  `OWNER` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK_FRSRPT700S9V50BU18WS5HA6` (`NAME`,`RESOURCE_SERVER_ID`),
  KEY `IDX_RES_SERV_POL_RES_SERV` (`RESOURCE_SERVER_ID`),
  CONSTRAINT `FK_FRSRPO213XCX4WNKOG82SSRFY` FOREIGN KEY (`RESOURCE_SERVER_ID`) REFERENCES `RESOURCE_SERVER` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `RESOURCE_SERVER_POLICY`
--

LOCK TABLES `RESOURCE_SERVER_POLICY` WRITE;
/*!40000 ALTER TABLE `RESOURCE_SERVER_POLICY` DISABLE KEYS */;
INSERT INTO `RESOURCE_SERVER_POLICY` VALUES
('11c1ddb8-56c6-4047-952a-23c46c1c6659','map-roles-client-scope.permission.client.34bb26a0-d197-48a9-a0e2-4987dec23d0e',NULL,'scope',1,0,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('127d7c94-3e76-43f0-976c-2977e2071647','configure.permission.client.34bb26a0-d197-48a9-a0e2-4987dec23d0e',NULL,'scope',1,0,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('22a760b8-0868-4e92-98fd-a12bf21b7db5','manage.permission.client.49a49ecd-6045-42e4-9043-edf917f74b18',NULL,'scope',1,0,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('2473c812-fd93-422e-8a63-4cdbbbd99d10','map-roles-composite.permission.client.49a49ecd-6045-42e4-9043-edf917f74b18',NULL,'scope',1,0,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('266a5dbd-e533-4789-b032-985b628826f9','map-roles-client-scope.permission.client.49a49ecd-6045-42e4-9043-edf917f74b18',NULL,'scope',1,0,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('39c718e6-f814-4e59-8d26-4a9fb7d46947','token-exchange.permission.client.49a49ecd-6045-42e4-9043-edf917f74b18','','scope',1,0,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('60dbd369-5166-4fb8-b88f-4539461d8114','view.permission.client.49a49ecd-6045-42e4-9043-edf917f74b18',NULL,'scope',1,0,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('71dd1617-3f3b-41d1-8ea7-a2a9f48e5d12','Default Permission','A permission that applies to the default resource type','resource',1,0,'53ef6db9-271e-46c5-bd72-2f12ea045014',NULL),
('8ccb48e6-0384-492c-a6c7-13d1642a0e81','configure.permission.client.49a49ecd-6045-42e4-9043-edf917f74b18',NULL,'scope',1,0,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('9a564341-4b20-4d9e-bd84-f049290d5771','map-roles.permission.client.49a49ecd-6045-42e4-9043-edf917f74b18',NULL,'scope',1,0,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('a53eb10e-0623-4586-a482-7a41666a4c68','allow-rucio','','client',1,0,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('cd2e5ea5-10ef-4aed-8871-a8d31296c40b','Default Policy','A policy that grants access only for users within this realm','js',0,0,'53ef6db9-271e-46c5-bd72-2f12ea045014',NULL),
('db08dfbb-34de-410a-a313-6b50fa0abcdb','view.permission.client.34bb26a0-d197-48a9-a0e2-4987dec23d0e',NULL,'scope',1,0,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('e6709021-619f-4d3c-9946-6f9e6a04d516','map-roles-composite.permission.client.34bb26a0-d197-48a9-a0e2-4987dec23d0e',NULL,'scope',1,0,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('ecc9bc08-bedc-4379-9aa1-0e933dfeb635','map-roles.permission.client.34bb26a0-d197-48a9-a0e2-4987dec23d0e',NULL,'scope',1,0,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('ef70cf4a-cf36-4fcf-90e0-6a73eef7cf8a','token-exchange.permission.client.34bb26a0-d197-48a9-a0e2-4987dec23d0e','','scope',1,0,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('f597076a-7d9e-4456-92c6-1189f4866149','manage.permission.client.34bb26a0-d197-48a9-a0e2-4987dec23d0e',NULL,'scope',1,0,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL);
/*!40000 ALTER TABLE `RESOURCE_SERVER_POLICY` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `RESOURCE_SERVER_RESOURCE`
--

DROP TABLE IF EXISTS `RESOURCE_SERVER_RESOURCE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `RESOURCE_SERVER_RESOURCE` (
  `ID` varchar(36) NOT NULL,
  `NAME` varchar(255) NOT NULL,
  `TYPE` varchar(255) DEFAULT NULL,
  `ICON_URI` varchar(255) DEFAULT NULL,
  `OWNER` varchar(255) DEFAULT NULL,
  `RESOURCE_SERVER_ID` varchar(36) DEFAULT NULL,
  `OWNER_MANAGED_ACCESS` bit(1) NOT NULL DEFAULT b'0',
  `DISPLAY_NAME` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK_FRSR6T700S9V50BU18WS5HA6` (`NAME`,`OWNER`,`RESOURCE_SERVER_ID`),
  KEY `IDX_RES_SRV_RES_RES_SRV` (`RESOURCE_SERVER_ID`),
  CONSTRAINT `FK_FRSRHO213XCX4WNKOG82SSRFY` FOREIGN KEY (`RESOURCE_SERVER_ID`) REFERENCES `RESOURCE_SERVER` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `RESOURCE_SERVER_RESOURCE`
--

LOCK TABLES `RESOURCE_SERVER_RESOURCE` WRITE;
/*!40000 ALTER TABLE `RESOURCE_SERVER_RESOURCE` DISABLE KEYS */;
INSERT INTO `RESOURCE_SERVER_RESOURCE` VALUES
('46e3249c-7cf7-4090-82f6-2a0099718f18','client.resource.34bb26a0-d197-48a9-a0e2-4987dec23d0e','Client',NULL,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','\0',NULL),
('7ecd04d3-2bb5-483c-85c2-b8a377e38f32','Default Resource','urn:rucio:resources:default',NULL,'53ef6db9-271e-46c5-bd72-2f12ea045014','53ef6db9-271e-46c5-bd72-2f12ea045014','\0',NULL),
('a673dabb-e69b-4f20-9a1d-f0be2931675f','client.resource.49a49ecd-6045-42e4-9043-edf917f74b18','Client',NULL,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6','\0',NULL);
/*!40000 ALTER TABLE `RESOURCE_SERVER_RESOURCE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `RESOURCE_SERVER_SCOPE`
--

DROP TABLE IF EXISTS `RESOURCE_SERVER_SCOPE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `RESOURCE_SERVER_SCOPE` (
  `ID` varchar(36) NOT NULL,
  `NAME` varchar(255) NOT NULL,
  `ICON_URI` varchar(255) DEFAULT NULL,
  `RESOURCE_SERVER_ID` varchar(36) DEFAULT NULL,
  `DISPLAY_NAME` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK_FRSRST700S9V50BU18WS5HA6` (`NAME`,`RESOURCE_SERVER_ID`),
  KEY `IDX_RES_SRV_SCOPE_RES_SRV` (`RESOURCE_SERVER_ID`),
  CONSTRAINT `FK_FRSRSO213XCX4WNKOG82SSRFY` FOREIGN KEY (`RESOURCE_SERVER_ID`) REFERENCES `RESOURCE_SERVER` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `RESOURCE_SERVER_SCOPE`
--

LOCK TABLES `RESOURCE_SERVER_SCOPE` WRITE;
/*!40000 ALTER TABLE `RESOURCE_SERVER_SCOPE` DISABLE KEYS */;
INSERT INTO `RESOURCE_SERVER_SCOPE` VALUES
('29ce15a4-9a72-4c86-ba7f-4020fdae2219','token-exchange',NULL,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('4c4f527f-c073-4ac5-a714-a0a3f1b8d7c9','map-roles-composite',NULL,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('5130fdf6-0d92-44b9-9369-3fcd1b5d5f0b','view',NULL,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('5449d5a5-fff3-4af4-925b-03a43f55a85f','map-roles',NULL,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('6cd9dd9e-0de9-47ca-a0d9-1db4166bc3c7','manage',NULL,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('9dd2004a-889e-44e5-840f-1dbd77b61c5d','configure',NULL,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL),
('f32e21c2-c59f-420f-97a4-57f7b74e75f1','map-roles-client-scope',NULL,'6f1f1e92-a5e0-48e5-bdf2-4948cc03b8e6',NULL);
/*!40000 ALTER TABLE `RESOURCE_SERVER_SCOPE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `RESOURCE_URIS`
--

DROP TABLE IF EXISTS `RESOURCE_URIS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `RESOURCE_URIS` (
  `RESOURCE_ID` varchar(36) NOT NULL,
  `VALUE` varchar(255) NOT NULL,
  PRIMARY KEY (`RESOURCE_ID`,`VALUE`),
  CONSTRAINT `FK_RESOURCE_SERVER_URIS` FOREIGN KEY (`RESOURCE_ID`) REFERENCES `RESOURCE_SERVER_RESOURCE` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `RESOURCE_URIS`
--

LOCK TABLES `RESOURCE_URIS` WRITE;
/*!40000 ALTER TABLE `RESOURCE_URIS` DISABLE KEYS */;
INSERT INTO `RESOURCE_URIS` VALUES
('7ecd04d3-2bb5-483c-85c2-b8a377e38f32','/*');
/*!40000 ALTER TABLE `RESOURCE_URIS` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `ROLE_ATTRIBUTE`
--

DROP TABLE IF EXISTS `ROLE_ATTRIBUTE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ROLE_ATTRIBUTE` (
  `ID` varchar(36) NOT NULL,
  `ROLE_ID` varchar(36) NOT NULL,
  `NAME` varchar(255) NOT NULL,
  `VALUE` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_ROLE_ATTRIBUTE` (`ROLE_ID`),
  CONSTRAINT `FK_ROLE_ATTRIBUTE_ID` FOREIGN KEY (`ROLE_ID`) REFERENCES `KEYCLOAK_ROLE` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `ROLE_ATTRIBUTE`
--

LOCK TABLES `ROLE_ATTRIBUTE` WRITE;
/*!40000 ALTER TABLE `ROLE_ATTRIBUTE` DISABLE KEYS */;
/*!40000 ALTER TABLE `ROLE_ATTRIBUTE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SCOPE_MAPPING`
--

DROP TABLE IF EXISTS `SCOPE_MAPPING`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SCOPE_MAPPING` (
  `CLIENT_ID` varchar(36) NOT NULL,
  `ROLE_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`CLIENT_ID`,`ROLE_ID`),
  KEY `IDX_SCOPE_MAPPING_ROLE` (`ROLE_ID`),
  CONSTRAINT `FK_OUSE064PLMLR732LXJCN1Q5F1` FOREIGN KEY (`CLIENT_ID`) REFERENCES `CLIENT` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SCOPE_MAPPING`
--

LOCK TABLES `SCOPE_MAPPING` WRITE;
/*!40000 ALTER TABLE `SCOPE_MAPPING` DISABLE KEYS */;
INSERT INTO `SCOPE_MAPPING` VALUES
('2f7d86a0-e8ba-4b75-9009-2048c5611177','1fa32b1c-f9e1-4d29-b3e5-104941bbb22d'),
('2f7d86a0-e8ba-4b75-9009-2048c5611177','4109672e-c529-4d28-88e6-8fedf3c20003'),
('9c1f7e9e-8703-4cca-82b0-d944dbf29287','714f833e-ed29-4000-b932-273a246d4dd6'),
('9c1f7e9e-8703-4cca-82b0-d944dbf29287','cd82ab55-5d73-49a5-b659-3bc83bc4e06b');
/*!40000 ALTER TABLE `SCOPE_MAPPING` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SCOPE_POLICY`
--

DROP TABLE IF EXISTS `SCOPE_POLICY`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SCOPE_POLICY` (
  `SCOPE_ID` varchar(36) NOT NULL,
  `POLICY_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`SCOPE_ID`,`POLICY_ID`),
  KEY `IDX_SCOPE_POLICY_POLICY` (`POLICY_ID`),
  CONSTRAINT `FK_FRSRASP13XCX4WNKOG82SSRFY` FOREIGN KEY (`POLICY_ID`) REFERENCES `RESOURCE_SERVER_POLICY` (`ID`),
  CONSTRAINT `FK_FRSRPASS3XCX4WNKOG82SSRFY` FOREIGN KEY (`SCOPE_ID`) REFERENCES `RESOURCE_SERVER_SCOPE` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SCOPE_POLICY`
--

LOCK TABLES `SCOPE_POLICY` WRITE;
/*!40000 ALTER TABLE `SCOPE_POLICY` DISABLE KEYS */;
INSERT INTO `SCOPE_POLICY` VALUES
('29ce15a4-9a72-4c86-ba7f-4020fdae2219','39c718e6-f814-4e59-8d26-4a9fb7d46947'),
('29ce15a4-9a72-4c86-ba7f-4020fdae2219','ef70cf4a-cf36-4fcf-90e0-6a73eef7cf8a'),
('4c4f527f-c073-4ac5-a714-a0a3f1b8d7c9','2473c812-fd93-422e-8a63-4cdbbbd99d10'),
('4c4f527f-c073-4ac5-a714-a0a3f1b8d7c9','e6709021-619f-4d3c-9946-6f9e6a04d516'),
('5130fdf6-0d92-44b9-9369-3fcd1b5d5f0b','60dbd369-5166-4fb8-b88f-4539461d8114'),
('5130fdf6-0d92-44b9-9369-3fcd1b5d5f0b','db08dfbb-34de-410a-a313-6b50fa0abcdb'),
('5449d5a5-fff3-4af4-925b-03a43f55a85f','9a564341-4b20-4d9e-bd84-f049290d5771'),
('5449d5a5-fff3-4af4-925b-03a43f55a85f','ecc9bc08-bedc-4379-9aa1-0e933dfeb635'),
('6cd9dd9e-0de9-47ca-a0d9-1db4166bc3c7','22a760b8-0868-4e92-98fd-a12bf21b7db5'),
('6cd9dd9e-0de9-47ca-a0d9-1db4166bc3c7','f597076a-7d9e-4456-92c6-1189f4866149'),
('9dd2004a-889e-44e5-840f-1dbd77b61c5d','127d7c94-3e76-43f0-976c-2977e2071647'),
('9dd2004a-889e-44e5-840f-1dbd77b61c5d','8ccb48e6-0384-492c-a6c7-13d1642a0e81'),
('f32e21c2-c59f-420f-97a4-57f7b74e75f1','11c1ddb8-56c6-4047-952a-23c46c1c6659'),
('f32e21c2-c59f-420f-97a4-57f7b74e75f1','266a5dbd-e533-4789-b032-985b628826f9');
/*!40000 ALTER TABLE `SCOPE_POLICY` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `USERNAME_LOGIN_FAILURE`
--

DROP TABLE IF EXISTS `USERNAME_LOGIN_FAILURE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `USERNAME_LOGIN_FAILURE` (
  `REALM_ID` varchar(36) NOT NULL,
  `USERNAME` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL,
  `FAILED_LOGIN_NOT_BEFORE` int(11) DEFAULT NULL,
  `LAST_FAILURE` bigint(20) DEFAULT NULL,
  `LAST_IP_FAILURE` varchar(255) DEFAULT NULL,
  `NUM_FAILURES` int(11) DEFAULT NULL,
  PRIMARY KEY (`REALM_ID`,`USERNAME`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `USERNAME_LOGIN_FAILURE`
--

LOCK TABLES `USERNAME_LOGIN_FAILURE` WRITE;
/*!40000 ALTER TABLE `USERNAME_LOGIN_FAILURE` DISABLE KEYS */;
/*!40000 ALTER TABLE `USERNAME_LOGIN_FAILURE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `USER_ATTRIBUTE`
--

DROP TABLE IF EXISTS `USER_ATTRIBUTE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `USER_ATTRIBUTE` (
  `NAME` varchar(255) NOT NULL,
  `VALUE` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `USER_ID` varchar(36) NOT NULL,
  `ID` varchar(36) NOT NULL DEFAULT 'sybase-needs-something-here',
  PRIMARY KEY (`ID`),
  KEY `IDX_USER_ATTRIBUTE` (`USER_ID`),
  KEY `IDX_USER_ATTRIBUTE_NAME` (`NAME`,`VALUE`),
  CONSTRAINT `FK_5HRM2VLF9QL5FU043KQEPOVBR` FOREIGN KEY (`USER_ID`) REFERENCES `USER_ENTITY` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `USER_ATTRIBUTE`
--

LOCK TABLES `USER_ATTRIBUTE` WRITE;
/*!40000 ALTER TABLE `USER_ATTRIBUTE` DISABLE KEYS */;
/*!40000 ALTER TABLE `USER_ATTRIBUTE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `USER_CONSENT`
--

DROP TABLE IF EXISTS `USER_CONSENT`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `USER_CONSENT` (
  `ID` varchar(36) NOT NULL,
  `CLIENT_ID` varchar(255) DEFAULT NULL,
  `USER_ID` varchar(36) NOT NULL,
  `CREATED_DATE` bigint(20) DEFAULT NULL,
  `LAST_UPDATED_DATE` bigint(20) DEFAULT NULL,
  `CLIENT_STORAGE_PROVIDER` varchar(36) DEFAULT NULL,
  `EXTERNAL_CLIENT_ID` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK_JKUWUVD56ONTGSUHOGM8UEWRT` (`CLIENT_ID`,`CLIENT_STORAGE_PROVIDER`,`EXTERNAL_CLIENT_ID`,`USER_ID`),
  KEY `IDX_USER_CONSENT` (`USER_ID`),
  CONSTRAINT `FK_GRNTCSNT_USER` FOREIGN KEY (`USER_ID`) REFERENCES `USER_ENTITY` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `USER_CONSENT`
--

LOCK TABLES `USER_CONSENT` WRITE;
/*!40000 ALTER TABLE `USER_CONSENT` DISABLE KEYS */;
/*!40000 ALTER TABLE `USER_CONSENT` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `USER_CONSENT_CLIENT_SCOPE`
--

DROP TABLE IF EXISTS `USER_CONSENT_CLIENT_SCOPE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `USER_CONSENT_CLIENT_SCOPE` (
  `USER_CONSENT_ID` varchar(36) NOT NULL,
  `SCOPE_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`USER_CONSENT_ID`,`SCOPE_ID`),
  KEY `IDX_USCONSENT_CLSCOPE` (`USER_CONSENT_ID`),
  CONSTRAINT `FK_GRNTCSNT_CLSC_USC` FOREIGN KEY (`USER_CONSENT_ID`) REFERENCES `USER_CONSENT` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `USER_CONSENT_CLIENT_SCOPE`
--

LOCK TABLES `USER_CONSENT_CLIENT_SCOPE` WRITE;
/*!40000 ALTER TABLE `USER_CONSENT_CLIENT_SCOPE` DISABLE KEYS */;
/*!40000 ALTER TABLE `USER_CONSENT_CLIENT_SCOPE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `USER_ENTITY`
--

DROP TABLE IF EXISTS `USER_ENTITY`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `USER_ENTITY` (
  `ID` varchar(36) NOT NULL,
  `EMAIL` varchar(255) DEFAULT NULL,
  `EMAIL_CONSTRAINT` varchar(255) DEFAULT NULL,
  `EMAIL_VERIFIED` bit(1) NOT NULL DEFAULT b'0',
  `ENABLED` bit(1) NOT NULL DEFAULT b'0',
  `FEDERATION_LINK` varchar(255) DEFAULT NULL,
  `FIRST_NAME` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `LAST_NAME` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `REALM_ID` varchar(255) DEFAULT NULL,
  `USERNAME` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `CREATED_TIMESTAMP` bigint(20) DEFAULT NULL,
  `SERVICE_ACCOUNT_CLIENT_LINK` varchar(255) DEFAULT NULL,
  `NOT_BEFORE` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK_DYKN684SL8UP1CRFEI6ECKHD7` (`REALM_ID`,`EMAIL_CONSTRAINT`),
  UNIQUE KEY `UK_RU8TT6T700S9V50BU18WS5HA6` (`REALM_ID`,`USERNAME`),
  KEY `IDX_USER_EMAIL` (`EMAIL`),
  KEY `IDX_USER_SERVICE_ACCOUNT` (`REALM_ID`,`SERVICE_ACCOUNT_CLIENT_LINK`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `USER_ENTITY`
--

LOCK TABLES `USER_ENTITY` WRITE;
/*!40000 ALTER TABLE `USER_ENTITY` DISABLE KEYS */;
INSERT INTO `USER_ENTITY` VALUES
('2d1a94bd-14ff-4e1d-af4c-3c61accf04a5',NULL,'be7b3642-d0e0-4b31-9ad0-4f5e6c8b7313','\0','',NULL,NULL,NULL,'139c1488-d000-4061-922b-0c0b518a57db','service-account-rucio',1702649298439,'53ef6db9-271e-46c5-bd72-2f12ea045014',0),
('bb803a13-3a2a-417e-a6c8-fe7abfb69983',NULL,'37d26078-20ab-4950-bf0f-6db2b5751283','\0','',NULL,NULL,NULL,'61c254e2-095d-42b9-b8cc-4546b124e548','admin',1702649218472,NULL,0);
/*!40000 ALTER TABLE `USER_ENTITY` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `USER_FEDERATION_CONFIG`
--

DROP TABLE IF EXISTS `USER_FEDERATION_CONFIG`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `USER_FEDERATION_CONFIG` (
  `USER_FEDERATION_PROVIDER_ID` varchar(36) NOT NULL,
  `VALUE` varchar(255) DEFAULT NULL,
  `NAME` varchar(255) NOT NULL,
  PRIMARY KEY (`USER_FEDERATION_PROVIDER_ID`,`NAME`),
  CONSTRAINT `FK_T13HPU1J94R2EBPEKR39X5EU5` FOREIGN KEY (`USER_FEDERATION_PROVIDER_ID`) REFERENCES `USER_FEDERATION_PROVIDER` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `USER_FEDERATION_CONFIG`
--

LOCK TABLES `USER_FEDERATION_CONFIG` WRITE;
/*!40000 ALTER TABLE `USER_FEDERATION_CONFIG` DISABLE KEYS */;
/*!40000 ALTER TABLE `USER_FEDERATION_CONFIG` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `USER_FEDERATION_MAPPER`
--

DROP TABLE IF EXISTS `USER_FEDERATION_MAPPER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `USER_FEDERATION_MAPPER` (
  `ID` varchar(36) NOT NULL,
  `NAME` varchar(255) NOT NULL,
  `FEDERATION_PROVIDER_ID` varchar(36) NOT NULL,
  `FEDERATION_MAPPER_TYPE` varchar(255) NOT NULL,
  `REALM_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_USR_FED_MAP_FED_PRV` (`FEDERATION_PROVIDER_ID`),
  KEY `IDX_USR_FED_MAP_REALM` (`REALM_ID`),
  CONSTRAINT `FK_FEDMAPPERPM_FEDPRV` FOREIGN KEY (`FEDERATION_PROVIDER_ID`) REFERENCES `USER_FEDERATION_PROVIDER` (`ID`),
  CONSTRAINT `FK_FEDMAPPERPM_REALM` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `USER_FEDERATION_MAPPER`
--

LOCK TABLES `USER_FEDERATION_MAPPER` WRITE;
/*!40000 ALTER TABLE `USER_FEDERATION_MAPPER` DISABLE KEYS */;
/*!40000 ALTER TABLE `USER_FEDERATION_MAPPER` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `USER_FEDERATION_MAPPER_CONFIG`
--

DROP TABLE IF EXISTS `USER_FEDERATION_MAPPER_CONFIG`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `USER_FEDERATION_MAPPER_CONFIG` (
  `USER_FEDERATION_MAPPER_ID` varchar(36) NOT NULL,
  `VALUE` varchar(255) DEFAULT NULL,
  `NAME` varchar(255) NOT NULL,
  PRIMARY KEY (`USER_FEDERATION_MAPPER_ID`,`NAME`),
  CONSTRAINT `FK_FEDMAPPER_CFG` FOREIGN KEY (`USER_FEDERATION_MAPPER_ID`) REFERENCES `USER_FEDERATION_MAPPER` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `USER_FEDERATION_MAPPER_CONFIG`
--

LOCK TABLES `USER_FEDERATION_MAPPER_CONFIG` WRITE;
/*!40000 ALTER TABLE `USER_FEDERATION_MAPPER_CONFIG` DISABLE KEYS */;
/*!40000 ALTER TABLE `USER_FEDERATION_MAPPER_CONFIG` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `USER_FEDERATION_PROVIDER`
--

DROP TABLE IF EXISTS `USER_FEDERATION_PROVIDER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `USER_FEDERATION_PROVIDER` (
  `ID` varchar(36) NOT NULL,
  `CHANGED_SYNC_PERIOD` int(11) DEFAULT NULL,
  `DISPLAY_NAME` varchar(255) DEFAULT NULL,
  `FULL_SYNC_PERIOD` int(11) DEFAULT NULL,
  `LAST_SYNC` int(11) DEFAULT NULL,
  `PRIORITY` int(11) DEFAULT NULL,
  `PROVIDER_NAME` varchar(255) DEFAULT NULL,
  `REALM_ID` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_USR_FED_PRV_REALM` (`REALM_ID`),
  CONSTRAINT `FK_1FJ32F6PTOLW2QY60CD8N01E8` FOREIGN KEY (`REALM_ID`) REFERENCES `REALM` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `USER_FEDERATION_PROVIDER`
--

LOCK TABLES `USER_FEDERATION_PROVIDER` WRITE;
/*!40000 ALTER TABLE `USER_FEDERATION_PROVIDER` DISABLE KEYS */;
/*!40000 ALTER TABLE `USER_FEDERATION_PROVIDER` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `USER_GROUP_MEMBERSHIP`
--

DROP TABLE IF EXISTS `USER_GROUP_MEMBERSHIP`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `USER_GROUP_MEMBERSHIP` (
  `GROUP_ID` varchar(36) NOT NULL,
  `USER_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`GROUP_ID`,`USER_ID`),
  KEY `IDX_USER_GROUP_MAPPING` (`USER_ID`),
  CONSTRAINT `FK_USER_GROUP_USER` FOREIGN KEY (`USER_ID`) REFERENCES `USER_ENTITY` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `USER_GROUP_MEMBERSHIP`
--

LOCK TABLES `USER_GROUP_MEMBERSHIP` WRITE;
/*!40000 ALTER TABLE `USER_GROUP_MEMBERSHIP` DISABLE KEYS */;
/*!40000 ALTER TABLE `USER_GROUP_MEMBERSHIP` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `USER_REQUIRED_ACTION`
--

DROP TABLE IF EXISTS `USER_REQUIRED_ACTION`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `USER_REQUIRED_ACTION` (
  `USER_ID` varchar(36) NOT NULL,
  `REQUIRED_ACTION` varchar(255) NOT NULL DEFAULT ' ',
  PRIMARY KEY (`REQUIRED_ACTION`,`USER_ID`),
  KEY `IDX_USER_REQACTIONS` (`USER_ID`),
  CONSTRAINT `FK_6QJ3W1JW9CVAFHE19BWSIUVMD` FOREIGN KEY (`USER_ID`) REFERENCES `USER_ENTITY` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `USER_REQUIRED_ACTION`
--

LOCK TABLES `USER_REQUIRED_ACTION` WRITE;
/*!40000 ALTER TABLE `USER_REQUIRED_ACTION` DISABLE KEYS */;
/*!40000 ALTER TABLE `USER_REQUIRED_ACTION` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `USER_ROLE_MAPPING`
--

DROP TABLE IF EXISTS `USER_ROLE_MAPPING`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `USER_ROLE_MAPPING` (
  `ROLE_ID` varchar(255) NOT NULL,
  `USER_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`ROLE_ID`,`USER_ID`),
  KEY `IDX_USER_ROLE_MAPPING` (`USER_ID`),
  CONSTRAINT `FK_C4FQV34P1MBYLLOXANG7B1Q3L` FOREIGN KEY (`USER_ID`) REFERENCES `USER_ENTITY` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `USER_ROLE_MAPPING`
--

LOCK TABLES `USER_ROLE_MAPPING` WRITE;
/*!40000 ALTER TABLE `USER_ROLE_MAPPING` DISABLE KEYS */;
INSERT INTO `USER_ROLE_MAPPING` VALUES
('05174a3b-088b-4002-9c29-07538b027be2','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('36351f76-327c-4f18-bb9d-7213f9ad0443','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('4a691081-0cec-4c8b-bb10-b74cd59896f6','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('5a4942b6-9d9c-42e3-8acf-f394a4c8653b','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('640f2839-b2f1-49fa-bb7e-605793c08de8','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('6b3487ba-98af-4992-a798-40f499258d5a','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('6fd3938c-9f28-423a-b49a-9b7059b52b42','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('714a6f1e-de37-4768-b6c5-f4792079b510','2d1a94bd-14ff-4e1d-af4c-3c61accf04a5'),
('73e0c1dc-6c4e-4171-acf8-028331b29e98','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('7e750a3e-d379-47a4-be5d-7837288f5183','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('83406e1d-a189-4b0f-8ec5-81bbeae69990','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('8d7973a1-8d62-4add-91e8-1a6676fc9ecd','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('8f1f8106-eae4-4213-8aa5-1480597cdec0','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('a30019cc-a32c-414c-a159-4bdbff80e001','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('b5be4df0-94bc-4f40-ae24-5ddba4b46bc8','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('c020bf25-1d76-4643-a446-73d175effe97','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('c120de31-e61d-41b1-a174-5e0fdf6c0ab9','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('c4ad0c25-3e5b-4e60-84e7-d4fa90dfb986','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('df76e680-bebc-4b85-a723-c5adf7ef86c6','bb803a13-3a2a-417e-a6c8-fe7abfb69983'),
('e33cb259-285b-4ebd-af96-3be259c3b84e','2d1a94bd-14ff-4e1d-af4c-3c61accf04a5'),
('f385ab65-af3b-4440-9735-c30448b45280','bb803a13-3a2a-417e-a6c8-fe7abfb69983');
/*!40000 ALTER TABLE `USER_ROLE_MAPPING` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `USER_SESSION`
--

DROP TABLE IF EXISTS `USER_SESSION`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `USER_SESSION` (
  `ID` varchar(36) NOT NULL,
  `AUTH_METHOD` varchar(255) DEFAULT NULL,
  `IP_ADDRESS` varchar(255) DEFAULT NULL,
  `LAST_SESSION_REFRESH` int(11) DEFAULT NULL,
  `LOGIN_USERNAME` varchar(255) DEFAULT NULL,
  `REALM_ID` varchar(255) DEFAULT NULL,
  `REMEMBER_ME` bit(1) NOT NULL DEFAULT b'0',
  `STARTED` int(11) DEFAULT NULL,
  `USER_ID` varchar(255) DEFAULT NULL,
  `USER_SESSION_STATE` int(11) DEFAULT NULL,
  `BROKER_SESSION_ID` varchar(255) DEFAULT NULL,
  `BROKER_USER_ID` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `USER_SESSION`
--

LOCK TABLES `USER_SESSION` WRITE;
/*!40000 ALTER TABLE `USER_SESSION` DISABLE KEYS */;
/*!40000 ALTER TABLE `USER_SESSION` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `USER_SESSION_NOTE`
--

DROP TABLE IF EXISTS `USER_SESSION_NOTE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `USER_SESSION_NOTE` (
  `USER_SESSION` varchar(36) NOT NULL,
  `NAME` varchar(255) NOT NULL,
  `VALUE` text DEFAULT NULL,
  PRIMARY KEY (`USER_SESSION`,`NAME`),
  CONSTRAINT `FK5EDFB00FF51D3472` FOREIGN KEY (`USER_SESSION`) REFERENCES `USER_SESSION` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `USER_SESSION_NOTE`
--

LOCK TABLES `USER_SESSION_NOTE` WRITE;
/*!40000 ALTER TABLE `USER_SESSION_NOTE` DISABLE KEYS */;
/*!40000 ALTER TABLE `USER_SESSION_NOTE` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `WEB_ORIGINS`
--

DROP TABLE IF EXISTS `WEB_ORIGINS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `WEB_ORIGINS` (
  `CLIENT_ID` varchar(36) NOT NULL,
  `VALUE` varchar(255) NOT NULL,
  PRIMARY KEY (`CLIENT_ID`,`VALUE`),
  KEY `IDX_WEB_ORIG_CLIENT` (`CLIENT_ID`),
  CONSTRAINT `FK_LOJPHO213XCX4WNKOG82SSRFY` FOREIGN KEY (`CLIENT_ID`) REFERENCES `CLIENT` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `WEB_ORIGINS`
--

LOCK TABLES `WEB_ORIGINS` WRITE;
/*!40000 ALTER TABLE `WEB_ORIGINS` DISABLE KEYS */;
INSERT INTO `WEB_ORIGINS` VALUES
('34bb26a0-d197-48a9-a0e2-4987dec23d0e','/*'),
('49a49ecd-6045-42e4-9043-edf917f74b18','/*'),
('53ef6db9-271e-46c5-bd72-2f12ea045014','/*'),
('79748e7e-06c2-4915-988c-0e30b15d12db','+'),
('8b2528fe-d14e-4b36-8b3d-4a44b89bd6dc','+');
/*!40000 ALTER TABLE `WEB_ORIGINS` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2023-12-23 10:06:44
