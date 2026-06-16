-- MySQL dump 10.13  Distrib 8.0.46, for Linux (x86_64)
--
-- Host: localhost    Database: CouldTalk
-- ------------------------------------------------------
-- Server version	8.0.46-0ubuntu0.22.04.2

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `anonymous_activities`
--

DROP TABLE IF EXISTS `anonymous_activities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `anonymous_activities` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(45) NOT NULL,
  `action_type` varchar(50) NOT NULL,
  `action_detail` text,
  `user_agent` varchar(255) DEFAULT NULL,
  `request_path` varchar(100) DEFAULT NULL,
  `method` varchar(10) DEFAULT NULL,
  `status_code` int DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `anonymous_activities`
--

LOCK TABLES `anonymous_activities` WRITE;
/*!40000 ALTER TABLE `anonymous_activities` DISABLE KEYS */;
INSERT INTO `anonymous_activities` VALUES (1,'183.228.54.203','waf_blocked','WAF拦截: RFI','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36','/static/images/flow.jpg','GET',NULL,'2026-05-03 22:33:46'),(2,'183.228.54.203','waf_blocked','WAF拦截: RFI','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36','/static/images/备案图标.png','GET',NULL,'2026-05-03 22:33:46'),(3,'183.228.54.203','waf_blocked','WAF拦截: RFI','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36','/static/video/银河系.mp4','GET',NULL,'2026-05-03 22:33:46'),(4,'183.228.54.203','waf_blocked','WAF拦截: RFI','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36','/static/images/flow.jpg','GET',NULL,'2026-05-03 22:33:51'),(5,'183.228.54.203','waf_blocked','WAF拦截: RFI','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36','/static/images/备案图标.png','GET',NULL,'2026-05-03 22:33:51'),(6,'183.228.54.203','waf_blocked','WAF拦截: RFI','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36','/static/video/银河系.mp4','GET',NULL,'2026-05-03 22:33:51'),(7,'183.228.54.203','waf_blocked','WAF拦截: RFI','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36','/static/images/香香的熏.jpg','GET',NULL,'2026-05-03 22:33:51'),(8,'183.228.54.203','waf_blocked','WAF拦截: RFI','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36','/static/images/备案图标.png','GET',NULL,'2026-05-03 22:33:52'),(9,'183.228.54.203','waf_blocked','WAF拦截: RFI','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36','/static/images/flow.jpg','GET',NULL,'2026-05-03 22:33:52'),(10,'183.228.54.203','waf_blocked','WAF拦截: RFI','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36','/static/video/银河系.mp4','GET',NULL,'2026-05-03 22:33:52'),(11,'183.228.54.203','waf_blocked','WAF拦截: RFI','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36','/static/images/香香的熏.jpg','GET',NULL,'2026-05-03 22:33:52');
/*!40000 ALTER TABLE `anonymous_activities` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `friend_requests`
--

DROP TABLE IF EXISTS `friend_requests`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `friend_requests` (
  `id` int NOT NULL AUTO_INCREMENT,
  `sender_id` int NOT NULL,
  `receiver_id` int NOT NULL,
  `status` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `sender_id` (`sender_id`),
  KEY `receiver_id` (`receiver_id`),
  CONSTRAINT `friend_requests_ibfk_1` FOREIGN KEY (`sender_id`) REFERENCES `users` (`id`),
  CONSTRAINT `friend_requests_ibfk_2` FOREIGN KEY (`receiver_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=16 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `friend_requests`
--

LOCK TABLES `friend_requests` WRITE;
/*!40000 ALTER TABLE `friend_requests` DISABLE KEYS */;
INSERT INTO `friend_requests` VALUES (7,12,11,'accepted',NULL),(8,13,12,'accepted',NULL),(9,2,11,'accepted',NULL),(10,2,12,'accepted',NULL),(11,2,13,'accepted',NULL),(12,14,12,'accepted',NULL),(13,14,11,'pending',NULL),(14,14,15,'pending',NULL),(15,12,15,'pending',NULL);
/*!40000 ALTER TABLE `friend_requests` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `friends`
--

DROP TABLE IF EXISTS `friends`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `friends` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `friend_id` int NOT NULL,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `friend_id` (`friend_id`),
  CONSTRAINT `friends_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  CONSTRAINT `friends_ibfk_2` FOREIGN KEY (`friend_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=25 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `friends`
--

LOCK TABLES `friends` WRITE;
/*!40000 ALTER TABLE `friends` DISABLE KEYS */;
INSERT INTO `friends` VALUES (13,12,11,'2026-04-08 18:20:20'),(14,11,12,'2026-04-08 18:20:20'),(15,13,12,'2026-04-08 18:20:20'),(16,12,13,'2026-04-08 18:20:20'),(17,2,12,'2026-04-08 18:20:20'),(18,12,2,'2026-04-08 18:20:20'),(19,2,13,'2026-04-08 18:20:20'),(20,13,2,'2026-04-08 18:20:20'),(21,2,11,'2026-04-13 22:06:48'),(22,11,2,'2026-04-13 22:06:48'),(23,14,12,'2026-04-28 11:23:51'),(24,12,14,'2026-04-28 11:23:51');
/*!40000 ALTER TABLE `friends` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `ip_attempts`
--

DROP TABLE IF EXISTS `ip_attempts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ip_attempts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(45) NOT NULL,
  `attempt_type` varchar(50) NOT NULL,
  `success` tinyint(1) DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_ip_attempts_ip_created` (`ip_address`,`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `ip_attempts`
--

LOCK TABLES `ip_attempts` WRITE;
/*!40000 ALTER TABLE `ip_attempts` DISABLE KEYS */;
/*!40000 ALTER TABLE `ip_attempts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `ip_blacklist`
--

DROP TABLE IF EXISTS `ip_blacklist`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ip_blacklist` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(45) NOT NULL,
  `blocked_until` datetime NOT NULL,
  `block_reason` varchar(255) DEFAULT NULL,
  `failed_attempts` int DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ip_address` (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `ip_blacklist`
--

LOCK TABLES `ip_blacklist` WRITE;
/*!40000 ALTER TABLE `ip_blacklist` DISABLE KEYS */;
/*!40000 ALTER TABLE `ip_blacklist` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `messages`
--

DROP TABLE IF EXISTS `messages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `messages` (
  `id` int NOT NULL AUTO_INCREMENT,
  `sender_id` int NOT NULL,
  `receiver_id` int NOT NULL,
  `content` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
  `file_type` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `file_path` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `timestamp` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `sender_id` (`sender_id`),
  KEY `receiver_id` (`receiver_id`),
  CONSTRAINT `messages_ibfk_1` FOREIGN KEY (`sender_id`) REFERENCES `users` (`id`),
  CONSTRAINT `messages_ibfk_2` FOREIGN KEY (`receiver_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=225 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `messages`
--

LOCK TABLES `messages` WRITE;
/*!40000 ALTER TABLE `messages` DISABLE KEYS */;
INSERT INTO `messages` VALUES (133,12,11,'你好',NULL,NULL,'2026-04-08 18:20:20'),(142,11,12,'你好',NULL,NULL,'2026-04-08 18:20:20'),(143,11,12,'你好',NULL,NULL,'2026-04-08 18:20:20'),(144,12,11,'这是一条测试消息',NULL,NULL,'2026-04-08 18:20:20'),(145,12,11,'李哥',NULL,NULL,'2026-04-08 21:23:08'),(146,11,12,'这是一条测试消息',NULL,NULL,'2026-04-13 22:15:27'),(147,12,11,'你妈',NULL,NULL,'2026-04-15 04:29:16'),(148,12,11,'你妈',NULL,NULL,'2026-04-15 04:29:16'),(150,12,11,'你妈',NULL,NULL,'2026-04-15 04:29:16'),(151,12,11,'你妈',NULL,NULL,'2026-04-15 04:29:16'),(154,11,12,'尼玛',NULL,NULL,'2026-04-15 04:29:16'),(155,11,12,'尼玛',NULL,NULL,'2026-04-15 04:29:16'),(156,11,12,'尼玛',NULL,NULL,'2026-04-15 04:29:16'),(157,12,11,'1',NULL,NULL,'2026-04-15 04:29:16'),(158,12,11,'1',NULL,NULL,'2026-04-15 04:29:16'),(159,12,11,'你好',NULL,NULL,'2026-04-15 04:45:13'),(162,13,12,'傻逼',NULL,NULL,'2026-04-15 05:01:38'),(163,12,11,'你好，这是',NULL,NULL,'2026-04-15 05:01:38'),(164,12,11,'niha o',NULL,NULL,'2026-04-17 20:49:35'),(165,11,12,'?',NULL,NULL,'2026-04-19 05:15:12'),(166,11,12,'唉',NULL,NULL,'2026-04-19 05:15:12'),(167,11,2,NULL,'audio','/static/uploads/60c26d70-5c51-4504-b541-dd074fb89674.flac','2026-04-19 05:15:12'),(168,11,12,'？',NULL,NULL,'2026-04-24 12:07:56'),(169,12,14,NULL,'image','/static/uploads/644e9eae-79e5-4ec9-bb92-090766f71125.png','2026-04-28 11:23:51'),(170,14,12,'hello',NULL,NULL,'2026-04-28 11:23:51'),(171,14,12,'Hello，大佬',NULL,NULL,'2026-04-28 11:23:51'),(172,12,14,'你好',NULL,NULL,'2026-04-28 11:23:51'),(173,14,12,NULL,'image','/static/uploads/d812f060-6375-4937-8006-b82bd829153b.png','2026-04-28 11:23:51'),(174,14,12,'图片和文字发送没什么问题',NULL,NULL,'2026-04-28 11:23:51'),(175,14,12,'附件是包括但不限于图片和文本吗？',NULL,NULL,'2026-04-28 11:23:51'),(176,12,14,NULL,'image','/static/uploads/1f8c7154-1e32-45e8-adb8-02632023540c.jpg','2026-04-28 11:23:51'),(177,12,14,'附件仅限于音频图片',NULL,NULL,'2026-04-28 11:23:51'),(178,14,12,'好的',NULL,NULL,'2026-04-28 11:23:51'),(179,12,14,'其它的没做',NULL,NULL,'2026-04-28 11:23:51'),(180,14,12,'管理员，倒是都行，看大佬你心情就好。只是我不一定会天天去，而且，这个，单对单聊天，管理能怎么管啊😂😂😂',NULL,NULL,'2026-04-28 11:23:51'),(181,14,12,'哦，说着玩啊',NULL,NULL,'2026-04-28 11:23:51'),(182,14,12,'那没事了',NULL,NULL,'2026-04-28 11:23:51'),(183,14,12,'hhh',NULL,NULL,'2026-04-28 11:23:51'),(184,12,14,'管理员给你了那还得了，哈哈',NULL,NULL,'2026-04-28 11:23:51'),(185,14,12,'hhh',NULL,NULL,'2026-04-28 11:23:51'),(186,14,12,'可不是嘛',NULL,NULL,'2026-04-28 11:23:51'),(187,12,14,'你发送音乐试试',NULL,NULL,'2026-04-28 11:23:51'),(188,12,14,'音乐接口好像真有有点儿问题',NULL,NULL,'2026-04-28 11:23:51'),(189,14,12,'我看看MP3能不能行，我找找',NULL,NULL,'2026-04-28 11:23:51'),(190,12,14,NULL,'audio','/static/uploads/516f446c-2813-442d-98c1-7bbc733a5a2b.mp3','2026-04-28 11:23:51'),(191,12,14,'666',NULL,NULL,'2026-04-28 11:23:51'),(192,14,12,NULL,'audio','/static/uploads/ff18a26a-a29a-441d-8ae8-9bae2fe335ae.mp3','2026-04-28 11:23:51'),(193,12,14,'没问题',NULL,NULL,'2026-04-28 11:23:51'),(194,14,12,'大佬你发过来的音频没有问题',NULL,NULL,'2026-04-28 11:23:51'),(195,12,14,NULL,'audio','/static/uploads/36d03ebf-4cdd-46cf-ac7f-af55f1cd83b5.flac','2026-04-28 11:23:51'),(196,14,12,'离别开出花，能播放',NULL,NULL,'2026-04-28 11:23:51'),(197,12,14,'没问题，刚刚是文件过大的原因',NULL,NULL,'2026-04-28 11:23:51'),(198,14,12,'but',NULL,NULL,'2026-04-28 11:23:51'),(199,14,12,'我好像发现了一个东西',NULL,NULL,'2026-04-28 11:23:51'),(200,12,14,'有问题就说',NULL,NULL,'2026-04-28 11:23:51'),(201,14,12,'本身没有，但是两个音乐文件点开能同时播放',NULL,NULL,'2026-04-28 11:23:51'),(202,12,14,'我毕竟是一个人测试，问题是无法全部排查出来的',NULL,NULL,'2026-04-28 11:23:51'),(203,12,14,'我没想到这方面',NULL,NULL,'2026-04-28 11:23:51'),(204,14,12,'大佬你预想的机制是本来就打算同时支持多个音频播放，还是点开第二个的时候，第一个音频文件自动暂停？',NULL,NULL,'2026-04-28 11:23:51'),(205,14,12,'hhh',NULL,NULL,'2026-04-28 11:23:51'),(206,14,12,'因为我的离谱操作，大佬你可以试着想想怎么安排多个音频播放的问题咯',NULL,NULL,'2026-04-28 11:23:51'),(207,12,14,'要得',NULL,NULL,'2026-04-28 11:23:51'),(208,12,14,'没有，我根本没想到这个，没有做这个处理',NULL,NULL,'2026-04-28 11:23:51'),(209,14,12,'大佬你的聊天记录排列是怎么布置的？',NULL,NULL,'2026-04-28 11:23:51'),(210,14,12,NULL,'image','/static/uploads/39da4692-d0ef-4660-8391-617b4df251d5.jpg','2026-04-28 11:23:51'),(211,14,12,NULL,'image','/static/uploads/3a05edd1-fba2-4f5c-b305-709d16ceed5b.jpg','2026-04-28 11:23:51'),(212,14,12,'退出会话，刷新，再进来新的消息在第一条消息前面显示',NULL,NULL,'2026-04-28 11:23:51'),(213,14,12,'进来的窗口界面又不在最新消息的地方',NULL,NULL,'2026-04-28 11:23:51'),(214,14,12,'我一度以为，我的网络出问题了，而且貌似的确还不够稳定',NULL,NULL,'2026-04-28 11:23:51'),(215,14,12,'选图片的机制，是点了就发送，没有预览，这点可能会导致误发送图片或者其他文件，建议加个预览或者确认的步骤',NULL,NULL,'2026-04-28 11:23:51'),(216,14,12,'通讯的管理和会话的管理界面是同一个，联系人少的时候还好，但是联系人多了可能会混乱，建议页面学习一下qq，联系人，会话，个人做三个页面，会比较方便管理',NULL,NULL,'2026-04-28 11:23:51'),(217,14,12,'对话的最新消息也不会在主界面显示，有一定隐私保护性，但也让信息显示不够直接',NULL,NULL,'2026-04-28 11:23:51'),(218,14,12,'目前就想到这些',NULL,NULL,'2026-04-28 11:23:51'),(219,14,12,'大佬你看之后要怎么平衡一下',NULL,NULL,'2026-04-28 11:23:51'),(220,14,12,'对了，联系人能分组吗？能加标签吗？',NULL,NULL,'2026-04-28 11:23:51'),(221,12,14,'你那边目前的接收有反应不',NULL,NULL,'2026-04-28 11:23:51'),(222,12,14,'如果聊天有的话，估计就是有关接口的原因了',NULL,NULL,'2026-04-28 11:23:51'),(223,12,14,'你上面问的问题我想过，但是需要加的接口会非常多',NULL,NULL,'2026-04-28 11:23:51'),(224,12,14,'数据库接口也出问题咯',NULL,NULL,'2026-04-28 11:23:51');
/*!40000 ALTER TABLE `messages` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_activities`
--

DROP TABLE IF EXISTS `user_activities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_activities` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `ip_address` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `action_type` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `action_detail` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
  `created_at` datetime NOT NULL,
  `user_agent` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `request_path` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `method` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `user_activities_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=49 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_activities`
--

LOCK TABLES `user_activities` WRITE;
/*!40000 ALTER TABLE `user_activities` DISABLE KEYS */;
INSERT INTO `user_activities` VALUES (1,1,'183.228.54.203','admin_access','访问管理员面板','2026-05-02 17:20:34',NULL,NULL,NULL),(2,1,'183.228.54.203','admin_access','访问管理员面板','2026-05-02 17:20:36',NULL,NULL,NULL),(3,1,'183.228.54.203','admin_access','访问管理员面板','2026-05-02 17:20:37',NULL,NULL,NULL),(4,1,'183.228.54.203','admin_access','访问导出页面','2026-05-02 17:20:38',NULL,NULL,NULL),(5,1,'183.228.54.203','admin_access','访问管理员面板','2026-05-02 17:20:39',NULL,NULL,NULL),(6,1,'183.228.54.203','admin_access','访问管理员面板','2026-05-02 17:20:40',NULL,NULL,NULL),(7,1,'183.228.54.203','admin_access','访问管理员面板','2026-05-02 17:20:41',NULL,NULL,NULL),(8,1,'183.228.54.203','admin_action','删除单条日志（ID: 4）','2026-05-02 17:20:46',NULL,NULL,NULL),(9,1,'183.228.54.203','admin_action','删除单条日志（ID: 1）','2026-05-02 17:20:49',NULL,NULL,NULL),(10,1,'183.228.54.203','admin_action','删除单条日志（ID: 1）','2026-05-02 17:20:56',NULL,NULL,NULL),(11,1,'183.228.54.203','admin_access','查看用户行为日志','2026-05-02 17:20:57',NULL,NULL,NULL),(12,1,'183.228.54.203','admin_action','删除单条日志（ID: 3）','2026-05-02 17:21:01',NULL,NULL,NULL),(13,1,'183.228.54.203','admin_action','删除单条日志（ID: 2）','2026-05-02 17:21:05',NULL,NULL,NULL),(14,1,'183.228.54.203','logout','用户主动登出','2026-05-02 17:21:09',NULL,NULL,NULL),(15,12,'183.228.54.203','login','登录成功，设备: Linux - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWeb...','2026-05-02 17:21:19',NULL,NULL,NULL),(16,12,'183.228.54.203','logout','用户主动登出','2026-05-02 17:22:04',NULL,NULL,NULL),(17,12,'183.228.54.203','login','登录成功，设备: Linux - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWeb...','2026-05-03 20:20:00',NULL,NULL,NULL),(18,12,'183.228.54.203','logout','用户主动登出','2026-05-03 20:20:05',NULL,NULL,NULL),(19,12,'183.228.54.203','login','登录成功，设备: Linux - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWeb...','2026-05-03 21:29:44',NULL,NULL,NULL),(20,1,'183.228.55.76','login','登录成功，设备: Linux - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWeb...','2026-05-09 13:04:55',NULL,NULL,NULL),(21,1,'183.228.55.76','admin_access','访问管理员面板','2026-05-09 13:04:55',NULL,NULL,NULL),(22,1,'183.228.55.76','logout','用户主动登出','2026-05-09 13:04:58',NULL,NULL,NULL),(23,12,'183.228.55.76','login','登录成功，设备: Linux - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWeb...','2026-05-09 13:30:25',NULL,NULL,NULL),(24,12,'183.228.55.76','logout','用户主动登出','2026-05-09 13:30:46',NULL,NULL,NULL),(25,12,'183.228.55.76','login','登录成功，设备: Linux - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWeb...','2026-05-09 13:52:27',NULL,NULL,NULL),(26,12,'183.228.55.76','logout','用户主动登出','2026-05-09 13:52:31',NULL,NULL,NULL),(27,16,'123.147.252.102','login','登录成功，设备: Linux - Mozilla/5.0 (Linux; Android 16; V2502A) AppleWebKi...','2026-05-11 15:34:36',NULL,NULL,NULL),(28,16,'123.147.252.102','logout','用户主动登出','2026-05-11 15:34:40',NULL,NULL,NULL),(29,1,'183.228.103.180','login','登录成功，设备: Linux - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWeb...','2026-05-22 20:29:37',NULL,NULL,NULL),(30,1,'183.228.103.180','admin_access','访问管理员面板','2026-05-22 20:29:37',NULL,NULL,NULL),(31,1,'183.228.103.180','admin_access','查看用户行为日志','2026-05-22 20:29:39',NULL,NULL,NULL),(32,1,'183.228.103.180','admin_access','访问管理员面板','2026-05-22 20:29:52',NULL,NULL,NULL),(33,1,'183.228.103.180','admin_action','用户admin的密码已修改','2026-05-22 20:30:07',NULL,NULL,NULL),(34,1,'183.228.103.180','login','登录成功，设备: Linux - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWeb...','2026-05-22 20:30:15',NULL,NULL,NULL),(35,1,'183.228.103.180','admin_access','访问管理员面板','2026-05-22 20:30:15',NULL,NULL,NULL),(36,1,'183.228.103.180','admin_access','访问管理员面板','2026-05-22 20:53:40',NULL,NULL,NULL),(37,1,'183.228.103.180','admin_access','查看用户行为日志','2026-05-22 20:54:05',NULL,NULL,NULL),(38,1,'183.228.103.180','admin_access','访问管理员面板','2026-05-22 20:54:06',NULL,NULL,NULL),(39,1,'183.228.103.180','admin_access','访问导出页面','2026-05-22 20:54:07',NULL,NULL,NULL),(40,1,'183.228.103.180','logout','用户主动登出','2026-05-22 20:54:12',NULL,NULL,NULL),(41,1,'123.147.249.171','login','登录成功，设备: Linux - Mozilla/5.0 (Linux; Android 16; V2502A) AppleWebKi...','2026-05-27 20:26:18',NULL,NULL,NULL),(42,1,'123.147.249.171','admin_access','访问管理员面板','2026-05-27 20:26:19',NULL,NULL,NULL),(43,1,'123.147.249.171','admin_access','查看用户行为日志','2026-05-27 20:26:21',NULL,NULL,NULL),(44,1,'123.147.249.171','admin_access','访问管理员面板','2026-05-27 20:26:28',NULL,NULL,NULL),(45,1,'183.228.55.64','login','登录成功，设备: Linux - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWeb...','2026-06-05 22:56:21',NULL,NULL,NULL),(46,1,'183.228.55.64','admin_access','访问管理员面板','2026-06-05 22:56:21',NULL,NULL,NULL),(47,1,'183.228.55.64','admin_access','查看用户 Zx 的聊天记录','2026-06-05 22:56:34',NULL,NULL,NULL),(48,1,'183.228.55.64','logout','用户主动登出','2026-06-05 22:56:39',NULL,NULL,NULL);
/*!40000 ALTER TABLE `user_activities` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `password` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `online` tinyint(1) DEFAULT NULL,
  `login_attempts` int DEFAULT NULL,
  `lock_time` datetime DEFAULT NULL,
  `verify_code` varchar(4) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `role` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_banned` tinyint(1) DEFAULT NULL,
  `is_muted` tinyint(1) DEFAULT NULL,
  `login_device` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `last_login_time` datetime DEFAULT NULL,
  `session_created_at` datetime DEFAULT NULL,
  `current_session_id` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `avatar` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email_verify_code` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email_verify_expire` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'admin','pbkdf2:sha256:600000$iOZDbbdONieUUTux$c5c27a40c1ffdf990ad8a07784dd6f5725d333c342c42c400efadbfe2594f0e2',0,0,NULL,NULL,'admin',0,0,'Linux - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWeb...','2026-06-05 22:56:21',NULL,NULL,NULL,NULL,NULL,NULL),(2,'5','pbkdf2:sha256:600000$c6hAIDOEKKmtqxzG$7779b65cd0368f47acb33ab54d0cb6ec1c3a81ea3c8387ed27730aaaf3d6376f',0,0,NULL,NULL,'user',0,0,'Linux - Mozilla/5.0 (Linux; Android 16; V2301A) AppleWebKi...','2026-04-08 18:32:51','2026-04-08 18:32:51','3faee729-c2dc-4886-a2ff-811a8cf3e1c7',NULL,NULL,NULL,NULL),(3,'6','pbkdf2:sha256:600000$ffznVpuVLsMgMCRg$3ba2b8d8c3f389e94f38035e3b5ddcde1de848aafc514153558399b0f44fc669',0,0,NULL,NULL,'user',0,0,'Linux - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWeb...','2026-04-08 18:00:15','2026-04-08 18:00:15','f0e57a71-027e-48c7-a740-a7577924493d',NULL,NULL,NULL,NULL),(4,'7','pbkdf2:sha256:600000$gtDKMqblBwRepY2c$74335ac721fe079bb62016e6abfec3e0863f89cbe10cf666dc4c1588658de98a',0,0,NULL,NULL,'user',0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(5,'8','pbkdf2:sha256:600000$J9R7pyGj0m9Q3vMN$e3fa16c6caaf9c6038d4fbac42fee67b935bcef060a0b100f05364e3dc908f8e',0,0,NULL,NULL,'user',0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(6,'16','pbkdf2:sha256:600000$L1HtYge4eP18tArc$da6056722ced8c9af13d86765bc2f696ef1067850f5d11deb26f504e6f25c7d1',0,0,NULL,NULL,'user',0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(7,'17','pbkdf2:sha256:600000$a4BNqaFldwyxYh62$3ad158e7a4823108d233f38fbea331305762e592fcd444ec95abdd299bf7d229',0,0,NULL,NULL,'user',0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(8,'18','pbkdf2:sha256:600000$TEFIt3GSPZOURsS9$b299f8f4392d63f66f404f80d806602ea8e35847d9a558b1705c224e41cc76b3',0,0,NULL,NULL,'user',0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(9,'19','pbkdf2:sha256:600000$NffClapnBrCJJViY$b754e4be102d6977a6fc4593a9c69d0d9c0ab8381962d7504b549bff5bd4bcb6',0,0,NULL,NULL,'user',0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(10,'20','pbkdf2:sha256:600000$uHgOUC3xa7mqGVey$fb2f50673198052072b9227542198fd724da73e771809cfece4283289220ec36',0,0,NULL,NULL,'user',0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(11,'LC','pbkdf2:sha256:600000$r2L9CL0YObAzaJK4$61216335171e7c59837517bebacc9156de1f89b8af074464406acad9be128b8e',0,0,NULL,NULL,'user',0,0,'Linux - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWeb...','2026-05-02 16:44:40','2026-05-02 16:44:40','17a369a4-2b32-49fd-98da-7e2b284be483','/static/uploads/b7b2f639-3687-4d7d-86f5-fe1442414795.jpg',NULL,NULL,NULL),(12,'LLH','pbkdf2:sha256:600000$tfXAH1thjE2R6udZ$08f286d97b09e13d2e57ab79f9cc8b137c1846f079710e2c20f69711c79b445f',0,0,NULL,NULL,'user',0,0,'Linux - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWeb...','2026-05-09 13:52:27',NULL,NULL,'/static/uploads/f5078435-8962-42da-8510-dd9fc7561171.jpg',NULL,NULL,NULL),(13,'Lyh','pbkdf2:sha256:600000$YqrLQWgvHNgilufb$d38ac81698b5676facdcd7eaccff361017ca5f98caa2dd3a8bdf118e7b7be930',0,0,NULL,NULL,'user',0,0,'Linux - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWeb...','2026-04-15 05:03:01',NULL,NULL,'/static/uploads/585f14c6-0ef0-49fa-ad3a-e839a5c3506b.jpg',NULL,NULL,NULL),(14,'渊','pbkdf2:sha256:600000$HiVaLQU6fN5s9dyj$172f65517bc3e1d3a18568e21e48840dd8b269903f66258a41988bfaed421874',0,0,NULL,NULL,'user',0,0,'Linux - Mozilla/5.0 (Linux; U; Android 11; zh-cn; Redmi K2...','2026-04-28 15:55:11',NULL,NULL,'/static/uploads/227f3e9e-ff73-40de-9565-87348170ed32.jpg','mow2022@163.com',NULL,NULL),(15,'PHLP_Neo','pbkdf2:sha256:600000$kdKqkRI1OuaIaSCy$df458be6d51dabbd5a8a74903f01c846a7a56d8ef10f430821ac038ff04cbe9e',0,0,NULL,NULL,'user',0,0,'Linux - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWeb...','2026-04-28 12:10:47',NULL,NULL,NULL,'phlp.neo@gmail.com',NULL,NULL),(16,'Zx','pbkdf2:sha256:600000$QD0BTfXeGqmz5bRb$03319548f208515818a8ae0b878cbdc9e139a0e1ce984f95f4f6471e0696f309',0,0,NULL,NULL,'user',0,0,'Linux - Mozilla/5.0 (Linux; Android 16; V2502A) AppleWebKi...','2026-05-11 15:34:36',NULL,NULL,NULL,'m13072397884@163.com',NULL,NULL);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `waf_logs`
--

DROP TABLE IF EXISTS `waf_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `waf_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(45) NOT NULL,
  `rule_type` varchar(50) NOT NULL,
  `severity` varchar(20) DEFAULT NULL,
  `request_path` varchar(255) DEFAULT NULL,
  `request_method` varchar(10) DEFAULT NULL,
  `request_data` text,
  `match_details` text,
  `blocked` tinyint(1) DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `waf_logs`
--

LOCK TABLES `waf_logs` WRITE;
/*!40000 ALTER TABLE `waf_logs` DISABLE KEYS */;
INSERT INTO `waf_logs` VALUES (1,'183.228.54.203','RFI','medium','/static/images/flow.jpg','GET','ImmutableMultiDict([])Host: www.ctalk.me\r\nX-Real-Ip: 183.228.54.203\r\nX-Forwarded-For: 183.228.54.203\r\nX-Forwarded-Proto: https\r\nConnection: close\r\nSec-Ch-Ua-Platform: \"Windows\"\r\nUser-Agent: Mozilla/5.','[\'(?i)https://\']',0,'2026-05-03 22:33:46'),(2,'183.228.54.203','RFI','medium','/static/images/备案图标.png','GET','ImmutableMultiDict([])Host: www.ctalk.me\r\nX-Real-Ip: 183.228.54.203\r\nX-Forwarded-For: 183.228.54.203\r\nX-Forwarded-Proto: https\r\nConnection: close\r\nSec-Ch-Ua-Platform: \"Windows\"\r\nUser-Agent: Mozilla/5.','[\'(?i)https://\']',0,'2026-05-03 22:33:46'),(3,'183.228.54.203','RFI','medium','/static/video/银河系.mp4','GET','ImmutableMultiDict([])Host: www.ctalk.me\r\nX-Real-Ip: 183.228.54.203\r\nX-Forwarded-For: 183.228.54.203\r\nX-Forwarded-Proto: https\r\nConnection: close\r\nSec-Ch-Ua-Platform: \"Windows\"\r\nAccept-Encoding: ident','[\'(?i)https://\']',0,'2026-05-03 22:33:46'),(4,'183.228.54.203','RFI','medium','/static/images/flow.jpg','GET','ImmutableMultiDict([])Host: www.ctalk.me\r\nX-Real-Ip: 183.228.54.203\r\nX-Forwarded-For: 183.228.54.203\r\nX-Forwarded-Proto: https\r\nConnection: close\r\nSec-Ch-Ua-Platform: \"Windows\"\r\nUser-Agent: Mozilla/5.','[\'(?i)https://\']',0,'2026-05-03 22:33:51'),(5,'183.228.54.203','RFI','medium','/static/images/备案图标.png','GET','ImmutableMultiDict([])Host: www.ctalk.me\r\nX-Real-Ip: 183.228.54.203\r\nX-Forwarded-For: 183.228.54.203\r\nX-Forwarded-Proto: https\r\nConnection: close\r\nSec-Ch-Ua-Platform: \"Windows\"\r\nUser-Agent: Mozilla/5.','[\'(?i)https://\']',0,'2026-05-03 22:33:51'),(6,'183.228.54.203','RFI','medium','/static/video/银河系.mp4','GET','ImmutableMultiDict([])Host: www.ctalk.me\r\nX-Real-Ip: 183.228.54.203\r\nX-Forwarded-For: 183.228.54.203\r\nX-Forwarded-Proto: https\r\nConnection: close\r\nSec-Ch-Ua-Platform: \"Windows\"\r\nAccept-Encoding: ident','[\'(?i)https://\']',0,'2026-05-03 22:33:51'),(7,'183.228.54.203','RFI','medium','/static/images/香香的熏.jpg','GET','ImmutableMultiDict([])Host: www.ctalk.me\r\nX-Real-Ip: 183.228.54.203\r\nX-Forwarded-For: 183.228.54.203\r\nX-Forwarded-Proto: https\r\nConnection: close\r\nSec-Ch-Ua-Platform: \"Windows\"\r\nUser-Agent: Mozilla/5.','[\'(?i)https://\']',0,'2026-05-03 22:33:51'),(8,'183.228.54.203','RFI','medium','/static/images/备案图标.png','GET','ImmutableMultiDict([])Host: www.ctalk.me\r\nX-Real-Ip: 183.228.54.203\r\nX-Forwarded-For: 183.228.54.203\r\nX-Forwarded-Proto: https\r\nConnection: close\r\nSec-Ch-Ua-Platform: \"Windows\"\r\nUser-Agent: Mozilla/5.','[\'(?i)https://\']',0,'2026-05-03 22:33:52'),(9,'183.228.54.203','RFI','medium','/static/images/flow.jpg','GET','ImmutableMultiDict([])Host: www.ctalk.me\r\nX-Real-Ip: 183.228.54.203\r\nX-Forwarded-For: 183.228.54.203\r\nX-Forwarded-Proto: https\r\nConnection: close\r\nSec-Ch-Ua-Platform: \"Windows\"\r\nUser-Agent: Mozilla/5.','[\'(?i)https://\']',0,'2026-05-03 22:33:52'),(10,'183.228.54.203','RFI','medium','/static/video/银河系.mp4','GET','ImmutableMultiDict([])Host: www.ctalk.me\r\nX-Real-Ip: 183.228.54.203\r\nX-Forwarded-For: 183.228.54.203\r\nX-Forwarded-Proto: https\r\nConnection: close\r\nSec-Ch-Ua-Platform: \"Windows\"\r\nAccept-Encoding: ident','[\'(?i)https://\']',0,'2026-05-03 22:33:52'),(11,'183.228.54.203','RFI','medium','/static/images/香香的熏.jpg','GET','ImmutableMultiDict([])Host: www.ctalk.me\r\nX-Real-Ip: 183.228.54.203\r\nX-Forwarded-For: 183.228.54.203\r\nX-Forwarded-Proto: https\r\nConnection: close\r\nSec-Ch-Ua-Platform: \"Windows\"\r\nUser-Agent: Mozilla/5.','[\'(?i)https://\']',0,'2026-05-03 22:33:52');
/*!40000 ALTER TABLE `waf_logs` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-06-16  3:52:09
