-- MySQL dump 10.13  Distrib 8.4.5, for macos15 (arm64)
--
-- Host: 127.0.0.1    Database: ispdp
-- ------------------------------------------------------
-- Server version	8.4.5

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
-- Dumping data for table `email_verification_codes`
--

LOCK TABLES `email_verification_codes` WRITE;
/*!40000 ALTER TABLE `email_verification_codes` DISABLE KEYS */;
/*!40000 ALTER TABLE `email_verification_codes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping data for table `login_challenges`
--

LOCK TABLES `login_challenges` WRITE;
/*!40000 ALTER TABLE `login_challenges` DISABLE KEYS */;
INSERT INTO `login_challenges` VALUES (4,3,'e1affc0a1a79111ec77e46a62465452f98b9149e01a2f074f60de8d4e6ef896d','2026-04-26 09:12:26',1,'2026-04-26 01:07:25');
/*!40000 ALTER TABLE `login_challenges` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping data for table `order_items`
--

LOCK TABLES `order_items` WRITE;
/*!40000 ALTER TABLE `order_items` DISABLE KEYS */;
INSERT INTO `order_items` VALUES (1,1,6,'课程实验商城模板',199.00,1,199.00,'2026-04-26 01:08:41');
/*!40000 ALTER TABLE `order_items` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping data for table `orders`
--

LOCK TABLES `orders` WRITE;
/*!40000 ALTER TABLE `orders` DISABLE KEYS */;
INSERT INTO `orders` VALUES (1,3,'ORD1777165721953339',199.00,'交易成功-待发货','杨雨飞','15704257909','哈尔滨工业大学一校区','1111','2026-04-26 01:08:41','2026-04-26 01:08:48');
/*!40000 ALTER TABLE `orders` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping data for table `products`
--

LOCK TABLES `products` WRITE;
/*!40000 ALTER TABLE `products` DISABLE KEYS */;
INSERT INTO `products` VALUES (1,'安全支付U盾 Pro','认证设备',299.00,32,'面向高安全场景的 USB 认证设备，支持私钥隔离存储与双因子登录演示。','热销','2026-04-26 01:05:16'),(2,'企业加密网关 Lite','网络安全',899.00,15,'适用于中小型系统的加密接入网关，可用于 HTTPS 接入与传输层策略控制。','新品','2026-04-26 01:05:16'),(3,'签名密钥备份盒','密钥管理',459.00,24,'离线备份 RSA 私钥与恢复材料的教学演示设备，适合课程展示。','恢复方案','2026-04-26 01:05:16'),(4,'认证日志审计屏','审计监控',699.00,18,'对登录、验签、支付确认等关键行为进行可视化审计的教学面板。','推荐','2026-04-26 01:05:16'),(5,'虚拟银行接口沙箱包','支付接口',1299.00,10,'用于模拟电子商务平台与虚拟银行交互的接口套件，便于后续联调。','接口预留','2026-04-26 01:05:16'),(6,'课程实验商城模板','教学资源',199.00,49,'集成商品列表、购物车、订单确认与模拟付款确认的课程展示模板。','演示版','2026-04-26 01:05:16');
/*!40000 ALTER TABLE `products` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (3,'yyf','$argon2id$v=19$m=19456,t=2,p=1$vhsDQMCzcFbmE8+OUtK9Jg$Q7BxVsffLjasQKGnI5dAeb5+N896mW5J+gJ9RrV9Vzs','2026-04-19 03:27:03','-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA69RO9kNm3MhTDNo9rToq\nBOssvrl9ju6bkYzNlQcKLcSu8Mup6iybty2DLQ6SgMVuh1soVQsjvsvTXU18iZmB\nNXa9gTMqH+NXrCzGAD/T9Q2US5Et4kVcexGMLoWd/Y5dYuyNVAZ3wUzb/H7xsY/Y\nV1bBElGCSzQUsnqJ1Bt1coqz1la4qX7EtVFJVTyXS6WQiXYzmyBcfJZLH3iqyrrq\nm0UPvyBF16gpIk2K0IPZ2p6xuaquvuaCaoby9WMYc3oiHQwATDsSFSaLY+bkcp8E\n6iPoKK0nsa+6a+kBmQlRQm2tUpHI9I9egV7t787N+glTXa3cycmRByTGZVng4/E3\npQIDAQAB\n-----END PUBLIC KEY-----','1447807745@qq.com',1);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-04-26 11:18:57
