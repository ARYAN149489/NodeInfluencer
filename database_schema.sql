CREATE DATABASE IF NOT EXISTS NodeInfluencer;
USE NodeInfluencer;

CREATE TABLE `users` (
  `email` varchar(100) NOT NULL,
  `pwd` varchar(255) NOT NULL,
  `utype` varchar(20) NOT NULL,
  `status` int DEFAULT '1',
  PRIMARY KEY (`email`)
);

CREATE TABLE `infprofile` (
  `email` varchar(100) NOT NULL,
  `iname` varchar(100) DEFAULT NULL,
  `gender` varchar(10) DEFAULT NULL,
  `dob` date DEFAULT NULL,
  `address` varchar(255) DEFAULT NULL,
  `city` varchar(100) DEFAULT NULL,
  `contact` varchar(20) DEFAULT NULL,
  `field` varchar(255) DEFAULT NULL,
  `insta` varchar(100) DEFAULT NULL,
  `yt` varchar(100) DEFAULT NULL,
  `other` text,
  `fileName` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`email`)
);

CREATE TABLE `coprofile` (
  `email` varchar(100) NOT NULL,
  `iname` varchar(100) DEFAULT NULL,
  `gender` varchar(10) DEFAULT NULL,
  `dob` date DEFAULT NULL,
  `address` varchar(255) DEFAULT NULL,
  `city` varchar(100) DEFAULT NULL,
  `contact` varchar(20) DEFAULT NULL,
  `insta` varchar(100) DEFAULT NULL,
  `fileName` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`email`)
);


CREATE TABLE `events` (
  `rid` int NOT NULL AUTO_INCREMENT,
  `pemail` varchar(100) NOT NULL,
  `ename` varchar(200) DEFAULT NULL,
  `datee` date DEFAULT NULL,
  `timing` time DEFAULT NULL,
  `city` varchar(100) DEFAULT NULL,
  `venue` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`rid`)
);