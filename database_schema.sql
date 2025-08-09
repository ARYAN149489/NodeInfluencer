-- database_schema.sql - UPDATED FOR POSTGRESQL
CREATE TABLE users (
  email VARCHAR(100) PRIMARY KEY,
  pwd VARCHAR(255) NOT NULL,
  utype VARCHAR(20) NOT NULL,
  status INT DEFAULT 1
);

CREATE TABLE infprofile (
  email VARCHAR(100) PRIMARY KEY,
  iname VARCHAR(100),
  gender VARCHAR(10),
  dob DATE,
  address VARCHAR(255),
  city VARCHAR(100),
  contact VARCHAR(20),
  field VARCHAR(255),
  insta VARCHAR(100),
  yt VARCHAR(100),
  other TEXT,
  "fileName" VARCHAR(255)
);

CREATE TABLE coprofile (
  email VARCHAR(100) PRIMARY KEY,
  iname VARCHAR(100),
  gender VARCHAR(10),
  dob DATE,
  address VARCHAR(255),
  city VARCHAR(100),
  contact VARCHAR(20),
  insta VARCHAR(100),
  "fileName" VARCHAR(255)
);

CREATE TABLE events (
  rid SERIAL PRIMARY KEY, -- SERIAL is PostgreSQL's auto-incrementing integer
  pemail VARCHAR(100) NOT NULL,
  ename VARCHAR(200),
  datee DATE,
  timing TIME,
  city VARCHAR(100),
  venue VARCHAR(255)
);