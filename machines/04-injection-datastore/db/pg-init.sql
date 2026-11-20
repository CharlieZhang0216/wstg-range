-- WSTG-INJT-05 (05.4 PostgreSQL + 05.1 Oracle PL/SQL-gateway facade) seed.
-- Synthetic training data only.

-- Non-superuser app role: COPY ... TO PROGRAM escalation is discussed in the
-- README but is deliberately NOT available to this role.
CREATE ROLE webapp LOGIN PASSWORD 'webapppass' NOSUPERUSER;

CREATE TABLE items (id INT PRIMARY KEY, name TEXT);
INSERT INTO items VALUES (1,'alpha'),(2,'beta'),(3,'gamma');

CREATE TABLE vault (id INT PRIMARY KEY, secret TEXT);
INSERT INTO vault VALUES (1,'WSTG-M04{pg_concat_union_sleep}');

-- "Oracle" side: the mod_plsql-style gateway (see app /pls/...) executes the
-- WEB_USERS package procedures against these tables.
CREATE TABLE web_users (user_id INT PRIMARY KEY, username TEXT, email TEXT);
INSERT INTO web_users VALUES
  (1,'alice','alice@lab.local'),(2,'bob','bob@lab.local'),(3,'admin','admin@lab.local');
CREATE TABLE ora_vault (id INT PRIMARY KEY, secret TEXT);
INSERT INTO ora_vault VALUES (1,'WSTG-M04{plsql_gateway_injection}');

GRANT CONNECT ON DATABASE webapp TO webapp;
GRANT USAGE ON SCHEMA public TO webapp;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO webapp;

-- Separate database for the SQLAlchemy ORM endpoints (05.7).
CREATE DATABASE ormdb;
\c ormdb
CREATE TABLE orm_users (id INT PRIMARY KEY, username TEXT, role TEXT);
-- id order != alphabetical order, so ORDER BY injection is observable
INSERT INTO orm_users VALUES (1,'zoe','user'),(2,'alice','user'),(3,'bob','manager');
CREATE TABLE orm_vault (id INT PRIMARY KEY, secret TEXT);
INSERT INTO orm_vault VALUES (1,'WSTG-M04{orm_rawsql_orderby}');
GRANT CONNECT ON DATABASE ormdb TO webapp;
GRANT USAGE ON SCHEMA public TO webapp;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO webapp;