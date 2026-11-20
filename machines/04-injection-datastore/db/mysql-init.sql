-- WSTG-INJT-05 (05.2 MySQL) seed data. Synthetic training data only.
USE shop;

CREATE TABLE IF NOT EXISTS products (
  id INT PRIMARY KEY,
  name VARCHAR(100),
  price DECIMAL(10,2)
);
INSERT INTO products VALUES
  (1,'Widget',9.99),(2,'Gadget',19.99),(3,'Gizmo',4.50),(4,'Doohickey',12.00);

CREATE TABLE IF NOT EXISTS vault (
  id INT PRIMARY KEY,
  secret VARCHAR(200)
);
INSERT INTO vault VALUES (1,'WSTG-M04{mysql_union_blind_stacked}');

CREATE TABLE IF NOT EXISTS audit (
  id INT AUTO_INCREMENT PRIMARY KEY,
  note VARCHAR(200)
);

-- The web app account gets FILE so the LOAD_FILE() variant is demonstrable.
GRANT FILE ON *.* TO 'webapp'@'%';
FLUSH PRIVILEGES;