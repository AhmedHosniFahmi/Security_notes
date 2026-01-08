### Content

- [Overview](#overview)
	- [Types of SQL Injections](#types-of-sql-injections)
- [SQLi Discovery](#sqli-discovery)
- [Comments](#comments)
- [Union Injections](#union-injections)
	- [Detect number of columns](#detect-number-of-columns)
		- [Using ORDER BY](#using-order-by)
		- [Using UNION](#using-union)
- [Mitigations](#mitigations)
	- [Input Sanitization](#input-sanitization)
	- [Input Validation](#input-validation)
	- [Parameterized Queries](#parameterized-queries)
	- [User Privileges](#user-privileges)
	- [Web Application Firewall](#web-application-firewall)

> [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass)

---
### Overview

- Cause: Occurs when user-input is inputted into the SQL query string without properly sanitizing or filtering the input.

A vulnerable code may look like the following:

`searchInput` would be inputted to complete the query, returning the expected outcome. Any input we type goes into the following SQL query:

```PHP
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

If we input `SHOW DATABASES;`, it would be executed as `'%SHOW DATABASES;'` The web application will search for usernames similar to `SHOW DATABASES;`.
As there is no sanitization, **we can add a single quote (`'`), which will end the user-input field, and after it, we can write actual SQL code**. For example, if we search for `1'; DROP TABLE users; --`, the search input would be:

```SQL
select * from logins where username like '%1'; DROP TABLE users; --'
```

 Once the query is run, the `users` table will get deleted.
 
###### Types of SQL Injections

<div style="display: flex; justify-content: center; align-items: center;"><img src="/assets/sql_injections_types.png" style="width:70%; length:60;"></div>

- **In-band SQL Injection**  
    In-band techniques are the most straightforward type of SQL injection. The attacker uses the same communication channel to both send the malicious query and receive the results. The database output is directly reflected in the application’s response, making the data easy to read.
    1. **Union-Based**  
        This technique uses the `UNION` SQL operator to append the results of a malicious query to the original query. To succeed, the attacker must identify the correct number of columns and compatible data types so the database places the injected results into visible columns on the page.
    2. **Error-Based**  
        Error-based injection relies on database or application errors being displayed on the front end. By intentionally triggering SQL errors, the attacker can force the database to include valuable information—such as table names, column names, or query results—inside the error messages returned to the user.
- **Blind SQL Injection**  
    Blind SQL injection is used when the application does not display database output or error messages. Instead of directly seeing results, the attacker infers information by observing changes in the application’s behavior.
    1. **Boolean-Based**  
        This method uses conditional SQL expressions that evaluate to true or false. If the condition is true, the application behaves normally; if false, the response changes (e.g., empty page, different message). By testing conditions one by one, the attacker can extract data bit by bit.
    2. **Time-Based**  
        Time-based injection also relies on conditional logic but measures response delays instead of page content. If a condition is true, the database executes a delay function such as `SLEEP()`. By analyzing response times, the attacker can deduce whether each condition is true or false.
- **Out-of-Band SQL Injection**  
    Out-of-band techniques are used when no query output is visible and timing or boolean inference is impractical. In this case, the attacker forces the database to send data to an external system under their control, such as via DNS or HTTP requests, and then retrieves the data from that external channel.

---
### SQLi Discovery

If the web application authentication function is wrote like the next snippet:

```PHP
$statement = "SELECT * FROM logins WHERE username = '$username' AND password = '$password'";
$query = $connection -> query($statement);
$users = $query -> fetchAll(PDO::FETCH_ASSOC);
```

Try to add one of the below payloads after our username and see if it causes any errors or changes how the page behaves:

- `'` -> `%27`
- `"` -> `%22`
- `#` -> `%23`
- `;` -> `%3B`
- `)` -> `%29`

The payload on the username field should be: `Admin' OR 1=1`

<div style="display: flex; justify-content: center; align-items: center;"><img src="/assets/sql_injections_operation_precedence.png" style="width:70%; length:60;"></div>

The whole query will return true and we will pass the authentication if the user `admin` exists.

---
### Comments

> [!Important]
> Note: In SQL, using two dashes only is not enough to start a comment. So, there has to be an empty space after them, so the comment starts with (-- ), with a space at the end. This is sometimes URL encoded as (--+), as spaces in URLs are encoded as (+). To make it clear, we will add another (-) at the end (-- -), to show the use of a space character.

We can use two types of line comments with MySQL `--` and `#`, in addition to an in-line comment `/**/` (though this is not usually used in SQL injections). The `--` can be used as follows:

```SQL
SELECT username FROM logins; -- Selects usernames from the logins table 
```

---
### Union Injections

 - The data types of the selected columns on all positions should be the same.
- Operate on SELECT statements with an equal number of columns.
- If the two table have un-even columns number, we can put junk data for the remaining required columns so that the total number of columns we are `UNIONing` with remains the same as the original query.
	- When filling other columns with junk data, we must ensure that the data type matches the columns data type, we can simply put `'NULL'` , as `'NULL'` fits all data types.

```SQL
-- The main query
SELECT * FROM products WHERE product_id = 'user_input'

-- The subverted one
SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '

-- If we don't know the number of the columns in the main table
SELECT * from products where product_id = '1' UNION SELECT username, 2 from passwords

SELECT * from products where product_id UNION SELECT username, 2, 3, 4 from passwords-- '
```

##### Detect number of columns

There are two methods of detecting the number of columns:

- Using `ORDER BY`
- Using `UNION`

###### Using ORDER BY

```SQL
SELECT * from products where product_id = '1' order by 3-- -
```

We have to inject a query that sorts the results by a column we specified, 'i.e., column 1, column 2, and so on', until we get an error saying the column specified does not exist.

For example, we can start with `order by 1`, sort by the first column, and succeed, as the table must have at least one column. Then we will do `order by 2` and then `order by 3` until:

- **Reach a number that returns an error**
- **The page does not show any output**

which means that this column number does not exist. The final successful column we successfully sorted by gives us the total number of columns. If we failed at `order by 4`, this means the table has three columns, which is the number of columns we were able to sort by successfully.

###### Using UNION

This method always gives an error until we get a success. We can start by injecting a 3 column `UNION` query:

```SQL
SELECT * from products where product_id = '1' UNION select 1,2,3-- -
```

---
### Mitigations

#### Input Sanitization

Snippet of a vulnerable code:

```PHP
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM logins WHERE username='". $username. "' AND password = '" . $password . "';" ;
echo "Executing query: " . $query . "<br /><br />";
```

Taking the `username` and `password` from the POST request and passes it to the query directly will let an attacker inject anything they wish and exploit the application.

Injection can be avoided by sanitizing any user input, rendering injected queries useless. Libraries provide multiple functions to achieve this, one such examples:

- [mysqli_real_escape_string()](https://www.php.net/manual/en/mysqli.real-escape-string.php) for MySQL queries. (Escapes `'` and `"`)
- [pg_escape_string()](https://www.php.net/manual/en/function.pg-escape-string.php) for PostgreSQL queries. 

```SQL
$username = mysqli_real_escape_string($conn, $_POST['username']);
$password = mysqli_real_escape_string($conn, $_POST['password']);

$query = "SELECT * FROM logins WHERE username='". $username. "' AND password = '" . $password . "';" ;
echo "Executing query: " . $query . "<br /><br />";
```

#### Input Validation

User input can also be validated based on the data used to query to ensure that it matches the expected input.

Snippet of a vulnerable code:

```php
<?php
if (isset($_GET["port_code"])) {
	$q = "Select * from ports where port_code ilike '%" . $_GET["port_code"] . "%'";
	$result = pg_query($conn,$q);
    
	if (!$result)
	{
   		die("</table></div><p style='font-size: 15px;'>" . pg_last_error($conn). "</p>");
	}
<SNIP>
?>
```

This code is vulnerable to union injections.
If we known that a port code consists only of letters or spaces, we can restrict the user input to only these characters, using a regular expression for validating the input:

```PHP
<SNIP>
$pattern = "/^[A-Za-z\s]+$/";
$code = $_GET["port_code"];

if(!preg_match($pattern, $code)) {
  die("</table></div><p style='font-size: 15px;'>Invalid input! Please try again.</p>");
}

$q = "Select * from ports where port_code ilike '%" . $code . "%'";
<SNIP>
```

The code is modified to use the [preg_match()](https://www.php.net/manual/en/function.preg-match.php) function, which checks if the input matches the given pattern or not. The pattern used is `[A-Za-z\s]+`, which will only match strings containing letters and spaces. Any other character will result in the termination of the script.

#### Parameterized Queries

To ensure that the input is safely sanitized is by using parameterized queries. Parameterized queries contain placeholders for the input data, which is then escaped and passed on by the drivers. Instead of directly passing the data into the SQL query, we use placeholders and then fill them with PHP functions.

[mysqli_stmt_bind_param()](https://www.php.net/manual/en/mysqli-stmt.bind-param.php)

```PHP
$username = $_POST['username'];
$password = $_POST['password'];

// The query is modified to contain two placeholders, marked with `?` where the username and password will be placed.
$query = "SELECT * FROM logins WHERE username=? AND password = ?" ;
$stmt = mysqli_prepare($conn, $query);
// Bind the username and password to the query using the mysqli_stmt_bind_param() function. 
mysqli_stmt_bind_param($stmt, 'ss', $username, $password);
// This will safely escape any quotes and place the values in the query.
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

$row = mysqli_fetch_array($result);
mysqli_stmt_close($stmt);
```

#### User Privileges

- Ensure that the user querying the database only has minimum permissions.
- Superusers and users with administrative privileges should never be used with web applications, because these accounts have access to functions and features, which could lead to server compromise.

Create a new user with limited permissions `SELECT ONLY` on a specific DB on a specific table:

```SQL
MariaDB [(none)]> CREATE USER 'reader'@'localhost';
MariaDB [(none)]> GRANT SELECT ON ilfreight.ports TO 'reader'@'localhost' IDENTIFIED BY 'p@ssw0Rd!!';
```

#### Web Application Firewall

WAFs can be open-source (`ModSecurity`) or premium (`Cloudflare`). Most of them have default rules configured based on common web attacks. For example, any request containing the string `INFORMATION_SCHEMA` would be rejected, as it's commonly used while exploiting SQL injection.

---