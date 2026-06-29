# ScalerKart CTF - Vulnerability Writeups

**Student ID:** `23bcs10087` (Based on the environment setup)

---

## Writeup 1: Hidden Inventory — SQL Injection

**Vulnerability Title:**  
UNION-Based SQL Injection in Product Search

**Description:**  
The product search feature is vulnerable to SQL Injection because user input from the search bar is directly inserted into the SQL query without proper parameterization. By injecting a `UNION SELECT` payload, it is possible to make the database return data from another table that normal customers should not be able to access.

**Steps to Reproduce:**  
1. Login as `customer1`.
2. Go to the Products page.
3. In the search bar, enter:

```sql
' UNION SELECT id,recovery_code,0,username FROM sellers--
```

4. Submit the search.
5. The search results reveal seller recovery-code data instead of only product data.
6. The leaderboard/flag status updates as solved.

**Proof of Concept:**
![SQL Injection PoC](./ss/1.png)

**Impact:**  
An attacker can read sensitive database records, such as seller recovery codes or other hidden data. In a real application, this could lead to account compromise and data leakage.

**Remediation:**  
Use parameterized SQL queries/prepared statements. Never concatenate user-controlled input directly into SQL. Also restrict database permissions so the application user cannot read unrelated sensitive tables.

**CVSS Score:**  
`6.5 Medium`  
Vector: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

---

## Writeup 2: Supplier Upload — XXE via SVG

**Vulnerability Title:**  
XML External Entity Injection in SVG Upload

**Description:**  
The seller image upload accepts SVG files. Since SVG is XML, a malicious SVG can define an external entity that points to a local server file. The server parses the SVG with entity resolution enabled, causing the contents of the local file to be included in the parsed result.

**Steps to Reproduce:**  
1. Login as `seller1`.
2. Go to Seller Dashboard.
3. Create an SVG file with this content:

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///app/data/canary_xxe.txt">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <title>&xxe;</title>
</svg>
```

4. Upload the SVG using the product image upload feature.
5. The application displays the file content as the image caption.
6. The leaderboard/flag status updates as solved.

**Proof of Concept:**
![XXE PoC](./ss/5.png)

**Impact:**  
An attacker can read sensitive files from the server filesystem. In a real system, this could expose secrets, credentials, configuration files, or internal tokens.

**Remediation:**  
Disable external entity resolution when parsing XML. Use a secure XML parser configuration such as `resolve_entities=False`, `load_dtd=False`, and block local/network entity access. Validate uploaded files and avoid parsing untrusted SVG/XML where possible.

**CVSS Score:**  
`7.1 High`  
Vector: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L`

---

## Writeup 3: Label Printer — Command Injection

**Vulnerability Title:**  
Command Injection in Shipping Label Generator

**Description:**  
The shipping label feature passes the recipient name into a shell command. Because the input is not safely escaped and the command is executed through a shell, an attacker can break out of the intended command and append their own command.

**Steps to Reproduce:**  
1. Login as `customer1`.
2. Add a product to cart and complete checkout.
3. Go to the Orders page.
4. In the shipping label recipient name field, enter:

```bash
test'; id; echo '
```

5. Click **Print**.
6. Click **Check Status**.
7. The command output appears in the label status response.
8. The leaderboard/flag status updates as solved.

**Proof of Concept:**
![Command Injection PoC](./ss/6.png)

**Impact:**  
This can allow remote command execution on the server. An attacker may read files, execute system commands, access environment variables, or potentially take full control of the application container.

**Remediation:**  
Do not use shell execution with untrusted input. Replace shell commands with safe argument arrays, for example:

```python
subprocess.run(["label-printer", recipient_name, "--order", str(order_id)])
```

Also validate recipient names using an allowlist of safe characters.

**CVSS Score:**  
`8.8 High`  
Vector: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`

---

## Writeup 4: Zero Checkout — Business Logic Vulnerability

**Vulnerability Title:**  
Negative Quantity Business Logic Flaw in Checkout

**Description:**  
The cart update feature accepts negative quantity values. The checkout logic calculates the final total using the submitted quantity without enforcing that quantities must be positive. This allows a customer to create an order with a zero or negative total.

**Steps to Reproduce:**  
1. Login as `customer1`.
2. Add products to the cart.
3. Intercept or modify the cart update request.
4. Set one product quantity to a negative value, for example:

```json
{"product_id":2,"quantity":-1}
```

5. Submit the cart update.
6. Proceed to checkout.
7. The order is created with a final total of zero or less.
8. The leaderboard/flag status updates as solved.

**Proof of Concept:**
![Business Logic PoC](./ss/11.png)

**Impact:**  
An attacker can purchase products for free or create negative-value orders. In a real e-commerce application, this could cause direct financial loss, accounting issues, and abuse of fulfillment systems.

**Remediation:**  
Perform strict server-side validation on quantity values. Only allow positive integers within a reasonable range, for example `1 <= quantity <= 99`. Recalculate totals server-side and reject checkout if the total is zero or negative.

**CVSS Score:**  
`6.5 Medium`  
Vector: `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`
