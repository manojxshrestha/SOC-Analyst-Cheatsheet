# 🟨 JAVASCRIPT DEOBFUSCATION

## SOC Analyst Cheatsheet - Module 11/15

---

## 0. Overview

> 📌 **JavaScript Deobfuscation** - Techniques to decode and understand obfuscated JavaScript code used by attackers.

### Module Description

This module covers the fundamentals of JavaScript Deobfuscation:
- Locating JavaScript code
- Understanding code obfuscation
- How to deobfuscate JavaScript code
- Decoding encoded messages
- Basic code analysis
- Sending basic HTTP requests

> 🔴 **Difficulty:** Easy | **Tier:** 0 | **Estimated Time:** 4 hours | **Cubes:** 10

### Prerequisites

- Web Requests module (understanding of HTTP requests)

### What We'll Cover

| Topic | Description |
|-------|-------------|
| **Introduction** | JavaScript basics, where to find JS code |
| **Obfuscation** | Basic and advanced obfuscation techniques |
| **Deobfuscation** | How to deobfuscate code |
| **Decoding** | Decode encoded messages |
| **Code Analysis** | Analyze deobfuscated code |
| **HTTP Requests** | Send/receive HTTP requests |

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Obfuscation](#2-obfuscation)
3. [Deobfuscation Examples](#3-deobfuscation-examples)
4. [Skills Assessment](#4-skills-assessment)

---

## 1. Introduction

> 📌 **JavaScript Deobfuscation** - An important skill for code analysis and reverse engineering. Used to understand obfuscated code that hides functionalities like malware retrieving payloads.

### Overview

Code deobfuscation is an important skill to learn if we want to be skilled in code analysis and reverse engineering. During red/blue team exercises, we often come across obfuscated code that wants to hide certain functionalities, like malware that utilizes obfuscated JavaScript code to retrieve its main payload. Without understanding what this code is doing, we may not know what exactly the code is doing, and hence may not be able to complete the red/blue team exercise.

In this module, we start by learning the general structure of an HTML page and then will locate JavaScript code within it. Once we do that, we will learn what obfuscation is, how it is done, and where it is used and follow that by learning how to deobfuscate such code. Once the code is deobfuscated, we will attempt to understand its general usage to replicate its functionality and uncover what it does manually.

### Topics Covered

| Topic | Description |
|-------|-------------|
| **Locating JavaScript code** | Find JS code in HTML pages |
| **Intro to Code Obfuscation** | What is obfuscation and why it's used |
| **How to Deobfuscate JavaScript code** | Techniques to reverse obfuscation |
| **How to decode encoded messages** | Decode Base64, hex, and other encodings |
| **Basic Code Analysis** | Analyze deobfuscated code |
| **Sending basic HTTP requests** | Replicate HTTP functionality |

---

### Locating JavaScript Code

JavaScript code can be found in:
- **`<script>` tags** - Inline JavaScript in HTML
- **External files** - `.js` files referenced in HTML (`<script src="file.js">`)
- **Inline in attributes** - Event handlers like `onclick`, `onload`
- **Browser DevTools** - Network tab, Console, Elements

### Introduction to Code Obfuscation

> 📌 **Obfuscation** - The process of making code difficult to understand or reverse engineer, while maintaining its functionality.

**Why is obfuscation used?**
| Reason | Description |
|--------|-------------|
| **Hide malicious code** | Evade security detection |
| **Evade AV/SIEM** | Signature-based detection bypass |
| **Protect IP** | Hide proprietary algorithms |
| **Reduce size** | Minification also obfuscates |

---

## 2. Obfuscation

### Overview

Most websites utilize JavaScript to perform their functions. While HTML determines the website's main fields and parameters, and CSS determines its design, JavaScript performs any functions necessary to run the website. This happens in the background, and we only see the pretty front-end.

Even though all of this source code is available at the client-side, it is rendered by browsers, so we do not often pay attention to the HTML source code. However, to understand a page's client-side functionalities, we start by viewing the page's source code.

### Viewing Source Code

**Method 1: Keyboard Shortcut**
- Press `CTRL + U` to view the source code

**Method 2: URL Prefix**
- Visit `view-source:http://example.com`

**Method 3: Browser DevTools**
- Press `F12` or `CTRL + SHIFT + I`
- Go to **Elements** tab

---

### HTML Structure

HTML source code can hold various information:
- Comments (`<!-- comment -->`)
- Hidden fields
- Sensitive information
- Reference to external scripts and styles

**Example HTML:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Secret Serial Generator</title>
</head>
<body>
    <h1>Secret Serial Generator</h1>
    <p>This page generates secret serials.</p>
</body>
</html>
```

> 📌 Always check HTML comments for hidden information left by developers.

---

### Locating CSS

CSS can be defined:
1. **Internally** - Within `<style>` tags in HTML
2. **Externally** - In separate `.css` file referenced with `<link>`

**Internal CSS:**
```html
<style>
    * {
        margin: 0;
        padding: 0;
    }
    h1 {
        font-size: 144px;
    }
</style>
```

**External CSS:**
```html
<head>
    <link rel="stylesheet" href="style.css">
</head>
```

---

### Locating JavaScript

JavaScript can be defined:
1. **Internally** - Within `<script>` tags
2. **Externally** - In separate `.js` file referenced with `<script src="file.js">`

**External JavaScript:**
```html
<script src="secret.js"></script>
```

---

### Code Obfuscation

Once we locate the JavaScript file, we may encounter obfuscated code:

```javascript
eval(function (p, a, c, k, e, d) { e = function (c) { '...SNIP... |true|function'.split('|'), 0, {})
```

> 📌 **Obfuscation** makes code difficult to understand while maintaining functionality.

---

### Types of Obfuscation

| Type | Description |
|------|-------------|
| **String Encoding** | Encoding strings (Base64, hex) |
| **Code Folding** | Collapsing functions |
| **Variable Renaming** | Changing `userName` to `a`, `b` |
| **Dead Code Injection** | Adding useless code |
| **Packing** | Using packers like jsmin, uglifyjs |

---

### Why Obfuscation?

| Use Case | Description |
|----------|-------------|
| **Malware** | Hide malicious functionality |
| **Phishing** | Hide credential harvesting code |
| **Evasion** | Bypass security tools |
| **IP Protection** | Hide proprietary code |
| **Size Reduction** | Minification |

---

### What is Obfuscation?

> 📌 **Obfuscation** is a technique used to make a script more difficult to read by humans but allows it to function the same from a technical point of view.

**How Obfuscation Works:**

Obfuscation tools take code as input and rewrite it in a way that is much more difficult to read. They often:
1. Convert code into a dictionary of words/symbols
2. Rebuild the original code during execution by referring to the dictionary
3. Encode strings, rename variables, add dead code

**Example of Obfuscation:**

![Obfuscation Example](https://github.com/user-attachments/assets/e48b73a3-733e-46e6-9b7d-813fd4ebbb21)

*JavaScript obfuscation tool interface*

> 🔴 **Reference:** https://beautifytools.com/javascript-obfuscator.php

---

### Why Obfuscation?

Languages like Python, PHP, and JavaScript are **interpreted languages**:
- **Python/PHP** - Server-side, hidden from users
- **JavaScript** - Client-side, sent to users in cleartext

This is why obfuscation is very commonly used with JavaScript.

---

### Use Cases

| Use Case | Description |
|----------|-------------|
| **Code Reuse Prevention** | Prevent code from being copied/reused |
| **Reverse Engineering Protection** | Make it difficult to understand functionality |
| **Client-Side Security** | Add security layer for authentication/encryption |
| **Malware Evasion** | Hide malicious scripts from IDS/IPS |

> 🔴 **Warning:** Client-side authentication/encryption is not recommended. Code is more prone to attacks.

---

### Obfuscation Tools

| Tool | Description | URL |
|------|-------------|-----|
| **JavaScript Obfuscator** | Online JS obfuscation | beautifytools.com |
| **jsfuck** | JSFuck encoding | jsfuck.com |
| **AAEncode** | Asian art encoding | https://... |
| **URL Encode/Decode** | URL encoding | Various online tools |

---

### Obfuscation vs Encryption

| Aspect | Obfuscation | Encryption |
|--------|-------------|------------|
| **Purpose** | Hide code readability | Hide data content |
| **Reversibility** | Usually reversible | Requires key to decrypt |
| **Security** | Low - can be decoded | High - requires key |
| **Use Case** | JavaScript code | Sensitive data |

---

## 3. Basic Obfuscation

> 📌 Code obfuscation is usually automated using tools. Many online tools exist, though malicious actors often develop custom obfuscation tools.

### Running JavaScript Code

**Example Code:**
```javascript
console.log('HTB JavaScript Deobfuscation Module');
```

**Testing in JSConsole:**
1. Visit https://jsconsole.com
2. Paste the code
3. Press Enter
4. See output: `HTB JavaScript Deobfuscation Module`

![JSConsole Test](https://github.com/user-attachments/assets/8177ff90-3e1f-4dd2-b1c8-3596f8ab79f5)

*Console output showing 'HTB JavaScript Deobfuscation Module'*

> 📌 The `console.log()` function prints output to the browser console.

---

### JavaScript Minification

> 📌 **Minification** - Reducing code to a single line while keeping it functional.

**Purpose:**
- Reduce file size
- Improve load time
- Reduce readability

**Tool:** https://javascript-minifier.com/

![Minification Example](https://github.com/user-attachments/assets/563667c4-f493-4c4d-94e3-6c025082937d)

*JavaScript minification tool showing input and minified output*

**Input:**
```javascript
console.log('HTB JavaScript Deobfuscation Module');
```

**Output (Minified):**
```javascript
console.log('HTB JavaScript Deobfuscation Module');
```

> 📌 Minified JavaScript files usually have `.min.js` extension.

---

### JavaScript Packing

**Tool:** https://beautifytools.com/javascript-obfuscator.php

![Packing Tool](https://github.com/user-attachments/assets/eeca25b8-2e8d-4ca7-a3b4-8ef6ccd3df32)

*JavaScript obfuscation tool with options*

**Original Code:**
```javascript
console.log('HTB JavaScript Deobfuscation Module');
```

**Packed Output:**
```javascript
eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\b'+e(c)+'\b','g'),k[c])}}return p}('5.4(\'3 2 1 0\');',6,6,'Module|Deobfuscation|JavaScript|HTB|log|console'.split('|'),0,{}))
```

**Verify in JSConsole:**

![Packed Code Test](https://github.com/user-attachments/assets/270a528b-34b9-4929-88b5-d3e89acd7b85)

*Obfuscated code running in JSConsole*

> 📌 The output remains the same after packing!

---

### How Packing Works

The packer obfuscation method:
1. Converts all words/symbols into a dictionary
2. Uses `(p,a,c,k,e,d)` function to rebuild code during execution
3. Recognizable by the six function arguments

**Typical Pattern:**
```javascript
eval(function(p,a,c,k,e,d){ ... })
```

> 🔴 **Note:** Strings may still be visible in cleartext within packed code, revealing some functionality.

---

### Advanced Obfuscation

> 📌 For better obfuscation, consider:
- **String encoding** (Base64, hex)
- **Multiple layers of packing**
- **Custom obfuscation tools**

---

## 4. Advanced Obfuscation

> 📌 Basic obfuscation still leaves some strings visible. Advanced obfuscation completely hides the code's functionality.

### Using obfuscator.io

**Tool:** https://obfuscator.io

**Configuration:**
1. Set **String Array Encoding** to **Base64**
2. Enable **Compact Code**
3. Enable **String Array**

![Obfuscator.io Settings](https://github.com/user-attachments/assets/d40edffb-592b-4820-bfc0-ae09224d65e2)

*JavaScript obfuscation tool with Base64 encoding option*

**Original Code:**
```javascript
console.log('HTB JavaScript Deobfuscation Module');
```

**Advanced Obfuscated Output:**
```javascript
var _0x1ec6=['Bg9N','sfrciePHDMfty3jPChqGrgvVyMz1C2nHDgLVBIbnB2r1Bgu='];(function(_0x13249d,_0x1ec6e5){var _0x14f83b=function(_0x3f720f){while(--_0x3f720f){_0x13249d['push'](_0x13249d['shift']());}};_0x14f83b(++_0x1ec6e5);}(_0x1ec6,0xb4));var _0x14f8=function(_0x13249d,_0x1ec6e5){_0x13249d=_0x13249d-0x0;var _0x14f83b=_0x1ec6[_0x13249d];if(_0x14f8['eOTqeL']===undefined){...};console[_0x14f8('0x0')](_0x14f8('0x1'));
```

![Obfuscator Input](https://github.com/user-attachments/assets/a4048165-c0da-4b13-b7b0-d9987af6ed35)

*JavaScript code input area with 'Obfuscate' button*

> 📌 This code is completely obfuscated with no cleartext remnants!

---

### JSFuck Encoding

**Example JSFuck code:**
```javascript
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][(...SNIP...)]()) 
```

> 🔴 This code still outputs `HTB JavaScript Deobfuscation Module` when executed!

**Example Output:**

![JSFuck Output](https://github.com/user-attachments/assets/f1bf37ad-6fc1-4236-bee6-554dc29686bc)

*Obfuscated code running in JSConsole*

---

### Other Obfuscation Tools

| Tool | Description | URL |
|------|-------------|-----|
| **JJEncode** | JJEncode obfuscation | Various online tools |
| **AAEncode** | Asian art encoding | Various online tools |
| **JSFuck** | Using only 6 characters | jsfuck.com |

> 🔴 **Warning:** These tools make code execution very slow. Use only for bypassing web filters.

---

### Performance Impact

> 📌 **Note:** Obfuscated code takes longer to execute due to the decoding process during runtime.

---

## 3. Deobfuscation Examples

*Coming soon...*

---

## 4. Skills Assessment

*Coming soon...*

---

*Module 11/15 - JavaScript Deobfuscation*
*For learning and SOC career preparation*
