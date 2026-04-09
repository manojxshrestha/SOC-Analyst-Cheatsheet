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

## 3. Deobfuscation Examples

*Coming soon...*

---

## 4. Skills Assessment

*Coming soon...*

---

*Module 11/15 - JavaScript Deobfuscation*
*For learning and SOC career preparation*
