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

*Coming soon...*

---

## 3. Deobfuscation Examples

*Coming soon...*

---

## 4. Skills Assessment

*Coming soon...*

---

*Module 11/15 - JavaScript Deobfuscation*
*For learning and SOC career preparation*
