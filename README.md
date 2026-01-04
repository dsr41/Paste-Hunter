# 🕵️ Paste-Hunter: OSINT Leak Monitor

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Type](https://img.shields.io/badge/Type-OSINT%20%7C%20Threat%20Intel-red)
![Status](https://img.shields.io/badge/Status-Active-success)

**A proactive Digital Risk Protection (DRP) tool that monitors public paste sites for compromised credentials and data leaks.**

---

## 📖 Overview
**Paste-Hunter** is an automated OSINT tool designed to simulate the capabilities of enterprise threat monitoring platforms (similar to **CloudSEK XVigil**). 

It continuously scrapes public sources (**Pastebin**, **Ghostbin**) to identify sensitive information such as:
* 🔓 **Compromised Credentials** (`email:pass` combos)
* 🗄️ **Database Dumps** & SQL leaks
* 🏢 **PII** (Personally Identifiable Information)

Instead of simple keyword matching, it uses a **Heuristic Threat Scoring** algorithm to grade the severity of a paste and alerts security teams in real-time via Discord or Telegram.

---

## ✨ Key Features
* **Real-Time Monitoring:** Scrapes `Pastebin` and `Ghostbin` archives with configurable intervals.
* **Heuristic Threat Scoring:** Calculates a "Risk Score" (0-100) based on regex patterns (email density, password complexity) and keyword context.
* **Intelligent Deduplication:** Uses `MD5` hashing to track seen pastes and prevent duplicate alerts.
* **Multi-Channel Alerting:** * 🔴 **Discord Webhooks:** Sends rich embeds with preview content.
  * 🔵 **Telegram Bot:** Sends instant mobile notifications.
* **Regex Pattern Matching:** Built-in patterns for `User:Pass` combos, email lists, and specific database keywords.

---

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/dsr41/Paste-Hunter.git
cd Paste-Hunter



