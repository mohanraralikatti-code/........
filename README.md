# 🛡️ ScamGuard AI PRO

> **Enterprise-Grade Threat Intelligence & Fraud Forensics Suite for GDG / Hack2Skill Hackathon 2026**

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](https://opensource.org/licenses/MIT)
[![Gemini API](https://img.shields.io/badge/AI-Google_Gemini_Flash-7928ca.svg)](https://ai.google.dev/)
[![Chrome Extension](https://img.shields.io/badge/Extension-Manifest_V3-00f2fe.svg)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![Hackathon](https://img.shields.io/badge/Hackathon-GDG_%2F_Hack2Skill-00ff87.svg)](#)

**ScamGuard AI PRO** is an advanced threat analysis workstation engineered to detect, analyze, and neutralize social engineering schemes—such as recruitment advance-fee check fraud, lease wire-transfer traps, and brand typosquatting attacks—before financial or identity harm occurs.

---

## ⚡ Key Architectural Pillars

* 🧠 **4-Pass Multi-Agent Gemini Pipeline:** Sequentially processes payloads across linguistic markers, economic anomalies, OSINT network traces, and adversarial bypass guardrails.
* 🔍 **Real-Time RDAP / WHOIS OSINT Checks:** Live REST integration checking domain registration dates to flag high-risk domains (<60 days old).
* 📐 **Levenshtein Brand Spoofing Engine:** Client-side string distance analysis detecting lookalike domain attacks (`g00gle.com`, `mcrosoft.com`) targeting top enterprise brands.
* 📄 **Multi-Page Document Extraction (`pdf.js`):** Extracts raw text sequentially across multi-page contract documents and offer letters.
* 🎯 **Automated Counter-Bait Honeypot:** Generates context-aware, evasive defensive replies demanding corporate EINs, official domain verification, and live video interviews.
* 🔌 **Chrome Extension Integration (Manifest V3):** Enables instant right-click text scanning directly from web interfaces (Gmail, LinkedIn, Craigslist).
* 📊 **1-Click Audit Dossier Export:** Renders printable, high-DPI security reports (`html2pdf.js`) for bank disputes or law enforcement reporting.
* ⚡ **Off-Grid Judges Demo Mode:** Built-in offline fallback engine guaranteeing 100% demo stability during judging evaluations.

---

## 🛠️ System Architecture & Stack

| Component | Technology / Library | Role |
| :--- | :--- | :--- |
| **Reasoning Engine** | Google Gemini Flash | Multi-agent reasoning & structured JSON generation |
| **OSINT Network** | RDAP / WHOIS REST API | Real-time domain registration age verification |
| **Frontend UI** | Cyber-Shield Glassmorphism CSS | High-contrast Obsidian aesthetic with responsive grids |
| **Document Processing** | `pdf.js` & `Marked.js` | Fast multi-page PDF text parsing & zero-latency markdown |
| **Reporting Engine** | `html2pdf.js` | Client-side security audit dossier PDF generation |
| **Browser Suite** | Chrome Extension Manifest V3 | Context menu integration & background payload passing |

---

## 🚀 Getting Started

### Prerequisites
* Any modern desktop web browser (Google Chrome recommended).
* A valid **Google Gemini API Key** (obtainable via [Google AI Studio](https://aistudio.google.com/)).

### Local Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/ScamGuard-AI.git](https://github.com/YOUR_USERNAME/ScamGuard-AI.git)
   cd ScamGuard-AI
