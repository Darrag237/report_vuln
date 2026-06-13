# 🛡️ report_vuln

A **web-based vulnerability reporting platform** built with TypeScript and React, designed for security researchers and penetration testers to document, organize, and present discovered vulnerabilities in a structured, professional format.

---

## 🎯 Purpose

This project provides a clean interface for generating detailed vulnerability reports. It was used to document real-world security findings across multiple vulnerability categories, with each finding captured as a visual evidence screenshot alongside structured report data.

---

## 🔍 Documented Vulnerability Categories

The repository includes documented findings across the following vulnerability types:

| # | Vulnerability | Category |
|---|---|---|
| 1 | SQL Injection (Authentication Bypass) | Injection |
| 2 | Broken Authentication (Missing JWT Validation) | Authentication |
| 3 | Blind Server-Side Request Forgery (SSRF) | Server-Side |
| 4 | Path Traversal | File System |
| 5 | Privilege Escalation via Client-Side Manipulation | Access Control |
| 6 | Excessive Data Exposure | API Security |
| 7 | Insecure Client-Side Storage (Local Storage Leak) | Client-Side |
| 8 | Missing Security Headers | Configuration |
| 9 | Fingerprinting & Server Information Disclosure | Information Disclosure |
| 10 | Sensitive Infrastructure Information Disclosure | Information Disclosure |
| 11 | Verbose Error Messages & Internal Information Disclosure | Information Disclosure |

---

## 🚀 Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React, TypeScript |
| Styling | CSS Modules |
| Build Tool | Vite / Next.js |
| Language Split | TypeScript 83% · CSS 14% · JS 2% · HTML 1% |

---

## 📁 Project Structure

```
report_vuln/
├── report-app/              # Main React/TypeScript application
│   ├── src/                 # Source components and pages
│   ├── public/              # Static assets
│   └── package.json         # Dependencies and scripts
│
├── *.jpg                    # Evidence screenshots for each vulnerability
└── README.md
```

---

## ⚙️ Getting Started

### Prerequisites
- Node.js 18+
- npm or pnpm

### Run Locally

```bash
# Clone the repository
git clone https://github.com/Darrag237/report_vuln.git
cd report_vuln/report-app

# Install dependencies
npm install

# Start development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Build for Production

```bash
npm run build
npm run start
```

---

## 📸 Evidence Screenshots

All vulnerability findings are documented with visual proof-of-concept screenshots stored at the root of the repository. Each screenshot corresponds to a specific finding with its ID and category clearly named.

Example evidence files:
- `SQL Injection (Authentication Bypass).jpg`
- `Blind Server-Side Request Forgery (SSRF).jpg`
- `Missing Security Headers (ID: 10).jpg`
- `Path Traversal (ID: 13).jpg`
- `Excessive Data Exposure (ID: 15).jpg`
- `Fingerprinting & Server Information Disclosure (ID: 20).jpg`

---

## ⚠️ Disclaimer

This repository is intended **strictly for educational and authorized security testing purposes**. All vulnerability findings documented here were discovered in controlled environments with proper authorization. Do not use any techniques demonstrated here against systems you do not own or have explicit permission to test.

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

---

> Built by [@Darrag237](https://github.com/Darrag237) — Security Researcher & Software Engineer
