# ACEDORKER // Autonomous Cyber Intelligence Core

`ACEDORKER` is an elite, modular, open-source intelligence (OSINT) reconnaissance and security exposure assessment platform optimized for robust terminal environments and mobile deployment (such as iSH Alpine Linux).

---

## Features

* **Multi-Engine Search Harvesting:** Concurrent asynchronous harvesting across Google and DuckDuckGo with resilient anti-blocking user-agent rotators and response selectors.
* **Autonomous Target Crawling:** Strict preflight DNS validation, SSRF protection, IP filtering, and redirect guards.
* **Real-Time Plain-Text Credential Extraction:** Live streaming of unmasked credentials, database backup indicators, environment configuration exposures, and email assets.
* **Persistent SQLite History & Export:** Session tracking, findings database (`acedorker_history.db`), and automated CSV export capabilities.
* **Flexible Interface:** Fully operational via both a streamlined CLI and an optional Tkinter/CustomTkinter desktop GUI.

---

## Installation & Setup

1. **Clone or copy the repository files** to your local environment or mobile workspace.
2. **Install required dependencies:**
   ```bash
   pip install -r requirements.txt
