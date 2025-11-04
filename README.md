🧠 ThreatIntelAI — Advanced IOC Enrichment Framework

 🔍 Overview

ThreatIntelAI is a Python-based asynchronous IOC enrichment engine that automates intelligence gathering from multiple security APIs.
It aggregates data such as reputation scores, geo-location, ASN, and abuse reports for IPs, domains, URLs, and file hashes.

Built for threat hunters, SOC analysts, and researchers, ThreatIntelAI enables rapid correlation and enrichment of indicators at scale.

---

 🚀 Features

* Asynchronous lookups with concurrency and retries.
* Automatic caching to avoid redundant API calls.
* Supports multiple data sources:

  * 🧬 VirusTotal v3
  * 🚨 AbuseIPDB
  * 👁️ GreyNoise (Community or API key)
  * 🌍 IPinfo
* Batch processing of IOCs from CSV, TXT, or JSON.
* CSV reports with merged and normalized fields.

---

 🧩 Supported IOC Types

| IOC Type   | Example                            | Data Sources                             |
| ---------- | ---------------------------------- | ---------------------------------------- |
| IP Address | `8.8.8.8`                          | VirusTotal, AbuseIPDB, GreyNoise, IPinfo |
| Domain     | `example.com`                      | VirusTotal                               |
| URL        | `http://malicious.site`            | VirusTotal (via domain extraction)       |
| Hash       | `44d88612fea8a8f36de82e1278abb02f` | VirusTotal                               |

---

 ⚙️ Installation

 1️⃣ Clone the Repository

```bash
git clone https://github.com/<your-username>/ThreatIntelAI.git
cd ThreatIntelAI
```

 2️⃣ Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate    On Windows: venv\Scripts\activate
```

 3️⃣ Install Requirements

```bash
pip install -r requirements.txt
```

---

 🔑 API Keys Configuration

Create a file called `.env` in the project root:

```ini
VT_API_KEY=<your_virustotal_api_key>
ABUSEIPDB_KEY=<your_abuseipdb_api_key>
GREYNOISE_KEY=<your_greynoise_key_or_leave_blank>
IPINFO_TOKEN=<your_ipinfo_token>
THREATINTELAI_MAX_CONCURRENCY=8
THREATINTELAI_TIMEOUT=12
THREATINTELAI_RETRIES=3
```

 🧱 Note on GreyNoise

* If you don’t have a GreyNoise API key, ThreatIntelAI automatically switches to Community mode, using the public endpoint:

  ```
  https://api.greynoise.io/v3/community/<ip>
  ```

  This returns limited but still valuable data (e.g., classification and noise status).

---

 🧰 Usage

 Basic Command

```bash
python enrich.py <input_file> --out data/enriched_iocs.csv
```

 Example

```bash
python enrich.py samples/iocs.csv --out reports/enriched.csv
```

 Supported Input Formats

| Format  | Example                               |
| ------- | ------------------------------------- |
| `.csv`  | Must contain columns like `ioc,type`  |
| `.txt`  | One IOC per line (type auto-detected) |
| `.json` | List of IOC objects                   |

---

 🧾 Output Example

| ioc             | type   | reputation_score | geo_country | asn                | malicious_votes |
| --------------- | ------ | ---------------- | ----------- | ------------------ | --------------- |
| 8.8.8.8         | ip     | 0                | US          | AS15169 Google LLC | 0               |
| bad.example.com | domain | -1               | —           | —                  | —               |

A full CSV is saved at your specified path (default: `data/enriched_iocs.csv`).

---

 🧩 Project Structure

```
ThreatIntelAI/
├── enrich.py               Main IOC enrichment engine
├── ioc_collector.py        IOC file parser and detector
├── utils.py                Logger and caching utilities
├── data/                   Output folder for enriched reports
├── samples/                Example IOC input files
├── .env                    Your API keys (not committed)
├── requirements.txt
└── README.md
```

---

 ⚡ Example `.csv` Input

samples/iocs.csv

```csv
ioc,type
8.8.8.8,ip
1.1.1.1,ip
example.com,domain
```

Then run:

```bash
python enrich.py samples/iocs.csv
```

---

 🧩 API Rate Limits

| Service             | Free Tier Limits |
| ------------------- | ---------------- |
| VirusTotal          | 4 requests/min   |
| AbuseIPDB           | 1000 req/day     |
| GreyNoise Community | Limited          |
| IPinfo              | 50k req/month    |

ThreatIntelAI automatically respects rate limits using async throttling and retries.

---

 🧠 Tech Stack

* Python 3.10+
* `aiohttp`, `async_timeout`, `tenacity`
* `dotenv` for key management
* `colorama` & `logging` for CLI feedback
* `json`, `csv` for data export

---

 🧑‍💻 Example Workflow

1. Collect IOCs from logs or SIEM into a CSV file.
2. Run:

   ```bash
   python enrich.py my_iocs.csv --out results/enriched.csv
   ```
3. Review the enriched IOC report.
4. Correlate results in your SOC dashboards or case management tools.

---

 🧱 Future Roadmap

* [ ] Add support for AlienVault OTX
* [ ] JSON output format
* [ ] Integration with MISP & TheHive
* [ ] Threat scoring aggregation model

---

 📜 License

This project is released under the MIT License.

---

 💬 Author & Credits

Developed by: SR (Security Engineer & Threat Researcher)
LinkedIn: www.linkedin.com/in/syed-raihaan-a03445291
GitHub: https://github.com/syedrai

---


