# 🕶️ InfoSpy

**InfoSpy** is a dark-themed macOS GUI tool for ethical hacking, reconnaissance, and OSINT (Open Source Intelligence) investigations. It works offline, integrates key scanning capabilities, and includes support for Shodan, WHOIS, and port scanning — all in one hacker-friendly interface.

![About Screen](assets/about.png)

---

## 🚀 Features

- 🌐 **IP & Domain Lookup**  
  Resolve public IPs, domain data, and reverse DNS.

- 🧠 **WHOIS, GeoIP & ASN Info**  
  Learn where domains/IPs are registered and who owns them.

- 🔐 **DNS Record Fetching**  
  View A, AAAA, MX, NS, TXT, and CNAME records.

- 🧾 **HTTP Header Inspection**  
  Fetch and display response headers from a target URL.

- 🔍 **Subdomain Enumeration**  
  Identify known subdomains using passive techniques.

- 🚪 **Port Scanning**  
  Scan popular or custom ports with socket-based scanning.

- 🛰️ **Shodan Integration** *(API key optional)*  
  Search open ports, banners, vulnerabilities, and more.

- 🧰 **Offline Capability**  
  Core features work without an internet connection.

- 📤 **Export Reports**  
  Save results for documentation or evidence.

- 🎨 **Dark Terminal-Themed GUI**  
  Custom icons, splash screen, and terminal-inspired styling.

---

## 💻 Installation

### 🧱 Requirements

- Python 3.8+
- macOS (tested), Linux supported with slight tweaks

Install dependencies:
```bash
pip install -r requirements.txt
```

Run the app:
```bash
python infospy.py
```

To package it as a macOS `.app`, use:
```bash
pyinstaller --onefile --windowed infospy.py
```

---

## 🖼️ Screenshots

![About Screen](assets/about.png)

---

## 🌐 Homepage

🔗 [Visit InfoSpy on Facebook](https://www.facebook.com/share/g/19E7mQb5kC/)

---

## 👨‍💻 Author

**KaliDarkmode** – _Ethical Hacker & OSINT Specialist_  
🧠 Built for recon missions, pentests, and infosec workflows.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
