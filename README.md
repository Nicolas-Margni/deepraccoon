# 🦝 DeepRaccoon

**Shadow AI & Unauthorized Tool Detector**

DeepRaccoon is a professional CLI security tool designed for defensive security analysts. It detects unauthorized AI tools running on a Windows system — including active processes, exposed API keys, installed packages, network connections, browser history, desktop applications, and configuration files — generating a structured report with findings classified by severity and a final risk score.

---

## 📸 Screenshots

![Image Alt](https://github.com/Nicolas-Margni/deepraccoon/blob/844ee45d6353557c134a1baed21171c5ad7aa463/pictures/screenshot-1.png)

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/Nicolas-Margni/deepraccoon.git
cd deepraccoon

# Install dependencies
pip install -r requirements.txt

# Launch the interactive menu
python main.py
```

> **Recommended:** Run as Administrator for full system visibility.
> Right-click PowerShell → "Run as administrator" → navigate to the project folder.

---

## ⚙️ Installation

**Requirements:**
- Python 3.10 or higher
- Windows 10 / 11 (primary platform)
- pip

```bash
pip install -r requirements.txt
```

**Dependencies:**

| Package  | Version  | Purpose                        |
|----------|----------|--------------------------------|
| rich     | ≥ 13.0.0 | Formatted terminal output      |
| psutil   | ≥ 5.9.0  | Process and network inspection |
| blessed  | ≥ 1.19.0 | Full-screen TUI interface      |

---

## 🖥️ Usage

### Interactive Mode (recommended)

```bash
python main.py
```

Launches the full-screen TUI. Navigate using number keys:

```
MAIN MENU
├── [1] Scan
│   ├── [1] Full Scan
│   ├── [2] Quick Scan
│   ├── [3] Full Scan — Critical only
│   └── [4] Full Scan — Export to JSON + TXT
│
├── [2] Reports
│   ├── [1] View last report
│   ├── [2] View any report
│   ├── [3] Export report
│   ├── [4] Delete last report
│   └── [5] Delete any report
│
├── [5] Help
└── [0] Exit
```

### CLI Mode (for scripting / automation)

```bash
# Full scan, terminal output
python main.py --scan full

# Quick scan (process + environment only)
python main.py --scan quick

# Full scan, save JSON + TXT report
python main.py --scan full --output both

# Show only CRITICAL findings
python main.py --scan full --severity critical

# Silent mode (no banner, report only)
python main.py --scan full --quiet
```

**Available flags:**

| Flag            | Options                              | Default    | Description                        |
|-----------------|--------------------------------------|------------|------------------------------------|
| `--scan`        | `full`, `quick`                      | —          | Scan mode                          |
| `--output`      | `terminal`, `json`, `txt`, `both`    | `terminal` | Output format                      |
| `--severity`    | `all`, `critical`, `high`, `medium`, `low` | `all` | Minimum severity filter           |
| `--quiet`       | —                                    | `false`    | Suppress banner and progress       |
| `--reports-dir` | path                                 | `reports/` | Custom reports output folder       |

---

## 🔍 Detection Modules

| Module            | What it detects                                          | Severity       |
|-------------------|----------------------------------------------------------|----------------|
| `process_scanner` | Active AI processes (Ollama, LM Studio, Jan...)          | HIGH           |
| `env_scanner`     | API keys in environment variables and `.env` files       | CRITICAL / HIGH|
| `package_scanner` | Installed Python AI/LLM packages                         | MEDIUM         |
| `network_scanner` | Active TCP connections and DNS cache hits to LLM APIs    | HIGH / MEDIUM  |
| `config_scanner`  | AI tool configuration folders (Claude Desktop, Cursor…)  | LOW            |
| `browser_scanner` | AI site visits in browser history + AI extensions        | MEDIUM / LOW   |
| `app_scanner`     | AI desktop applications installed on the system          | MEDIUM         |

---

## ⚠️ Severity Scale

| Level      | Points | Meaning                                              |
|------------|--------|------------------------------------------------------|
| `CRITICAL` | 25 pts | API key exposed — immediate action required          |
| `HIGH`     | 15 pts | Active AI process or extension with system access    |
| `MEDIUM`   |  8 pts | AI app installed or developer API console visited    |
| `LOW`      |  3 pts | AI chat site visited or config folder found          |
| `INFO`     |  0 pts | Informational — no action required                   |

---

## 📊 Risk Score

The final risk score (0–100) is calculated by summing the severity points of all findings, capped at 100.

| Score   | Level        | Meaning                              |
|---------|--------------|--------------------------------------|
| 80–100  | **CRITICAL** | Immediate investigation required     |
| 60–79   | **HIGH**     | Significant AI presence detected     |
| 40–59   | **MEDIUM**   | Moderate AI usage found              |
| 0–39    | **LOW**      | Minimal or no AI presence            |

---

## 📁 Project Structure

```
deepraccoon/
├── main.py                  # Entry point — TUI launcher + CLI fallback
├── requirements.txt
├── README.md
├── .gitignore
│
├── config/
│   └── signatures.json      # Detection signatures database
│
├── core/
│   ├── finding.py           # Finding dataclass
│   ├── scanner.py           # Main orchestrator
│   └── risk_score.py        # Risk score calculator
│
├── modules/
│   ├── base_module.py       # Abstract base class
│   ├── process_scanner.py
│   ├── env_scanner.py
│   ├── package_scanner.py
│   ├── network_scanner.py
│   ├── config_scanner.py
│   ├── browser_scanner.py
│   └── app_scanner.py
│
├── output/
│   ├── tui.py               # Full-screen interactive interface
│   ├── terminal_reporter.py # Rich-based terminal output
│   └── file_reporter.py     # JSON and TXT export
│
└── reports/                 # Auto-generated scan reports
    └── Scan-001-2026-04-19_20-30-00/
        ├── report.json
        └── report.txt
```

---

## 🗂️ signatures.json

All detection intelligence lives in `config/signatures.json` — no hardcoded values in Python code. This makes it easy to update the database without touching the source code.

```json
{
  "processes":        [...],   // Known AI process names
  "api_domains":      [...],   // LLM API hostnames
  "api_key_patterns": [...],   // Regex patterns for API keys
  "python_packages":  [...],   // Known AI Python packages
  "config_paths":     [...],   // Known AI tool config folders
  "browser_extensions":[...],  // Known AI browser extension IDs
  "browser_ai_sites": [...],   // Known AI websites
  "installed_apps":   [...]    // Known AI desktop app paths
}
```

To add a new AI tool to detect, just add an entry to the relevant section — no code changes needed.

---

## 📝 Report Output

Each scan that is saved generates a timestamped folder:

```
reports/Scan-001-2026-04-19_20-30-00/
    report.json    ← structured data for programmatic use
    report.txt     ← human-readable for emails and documentation
```

**report.json structure:**
```json
{
  "metadata": {
    "tool": "DeepRaccoon",
    "version": "0.1.0",
    "generated_at": "2026-04-19T20:30:00",
    "total_findings": 7
  },
  "risk_score": {
    "score": 63,
    "level": "HIGH",
    "breakdown": { "CRITICAL": 1, "HIGH": 0, "MEDIUM": 4, "LOW": 2, "INFO": 0 }
  },
  "findings": [...]
}
```

---

## 🔒 Ethical Use

DeepRaccoon is designed for **defensive security auditing** only.

- Intended use: authorized security audits on systems you own or have explicit permission to scan
- It does **not** read conversation content from AI chats
- It does **not** exfiltrate any data — all analysis is local
- It does **not** modify any system files

Always ensure you have proper authorization before scanning any system.

---

## 🤝 Contributing

To add a new detection module:

1. Create `modules/your_module.py` inheriting from `BaseModule`
2. Implement `name`, `description`, and `run()` 
3. Add relevant signatures to `config/signatures.json`
4. Register the module in `core/scanner.py`

That's it — no other files need to be modified.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built for the defensive security community.*
