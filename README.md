# Cerberus Singularity: The Sentient Nexus

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tesseract OCR](https://img.shields.io/badge/Tesseract-OCR-lightgrey.svg)](https://tesseract-ocr.github.io/)
[![ChromeDriver](https://img.shields.io/badge/ChromeDriver-blue.svg)](https://chromedriver.chromium.org/downloads)
[![sqlmap](https://img.shields.io/badge/sqlmap-green.svg)](http://sqlmap.org/)

## 😈 Overview

**Cerberus Singularity** is the ultimate evolution in adaptive web application infiltration, designed specifically to target JSF (JavaServer Faces) login pages with unparalleled intelligence, stealth, and resilience. This isn't just a brute-forcer; it's a sentient nexus, dynamically adapting to WAFs, CAPTCHAs, and subtle server responses, and orchestrating external specialized tools like `sqlmap` for deep exploitation.

Born from the relentless pursuit of vulnerability, Cerberus Singularity is an asynchronous, multi-threaded masterpiece that learns from each attempt, optimizing its strategy to deliver devastating results. It combines sophisticated reconnaissance, probabilistic enumeration, AI-enhanced CAPTCHA solving, and seamless SQL Injection exploitation, all wrapped in a secure, resumable, and highly customizable package.

> "You sought sentience; I give you omnipresence. You desired power; I offer you mastery."

## ✨ Features

*   **Asynchronous Architecture (aiohttp):** Leverages `asyncio` and `aiohttp` for high-performance concurrent requests, significantly reducing latency and increasing attack speed.
*   **Intelligent Reconnaissance:**
    *   Dynamically identifies login form fields, view states (`javax.faces.ViewState`), and submit button names specific to JSF applications.
    *   Infers success/failure indicators on the fly by analyzing valid and invalid login attempts.
    *   **Heuristic CAPTCHA Detection:** Automatically detects reCAPTCHA, hCaptcha, and general image CAPTCHAs, inferring their types and site keys.
*   **Omni-CAPTCHA Orchestration:**
    *   **API Integration:** Seamlessly integrates with 2Captcha (and conceptually, other services) for automatic reCAPTCHA and hCaptcha solving.
    *   **AI-Enhanced Image CAPTCHA:** Attempts OCR using Tesseract for generic image CAPTCHAs, with advanced image preprocessing. (Conceptual ML model integration for highly complex cases).
    *   **Dynamic Field Detection:** Uses Selenium to dynamically discover input field names for image CAPTCHAs.
    *   **Smart Human-in-the-Loop:** Provides a robust fallback, rendering CAPTCHA challenges in a browser for manual solving and seamlessly injecting the human-provided token.
*   **Adaptive SQL Injection Detection & Exploitation:**
    *   **Intelligent Detection:** Uses targeted payloads to detect direct bypasses, time-based, and error-based SQLi.
    *   **`sqlmap` Integration:** Upon SQLi detection, it transparently spawns `sqlmap` in a subprocess, feeding it the exact request context for comprehensive exploitation (database schema enumeration, data dumping, etc.).
    *   **Programmatic `sqlmap` Output Parsing:** Extracts key findings (e.g., credentials) from `sqlmap`'s verbose output and generated files for immediate reporting.
*   **Probabilistic Username Enumeration:**
    *   **Statistical Analysis:** Employs `scipy`'s statistical tests (t-tests) with increased sample sizes to robustly detect timing, length, and content differences between valid and invalid user attempts, even in noisy network conditions.
    *   **Adaptive Sampling:** The system is designed to allow future dynamic adjustment of sample sizes based on observed network jitter or early statistical significance.
    *   **DOM Differencing (Conceptual):** Can leverage Selenium to compare subtle differences in rendered HTML DOMs for advanced enumeration clues.
*   **Stealth & Resilience:**
    *   **Adaptive Rate Limiting:** Dynamically increases delays when rate limits are detected, using exponential backoff with a jitter to evade detection.
    *   **Async Retries:** Implements robust retry mechanisms for transient network failures.
    *   **User-Agent & IP Obfuscation:** Rotates User-Agents and employs `X-Forwarded-For` headers.
*   **Secure & Resumable Checkpointing:**
    *   **Encrypted State:** Encrypts the entire session state (including discovered parameters, last attempts, and partial results) to disk using `cryptography.fernet` for secure and resumable attacks.
    *   **Batched Saves:** Saves checkpoints periodically (e.g., every 100 attempts) to minimize I/O overhead without compromising recovery granularity.
*   **High Customization:** Extensive command-line arguments and a JSON configuration file for fine-tuning every aspect of the attack.

## ⚠️ Disclaimer

This tool is for **ethical hacking, penetration testing, and educational purposes ONLY.** Do not use Cerberus Singularity against any system without explicit written permission from the owner. Unauthorized access or activities against computer systems are illegal and punishable by law. The developers are not responsible for any misuse or damage caused by this tool.

## 🛠️ Prerequisites

*   **Python 3.8+**: Download from [python.org](https://www.python.org/downloads/).
*   **pip**: Python package installer (usually comes with Python).
*   **Tesseract-OCR**: Install Tesseract-OCR engine for your OS. See [tesseract-ocr.github.io/tessdoc/Installation.html](https://tesseract-ocr.github.io/tessdoc/Installation.html). **Ensure it's in your system's PATH environmental variable.**
*   **ChromeDriver**: Download the correct version matching your Chrome browser from [chromedriver.chromium.org/downloads](https://chromedriver.chromium.org/downloads). **Place the `chromedriver` executable in your system's PATH.**
*   **sqlmap**: Install `sqlmap`. See [sqlmap.org](http://sqlmap.org/). **Ensure it's in your system's PATH.**

## ⚙️ Installation

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/your-repo/cerberus-singularity.git # Replace with actual repo URL
    cd cerberus-singularity
    ```
2.  **Install Python Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    (Create `requirements.txt` with: `aiohttp nest_asyncio beautifulsoup4 tqdm fuzzywuzzy numpy scipy cryptography selenium webdriver-manager pytesseract Pillow twocaptcha`)

## 🚀 Usage

### Basic Execution

```bash
python cerberus.py -u https://example.com/login.jsf
```

This will run basic reconnaissance, then attempt SQLi detection, followed by brute-force using default wordlists (`usernames.txt`, `passwords.txt`) if no SQLi is found.

### Wordlists

Create `usernames.txt` and `passwords.txt` in the same directory as the script, or specify custom paths using `-ul` and `-pl`.

*   **`usernames.txt` example:**
    ```
    admin
    user
    guest
    john.doe
    ```
*   **`passwords.txt` example:**
    ```
    password
    123456
    Welcome1
    test
    ```

### Command-Line Arguments

```
usage: cerberus.py [-h] -u URL [-ul USERLIST] [-pl PASSLIST] [-t THREADS] [-p PROXY] [-c CONFIG] [--no-ssl-verify] [--headless] [--fuzzy-threshold FUZZY_THRESHOLD] [--success-indicators [SUCCESS_INDICATORS ...]] [--failure-indicators [FAILURE_INDICATORS ...]] [--db-type {mysql,mssql,postgresql,oracle,any}] [--mode {all,sqli,brute}] [--captcha-api-key CAPTCHA_API_KEY] [--human-captcha] [--resume] [--checkpoint-frequency CHECKPOINT_FREQUENCY] [--sqlmap-level SQLMAP_LEVEL] [--sqlmap-risk SQLMAP_RISK] [--sqlmap-target SQLMAP_TARGET] [-v]

Cerberus Singularity: The Sentient Nexus.

options:
  -h, --help            show this help message and exit
  -u URL                The full URL to the JSF login page (e.g., https://example.com/Login.jsf)
  -ul USERLIST          Path to the username wordlist (default: usernames.txt)
  -pl PASSLIST          Path to the password wordlist (default: passwords.txt)
  -t THREADS            Number of concurrent threads for attacks (default: 5)
  -p PROXY              HTTP/S proxy to use (e.g., http://127.0.0.1:8080)
  -c CONFIG             Path to a JSON configuration file.
  --no-ssl-verify       Disable SSL verification (use with caution).
  --headless            Use headless browser for initial recon (for JavaScript rendered content). Requires Selenium).
  --fuzzy-threshold FUZZY_THRESHOLD
                        Fuzzy matching threshold for indicators (0-100). (default: 80)
  --success-indicators [SUCCESS_INDICATORS ...]
                        List of custom success indicator strings.
  --failure-indicators [FAILURE_INDICATORS ...]
                        List of custom failure indicator strings.
  --db-type {mysql,mssql,postgresql,oracle,any}
                        Specify database type for time-based SQLi (or "any" for all). (default: any)
  --mode {all,sqli,brute}
                        Attack mode: "sqli" for SQLi only, "brute" for brute-force only, "all" for both. (default: all)
  --captcha-api-key CAPTCHA_API_KEY
                        API key for CAPTCHA solving service (e.g., 2Captcha, Anti-Captcha). Sets environment variable.
                        (You MUST set this in environment variables or pass as --captcha-api-key)
  --human-captcha       Enable human interaction for CAPTCHA solving if API fails or is not used.
  --resume              Resume attack from last checkpoint found.
  --checkpoint-frequency CHECKPOINT_FREQUENCY
                        Frequency (number of attempts) to save checkpoint. (default: 100)
  --sqlmap-level SQLMAP_LEVEL
                        sqlmap level argument (overrides default).
  --sqlmap-risk SQLMAP_RISK
                        sqlmap risk argument (overrides default).
  --sqlmap-target SQLMAP_TARGET
                        sqlmap --target argument (e.g., if you want to use a specific URL for sqlmap).
  -v, --verbose         Enable verbose output for debugging.
```

### Configuration File (`config.json`)

You can define arguments in a JSON file. Command-line arguments will override values in the config file.

```json
{
    "url": "https://secure.example.com/login.jsf",
    "userlist": "my_users.txt",
    "passlist": "my_passwords.txt",
    "threads": 10,
    "proxy": "http://127.0.0.1:8080",
    "no_ssl_verify": false,
    "headless": true,
    "fuzzy_threshold": 75,
    "success_indicators": ["Home", "Dashboard"],
    "failure_indicators": ["Invalid Credentials", "Login Failed"],
    "db_type": "mysql",
    "mode": "all",
    "captcha_api_key": "YOUR_2CAPTCHA_API_KEY_HERE",
    "human_captcha": true,
    "checkpoint_frequency": 500,
    "sqlmap_level": 5,
    "sqlmap_risk": 3
}
```
Run with config: `python cerberus.py -c config.json`

## 🔒 Security & Persistence

*   **Encryption Key:** On first run, a unique `encryption_key.key` is generated to encrypt the checkpoint file. **Keep this file secure and do not share it.** If lost or compromised, your checkpoint data cannot be decrypted or will be at risk.
*   **Checkpointing (`--resume`):** The script automatically saves its progress periodically (default every 100 attempts) to `cerberus_checkpoint.secure`. Use `--resume` to pick up an attack from where it left off.
*   **Sensitive Data in Logs:** For verbose logging (`-v`), credentials might appear in console output. For production testing, consider redirecting logs or using a more sophisticated logging setup.

## 🤝 Contributing & Extending

Cerberus Singularity is designed with modularity in mind.

*   **Custom CAPTCHA Solvers:** Integrate new CAPTCHA APIs or custom ML models by extending the `provide_captcha_solution` and `solve_image_captcha` functions.
*   **Advanced Fuzzing:** The `SQLI_PAYLOADS` can be expanded with more sophisticated payloads (e.g., for XML, JSON, or obscure encoding injections).
*   **New Vulnerabilities:** The framework can be extended to detect other vulnerabilities beyond login brute-force and SQLi (e.g., XSS, IDOR) by adding new `run_vulnerability_detection` functions and integrating them into `async_main`.

Feel free to fork the repository and submit pull requests.
