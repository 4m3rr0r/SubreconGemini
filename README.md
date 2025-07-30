# SubreconGemini  🛡️🔍

`SubreconGemini` is a fast, lightweight, and focused subdomain discovery tool. It leverages a hybrid approach by combining AI-powered suggestions from Google's Gemini, traditional wordlist brute-forcing, and certificate transparency log analysis to uncover live subdomains.

---

## Features

* **Hybrid Discovery:** Uses multiple techniques for comprehensive results:
    * 🤖 **AI-Powered:** Integrates with the Google Gemini API to generate likely subdomain candidates.
    * 📖 **Wordlist Brute-force:** Utilizes common subdomain wordlists for discovery.
    * 📜 **Certificate Transparency:** Queries `crt.sh` to find subdomains from SSL/TLS certificates.
* **Live Verification:** Verifies discovered subdomains through DNS resolution and detects wildcard DNS configurations to minimize false positives.
* **HTTP Probing:** Checks for live web services on verified subdomains, capturing HTTP status codes and page titles.
* **Concurrent & Fast:** Employs `asyncio` and `ThreadPoolExecutor` for high-speed scanning.
* **Rich Output:**
    * Displays a clean, color-coded summary table in the console using `rich`.
    * Generates reports in `.txt` (simple list) and `.csv` (detailed summary) formats.
* **Flexible Input:** Accepts a single target domain or a file containing a list of domains.

---

## Requirements

* Python 3.7+
* The required Python packages can be installed via `pip`.

### Installation

1.  **Clone the repository (or save the script):**
    ```bash
    # If you have a git repo
    https://github.com/4m3rr0r/SubreconGemini.git
    cd SubreconGemini
    ```

2.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

---

## Configuration

The AI discovery feature requires a **Google Gemini API Key**. You can get one from the [Google AI Studio](https://aistudio.google.com/app/apikey).

You can provide the API key in two ways:

1.  **(Recommended) As an environment variable:**
    ```bash
    export GEMINI_API_KEY="YOUR_API_KEY_HERE"
    ```
    The script will automatically detect and use this variable.

2.  **As a command-line argument:**
    Use the `-k` or `--key` flag when running the script.

> **Note:** If no API key is provided, the tool will skip the AI discovery step and proceed with the other methods.

---

## Usage

The script requires a target, which can be a single domain (`-d`) or a file with a list of domains (`-l`).

```bash
python3 subrecon_gemini.py [TARGET] [OPTIONS]
```

Here is the complete content for your README.md file. You can copy and paste the text below into a file named README.md in your project's directory.

Markdown

# SubreconGemini (Lite) 🛡️🔍

`SubreconGemini` is a fast, lightweight, and focused subdomain discovery tool. It leverages a hybrid approach by combining AI-powered suggestions from Google's Gemini, traditional wordlist brute-forcing, and certificate transparency log analysis to uncover live subdomains.

---

## Features

* **Hybrid Discovery:** Uses multiple techniques for comprehensive results:
    * 🤖 **AI-Powered:** Integrates with the Google Gemini API to generate likely subdomain candidates.
    * 📖 **Wordlist Brute-force:** Utilizes common subdomain wordlists for discovery.
    * 📜 **Certificate Transparency:** Queries `crt.sh` to find subdomains from SSL/TLS certificates.
* **Live Verification:** Verifies discovered subdomains through DNS resolution and detects wildcard DNS configurations to minimize false positives.
* **HTTP Probing:** Checks for live web services on verified subdomains, capturing HTTP status codes and page titles.
* **Concurrent & Fast:** Employs `asyncio` and `ThreadPoolExecutor` for high-speed scanning.
* **Rich Output:**
    * Displays a clean, color-coded summary table in the console using `rich`.
    * Generates reports in `.txt` (simple list) and `.csv` (detailed summary) formats.
* **Flexible Input:** Accepts a single target domain or a file containing a list of domains.

---

## Requirements

* Python 3.7+
* The required Python packages can be installed via `pip`.

### Installation

1.  **Clone the repository (or save the script):**
    ```bash
    # If you have a git repo
    git clone https://your-repo-url/SubreconGemini.git
    cd SubreconGemini
    ```

2.  **Create a `requirements.txt` file with the following content:**
    ```
    requests
    dnspython
    rich
    google-generativeai
    ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

---

## Configuration

The AI discovery feature requires a **Google Gemini API Key**. You can get one from the [Google AI Studio](https://aistudio.google.com/app/apikey).

You can provide the API key in two ways:

1.  **(Recommended) As an environment variable:**
    ```bash
    export GEMINI_API_KEY="YOUR_API_KEY_HERE"
    ```
    The script will automatically detect and use this variable.

2.  **As a command-line argument:**
    Use the `-k` or `--key` flag when running the script.

> **Note:** If no API key is provided, the tool will skip the AI discovery step and proceed with the other methods.

---

## Usage

The script requires a target, which can be a single domain (`-d`) or a file with a list of domains (`-l`).

```
python3 subrecon_gemini.py [TARGET] [OPTIONS]
```

![Databases ](./Images/Screenshot%20from%202025-07-30%2016-57-02.png) 


