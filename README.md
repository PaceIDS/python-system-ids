# Simple Intrusion Detection System (IDS) with Signature & Anomaly-based Detection

This project is a simple yet powerful Intrusion Detection System (IDS) developed as part of a thesis research. The system is designed to run on Linux and leverages `scapy` for real-time packet sniffing and `iptables` for active response. It can detect several common cyber threats, provide instant notifications via a Telegram Bot, and allow for remote administration.

## ✨ Key Features

* **Multi-Faceted Threat Detection**: Implements a hybrid approach to identify various attacks:
    * **Port Scanning**: Detects when a single source IP scans multiple ports within a short time frame.
    * **Honeypot for Brute-Force**: A simple honeypot listens on a specified port (e.g., 2222) to bait and detect brute-force connection attempts.
    * **Intelligent SYN Flood Detection**: Utilizes three distinct methods to accurately detect Denial of Service attacks:
        1.  **Global SYN Flood**: Identifies large-scale DDoS attacks from multiple, often randomized, source IPs by monitoring the overall volume of SYN packets.
        2.  **Fast-Path Detection**: Quickly blocks a single IP address that sends an extremely high number of SYN packets in a very short window.
        3.  **Ratio-Based Anomaly**: Detects stealthier attacks by analyzing the ratio of `SYN` packets to `FIN/RST` packets, catching attackers who don't complete the TCP handshake.
* **Active Response System**:
    * **Automatic Blocking**: Permanently blocks malicious IPs using `iptables` for severe threats like SYN floods and brute-force attacks.
    * **Temporary Quarantine**: Temporarily blocks IPs for less severe threats like port scanning, with an automatic unblocking mechanism.
    * **Grace Period**: After an IP is unblocked, it is granted a "grace period" to prevent it from being immediately re-blocked by lingering packets from the same attack.
* **Telegram Bot Integration**:
    * **Real-time Alerts**: Sends detailed, formatted alert messages to a specified Telegram chat for every detected event.
    * **Remote Administration**: Allows an authorized admin to manage the IDS remotely with commands like `/block <IP>`, `/unblock <IP>`, `/karantina <IP> <minutes>`, and `/status`.
* **State Persistence**:
    * Saves the status of all blocked and quarantined IPs to a JSON file (`ip_status.json`).
    * On startup, it reloads the IP statuses and ensures that `iptables` rules are re-applied, making the system resilient to restarts.

---

## ⚙️ System Architecture & Modules

The project is modularized to separate concerns, making it easier to maintain and understand.

* `main.py`: The entry point of the application. Initializes all modules, starts background threads (sniffer, honeypot, etc.), and handles graceful shutdown.
* `config.py`: A centralized configuration file for all parameters, such as Telegram tokens, detection thresholds, and excluded IPs.
* `detection.py`: Contains all the logic for detecting different types of attacks based on the rules defined in `config.py`.
* `response.py`: Handles all response actions, primarily by interacting with the system's `iptables` firewall to block and unblock IPs.
* `telegram_bot.py`: Manages all communications with the Telegram Bot API, including sending alerts and handling admin commands.
* `honeypot.py`: Runs a simple TCP server on a custom port to act as a honeypot and log brute-force attempts.
* `persistence.py`: Responsible for saving the current state of blocked/quarantined IPs to a file and loading it on startup.
* `state.py`: Defines all global state variables (e.g., lists of blocked IPs, packet counters) used across different modules.
* `logging_utils.py`: Provides utility functions for writing attack logs and Telegram activity logs to files.
* `utils.py`: Contains common utility functions, such as IP validation.

---

## 🚀 Installation and Setup

This system is designed for a **Linux environment** (e.g., Ubuntu, Debian) due to its dependency on `iptables`.

### Prerequisites

* Python 3.8+
* `git`
* `iptables` (available by default on most Linux distributions)

### Step-by-Step Guide

1.  **Clone the Repository**
    Open your terminal and clone the project:
    ```bash
    git clone <YOUR_REPOSITORY_URL>
    cd <YOUR_PROJECT_DIRECTORY>
    ```

2.  **Create and Activate a Virtual Environment**
    It is highly recommended to use a virtual environment to manage project dependencies and avoid conflicts with system-wide packages.
    ```bash
    # Create a virtual environment named 'myvenv'
    python3 -m venv myvenv

    # Activate the environment
    source myvenv/bin/activate
    ```
    You will know it's active when you see `(myvenv)` at the beginning of your terminal prompt.

3.  **Install Dependencies**
    With the virtual environment active, install all required Python libraries using the `requirements.txt` file:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure the System**
    Edit the `config.py` file to set up your specific parameters:
    * `TELEGRAM_BOT_TOKEN`: Enter your Telegram Bot token.
    * `TELEGRAM_CHAT_ID`: Enter your personal Chat ID to receive alerts.
    * `EXCLUDED_IPS`: Add any IP addresses you want the IDS to ignore (e.g., your server's public IP, your home IP, the gateway).

---

## ▶️ Running the System

Because the program needs to perform low-level network sniffing and modify `iptables` firewall rules, it must be run with root privileges (`sudo`).

[cite_start]Make sure your virtual environment is active (`source myvenv/bin/activate`), then run the main script using the Python interpreter from within your environment[cite: 2]:

```bash
sudo ./myvenv/bin/python3 main.py
```

The IDS will initialize, load any previously saved IP statuses, start all detection threads, and begin monitoring your network traffic. All activity and alerts will be logged and sent to your configured Telegram chat.

To stop the system, press `Ctrl+C`. This will trigger a graceful shutdown, saving the current state of blocked IPs before exiting.

---

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
