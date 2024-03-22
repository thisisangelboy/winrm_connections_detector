# WinRM Connections Detector

WinRM Connections Detector is a Python script that monitors network traffic and detects WinRM (Windows Remote Management) connections. It captures packets on a specified network interface and logs the detected WinRM traffic along with the source IP address and timestamp. The script can also send email notifications when a WinRM connection is detected from a new IP address.

## Prerequisites

- Python 3.x
- Wireshark (installed in the default location)
- pyshark library
- smtplib library (for email notifications)

## Installation

1. Install Wireshark from the official website: [https://www.wireshark.org](https://www.wireshark.org)
2. Install the required Python libraries by running the following command:

   ```
   pip install pyshark
   ```

3. Clone or download the script files from the repository.

## Usage

1. Open the script file (`winrm_connections_detector.py` or `winrm_connections_detector_nomail.py`) in a text editor.

2. Modify the following variables according to your requirements:
   - `interface`: Specify the network interface to monitor (e.g., 'Ethernet0').
   - `mailgun_user`: Your Mailgun SMTP username (only applicable for `winrm_connections_detector.py`).
   - `mailgun_password`: Your Mailgun SMTP password (only applicable for `winrm_connections_detector.py`).
   - `to_email`: The recipient email address for notifications (only applicable for `winrm_connections_detector.py`).

3. Save the script file.

4. Open a terminal or command prompt and navigate to the directory where the script is located.

5. Run the script using the following command:
   ```
   python winrm_connections_detector.py
   ```
   or
   ```
   python winrm_connections_detector_nomail.py
   ```

6. The script will start monitoring WinRM traffic on the specified network interface. It will display log messages in the console and write them to a log file named `winrm_traffic.log`.

7. Press `Ctrl+C` to stop the monitoring process.

## Script Details

### `winrm_connections_detector.py`

- Captures packets on the specified network interface and detects WinRM connections.
- Logs the detected WinRM traffic with the source IP address and timestamp.
- Sends email notifications when a WinRM connection is detected from a new IP address.
- Skips logging and email notifications if the same IP address is detected within a 30-second interval.
- Limits email notifications to once per hour for each IP address.

### `winrm_connections_detector_nomail.py`

- Similar to `winrm_connections_detector.py`, but without the email notification functionality.

## Notes

- The script requires Wireshark to be installed in the default location for packet capture.
- Ensure that you have the necessary permissions to capture network traffic on the specified interface.
- The email notification feature in `winrm_connections_detector.py` uses Mailgun SMTP settings. Make sure to provide your Mailgun credentials and update the recipient email address accordingly.

## License

This script is open-source and available under the [MIT License](LICENSE).

## Disclaimer
This script is provided as-is without any warranty. Use it at your own risk. The author is not responsible for any damage or loss caused by the usage of this script.
