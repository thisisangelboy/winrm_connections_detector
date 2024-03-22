import pyshark
from datetime import datetime
import smtplib
from email.mime.text import MIMEText

detected_ips = {}
last_email_sent_time = {}

def detect_winrm_connection(packet):
    try:
        if 'TCP' in packet:
            tcp_layer = packet.tcp
            # Check if the destination port is 5985 or 5986
            if tcp_layer.dstport in ['5985', '5986']:
                src_ip = packet.ip.src
                current_time = datetime.now()
               
                # Check if the IP address has been detected before
                if src_ip in detected_ips:
                    last_detection_time = detected_ips[src_ip]
                    # Calculate the time difference between the current detection and the last detection
                    time_diff = (current_time - last_detection_time).total_seconds()
                   
                    # If the time difference is less than 30 seconds, skip logging
                    if time_diff < 30:
                        return
               
                # Update the last detection time for the IP address
                detected_ips[src_ip] = current_time
               
                log_message = f"Detected WinRM traffic from {src_ip} at {current_time.strftime('%Y-%m-%d %H:%M:%S')}"
                print(log_message)
                # Log the message to a file
                log_to_file(log_message)
                
                # Check if an email has been sent for this IP address within the last hour
                if src_ip not in last_email_sent_time or (current_time - last_email_sent_time[src_ip]).total_seconds() >= 3600:
                    # Send an email notification
                    send_email_notification(src_ip, current_time)
                    # Update the last email sent time for the IP address
                    last_email_sent_time[src_ip] = current_time
                
    except Exception as e:
        print(f"Error processing packet: {str(e)}")

def log_to_file(message):
    log_file_path = 'winrm_traffic.log'
    try:
        with open(log_file_path, 'a') as log_file:
            # Write the log message to the file
            log_file.write(message + '\n')
        print(f"Log message written to {log_file_path}: {message}")
    except Exception as e:
        print(f"Error writing log message to {log_file_path}: {str(e)}")

def send_email_notification(src_ip, detection_time):
    # Configure Mailgun SMTP settings
    mailgun_user = "your_mailgun_username"
    mailgun_password = "your_mailgun_password"
    to_email = "recipient@example.com"
    
    # Compose the email message
    subject = f"WinRM Connection Detected from {src_ip}"
    body = f"A WinRM connection was detected from {src_ip} at {detection_time.strftime('%Y-%m-%d %H:%M:%S')}."
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = mailgun_user
    msg['To'] = to_email
    
    try:
        # Establish a connection with the Mailgun server
        server = smtplib.SMTP('smtp.mailgun.org', 587)
        server.starttls()
        server.login(mailgun_user, mailgun_password)
        # Send the email
        server.send_message(msg)
        print("Email has been sent.")
    except Exception as e:
        print(f"Error sending email: {str(e)}")
    finally:
        # Close the SMTP connection
        server.quit()

def main():
    # Change this to the desired network interface
    interface = 'Ethernet0'
   
    # Capture packets on the specified interface and ports
    capture = pyshark.LiveCapture(interface=interface, bpf_filter='tcp portrange 5985-5986')
    print(f"Monitoring WinRM traffic on interface: {interface}")
    print("Press Ctrl+C to stop monitoring.")
    try:
        # Apply the detect_winrm_connection function to each captured packet
        capture.apply_on_packets(detect_winrm_connection)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by the user.")
    finally:
        print("Closing the capture...")
        # Close the capture when monitoring is stopped
        capture.close()

if __name__ == '__main__':
    main()