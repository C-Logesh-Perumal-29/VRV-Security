import re
import csv
from collections import defaultdict

# Configurable threshold for suspicious activity detection
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    ip_request_count = defaultdict(int)
    endpoint_count = defaultdict(int)
    failed_login_count = defaultdict(int)

    with open(file_path, 'r') as log_file:
        for line in log_file:
            # Extract IP address
            ip_match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip_address = ip_match.group(1)
                ip_request_count[ip_address] += 1

            # Extract endpoint
            endpoint_match = re.search(r'"[A-Z]+\s(/[\w/]+)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_count[endpoint] += 1

            # Check for failed login attempts
            if '401' in line or 'Invalid credentials' in line:
                if ip_match:
                    failed_login_count[ip_address] += 1

    return ip_request_count, endpoint_count, failed_login_count

def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    log_file_path = 'sample.log'  # Path to the log file
    output_file = 'log_analysis_results.csv'

    # Parse the log file
    ip_request_count, endpoint_count, failed_login_count = parse_log_file(log_file_path)

    # Sort and display requests per IP
    print("IP Address           Request Count")
    for ip, count in sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:20} {count}")

    # Find the most accessed endpoint
    most_accessed_endpoint = max(endpoint_count.items(), key=lambda x: x[1])
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Detect suspicious activity
    suspicious_ips = {ip: count for ip, count in failed_login_count.items() if count > FAILED_LOGIN_THRESHOLD}
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips.items():
            print(f"{ip:20} {count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_to_csv(ip_request_count, most_accessed_endpoint, suspicious_ips, output_file)
    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    main()
