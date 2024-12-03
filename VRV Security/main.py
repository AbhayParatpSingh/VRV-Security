import re
import csv
from collections import defaultdict


LOG_FILE_NAME = "sample.log" 
FAILURE_THRESHOLD = 10  
RESULT_OUTPUT_FILE = "log_analysis_results.csv"  


LOG_ENTRY_PATTERN = (
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)' 
    r' - - \[.*?\] '               
    r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) '  
    r'(?P<endpoint>\S+)'          
    r' HTTP/.*?" '                 
    r'(?P<status>\d{3})'         
)

ip_request_counts = defaultdict(int)      
endpoint_request_counts = defaultdict(int) 
failed_login_counts = defaultdict(int)     


try:
    with open(LOG_FILE_NAME, 'r') as log_file:
        for line in log_file:
            entry_match = re.match(LOG_ENTRY_PATTERN, line)
            if entry_match:
                ip_address = entry_match.group("ip")  
                requested_endpoint = entry_match.group("endpoint") 
                http_status = entry_match.group("status")
                
               
                ip_request_counts[ip_address] += 1
                
                
                endpoint_request_counts[requested_endpoint] += 1
                
                
                if http_status == "401": 
                    failed_login_counts[ip_address] += 1
except FileNotFoundError:
    print(f"Error: Unable to find the file '{LOG_FILE_NAME}'.")
    exit(1)


sorted_ip_requests = sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True)


most_frequent_endpoint = max(endpoint_request_counts.items(), key=lambda x: x[1])


suspicious_ips_found = {ip: count for ip, count in failed_login_counts.items() if count > FAILURE_THRESHOLD}


print("\n1. Request Counts by IP Address:")
print(f"{'IP Address':<20}{'Request Count':<15}")
for ip, count in sorted_ip_requests:
    print(f"{ip:<20}{count:<15}")

print("\n2. Most Frequently Accessed Endpoint:")
print(f"{most_frequent_endpoint[0]} (Accessed {most_frequent_endpoint[1]} times)")

print("\n3. Detected Suspicious Activity:")
if suspicious_ips_found:
    print(f"{'IP Address':<20}{'Failed Login Attempts':<15}")
    for ip, count in suspicious_ips_found.items():
        print(f"{ip:<20}{count:<15}")
else:
    print("No suspicious activity detected.")


with open(RESULT_OUTPUT_FILE, 'w', newline='') as output_csv:
    csv_writer = csv.writer(output_csv)
    
 
    csv_writer.writerow(["Requests per IP"])
    csv_writer.writerow(["IP Address", "Request Count"])
    csv_writer.writerows(sorted_ip_requests)
    csv_writer.writerow([])  
    
  
    csv_writer.writerow(["Most Accessed Endpoint"])
    csv_writer.writerow(["Endpoint", "Access Count"])
    csv_writer.writerow(most_frequent_endpoint)
    csv_writer.writerow([])  
    

    csv_writer.writerow(["Suspicious Activity"])
    csv_writer.writerow(["IP Address", "Failed Login Count"])
    for ip, count in suspicious_ips_found.items():
        csv_writer.writerow([ip, count])

print(f"\nResults have been saved to '{RESULT_OUTPUT_FILE}'.")