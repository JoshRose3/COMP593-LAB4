'''
lab4_JR.py  
This file contains the code for Lab 4, written by Josh Rose.  
It processes a gateway log file to analyze SSHD attempts, invalid users, errors, 
port traffic, and source IP logs. It also generates reports based on the findings.

Functions:

    - main(): Runs the script and calls other functions to analyze the log file.
    - get_log_file_path_from_cmd_line(): Gets the log file path from the command line.
    - filter_log_by_regex(log_file, regex, ignore_case, print_summary, print_records): 
      Searches the log file for records matching a regex pattern.
    - tally_port_traffic(log_file): Counts how many times each destination port appears in the log.
    - generate_port_traffic_report(log_file, port_number): Creates a CSV file showing traffic for a specific port.
    - generate_invalid_user_report(log_file): Creates a CSV file with details about invalid user login attempts.
    - generate_source_ip_log(log_file, ip_address): Creates a log file with all records related to a specific source IP.

Example usage:
    - Run the script in the terminal with a log file as an argument.
    - It will automatically process the log and generate reports.

#This program is strictly my own work. Any material beyond course
#  learning materials that is taken from the Web or other sources 
# is properly cited, giving credit to the original author(s).


'''
import pandas as pd
import re
from log_analysis import get_log_file_path_from_cmd_line, filter_log_by_regex

def main():
    log_file = get_log_file_path_from_cmd_line()
    #step 5
    regex = r'SSHD'
    filter_log_by_regex(log_file, regex, ignore_case=True, print_summary =True, print_records=True)
    
    regex2 = r'invalid user.*220.195.35.40'
    filter_log_by_regex(log_file, regex2, ignore_case=True, print_summary=True, print_records=True)
    
    regex3 = 'error'
    filter_log_by_regex(log_file, regex3, ignore_case=True, print_summary=True, print_records=True)

    regex4 = r'Pam'
    filter_log_by_regex(log_file, regex4, ignore_case=True, print_summary=True, print_records=True)
    
   
    #step 8
    port_traffic = tally_port_traffic(log_file)
    print(port_traffic)

    #step 10
    for port, count in port_traffic.items():
        if (count >= 100 ):
            print(f' Port {port} has traffic greater than or equal to 100, it is {count}')
            generate_port_traffic_report(log_file,port)

    #step 11
    generate_invalid_user_report(get_log_file_path_from_cmd_line())
  
    #step 12
    generate_source_ip_log(log_file, "220.195.35.40") 


# TODO: Step 8
def tally_port_traffic(log_file):
    port_traffic = {}

    with open(log_file, 'r') as file:
        for record in file: #iterate through line by line
            match = re.search(r'DPT=([^ ]*)',record)
            if match:
                port = match.group(1)
                port_traffic[port]=port_traffic.get(port,0)+1
                print(port)

    return port_traffic

# TODO: Step 9
def generate_port_traffic_report(log_file, port_number):
    
    
    regex = r'^(.{6}) (.*) myth.*SRC=(.*?) DST=(.*?) .*SPT=(.*?) '+ f'DPT=({port_number})'
    traffic_records = filter_log_by_regex(log_file,regex)[1]
    
    traffic_df = pd.DataFrame(traffic_records)

    traffic_header = ('Date', 'Time', 'Source IP Address', 'Destination IP Address', 'Source Port', 'Destination Port' )
    traffic_df.to_csv(f'destination_port_{port_number}_report.csv',header=traffic_header, index=False)
    
    return

# TODO: Step 11
def generate_invalid_user_report(log_file):

    
    regex = r'(\w{3})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2}).*Invalid user (\S+) from ([\d.]+)'
    records = filter_log_by_regex(log_file, regex)[1]

    if not records:
        print("\n No invalid user attempts found!")
        return  

    
    formatted_records = [(f"{day}-{month}", time, user, ip) for month, day, time, user, ip in records]

    
    invalid_user_df = pd.DataFrame(formatted_records, columns=["Date", "Time", "Username", "IP Address"])
    
   
    invalid_user_df.to_csv("invalid_users.csv", index=False)

    print("invalid_users.csv generated successfully!")
    

    


  # TODO: Step 12
def generate_source_ip_log(log_file, ip_address):
    regex = rf'.*SRC={ip_address}.*'
    records = filter_log_by_regex(log_file, regex)[0]

    if not records:
        print(f"\n No records found for source IP {ip_address}!")
        return  

    filename = f"source_ip_{ip_address.replace('.', '_')}.log"
    with open(filename, "w") as file:
        file.write("\n".join(records) + "\n")

    print(f"{filename} generated successfully!")
    return

if __name__ == '__main__':
    main()

