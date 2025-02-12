'''
#add docstring here


'''

import sys
import os
from log_analysis
import pandas as pd
import re

def main():
    log_file = get_log_file_path_from_cmd_line()
    regex = r'sshd'
    filter_log_by_regex(log_file,regex, ignore_case=True, print_summary =True, print_records=True)
    #regex = r'invalid user.*220.195.35.40'

    port_traffic = tally_port_traffic(log_file)
    print(port_traffic)

    for port, count in port_traffic.items()
        if (count >= 100):
            generate_port_traffic_report(log_file,port)

# TODO: Step 8
def tally_port_traffic(log_file):
    port_traffic = {}

    with open (log_file, 'r') as file:
        for record in file:
            match = re.search(r"DPT=(.[^ ]*)",record)
            if match:
                port = match.group(1)
                port_traffic[port]= port_traffic.get(port,0) + 1
                print(port)

    return port_traffic

# TODO: Step 9
def generate_port_traffic_report(log_file, port_number):
    
    
    regex = ''
    traffic_records = filter_log_by_regex(log_file,regex,)[1]

    traffic_df = pd.DataFrame(traffic_records)

    traffic_df.to_csv(f'destination_port_{port_number}_report.csv',header=traffic_header index=False)
    traffic_header = ('Date', 'Time', 'Source IP Address', 'Destination IP Address', 'Source Port')
    return

# TODO: Step 11
def generate_invalid_user_report(log_file):
    return

# TODO: Step 12
def generate_source_ip_log(log_file, ip_address):
    return

if __name__ == '__main__':
    main()