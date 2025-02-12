'''


'''
#imports
import re
import sys
import os

# TODO: Step 3
def get_log_file_path_from_cmd_line():
    if len(sys.argv)>1: #checks that there are enough arguments
         filename = sys.argv[1]
         if os.path.isfile(filename):
            return os.path.abspath(filename)
         else:
            print("sorry this is not a file")
            exit(0)
    else:
        print("insufficient arguments, please include filename")
        exit(0)   
    return



# TODO: Steps 4-7
def filter_log_by_regex(log_file, regex, ignore_case=True, print_summary=False, print_records=False):
    """Gets a list of records in a log file that match a specified regex.

    Args:
        log_file (str): Path of the log file
        regex (str): Regex filter
        ignore_case (bool, optional): Enable case insensitive regex matching. Defaults to True.
        print_summary (bool, optional): Enable printing summary of results. Defaults to False.
        print_records (bool, optional): Enable printing all records that match the regex. Defaults to False.

    Returns:
        (list, list): List of records that match regex, List of tuples of captured data
    """
    filtered_records = [] #starting with an empty list
    filtered_groups = []

    if ignore_case:
        search_flag = re.IGNORECASE
        sensitive = "case insensitive"
    else:
        search_flags = 0
        sensitive = "case sensitive"
    with open(log_file,'r')as file:
         for record in file: #iterate through the lines in the file
            match = re.search(regex,record,search_flags)
            if match:
                    filtered_records.append(record.strip()) #returns the entire record that matches
                    if match.lastindex !=0:
                         filtered_groups.append(match.groups())

                         
    if print_records: 
         for record in filtered_records:
              print(rec)
    if match.lastindex !=0:
                        filtered_groups.append(match.groups())                
    if print_records:
        for rec in filtered_records:
            print(rec)


    if print_summary:
        print(f'The log file contains {len(filtered_records)} records, that are {sensitive}, matching regex:\n \r"{regex}"')
    return (filtered_records, filtered_groups)
