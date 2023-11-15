import os
import glob
from subprocess import Popen, PIPE

# Get the directory of the script
base_dir = os.path.dirname(os.path.abspath(__file__))

# Build the path to the resources folder
resources_dir = os.path.join(base_dir, 'resources')

# get a list of all pcap files
pcap_files = glob.glob(os.path.join(resources_dir, '*.yaml'))
total_files = len(pcap_files)

# loop through each file and process it
for idx, pcap_file in enumerate(pcap_files):
    with Popen(["python", "main.py", pcap_file], stdout=PIPE, bufsize=1, universal_newlines=True) as p:
        for line in p.stdout:
            print(line, end='')
    print(f"Processed file #{idx + 1} of {total_files}. {total_files - (idx + 1)} files left.")