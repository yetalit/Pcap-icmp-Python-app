# Pcap icmp Python app
Client and server Python scripts for sending and logging icmp packets using pcap. Designed according to Unix based systems.


https://github.com/user-attachments/assets/6e8343b4-a563-43a0-b6d1-63deccd1e4fd


## Dependencies
1. pcapy-ng
2. psutil

## Usage
Run `icmp_client.py` script on client machine and `icmp_server.py` on server machine.

Press `z` to exit.

On client:
- Press `p` to send a ping request.
- Press `t` to send a time stamp request.

# Notes
It is tested using two VMs on the same host. To get it to work on complex networks, you may need to consider more configurations, like dealing with the MAC addresses of median interfaces rather than the reported MAC of the target machine.
