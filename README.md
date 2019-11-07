# illumio_challenge - Pranav Narasimmaraj

## Pre-requisites
I used the ipaddress package, which is part of Python3's standard library. If you are using Python2, you may have to `pip install ipaddress`.

## How to Run and Test
You can use the Python interpreter to test any input to my Firewall class.
1. `import firewall`
2. `fw = firewall.Firewall(csv_file_name)`
3. `fw.accept_packet(direction, protocol, port, ip address)`

I included a test script called firewall_test.py, which does all the above tasks with a sample csv file `firewall_data.csv`. It also runs a few test cases that I used to test my code. Feel free to add more test cases to this file if needed. You can run the test script simply with `python3 firewall_test.py`.

## Notes/Refinements/Optimizations
1. Initially, if a rule was an ip range, I made a list of every ip address in this range and tested if the given ip was in this list. This was incredibly inefficient, especially if the given range was 0.0.0.0-255.255.255.255(The list would contain 255^4 IP addresses!!!!). To fix this, I instead converted the min and max IP in the rule to an integer and compared this to the given ip, like how I did with ports.
2. To make this implementation more efficient given more time, I could have possibly sorted the set of rules by some comparator function and then used a binary search to go through the rules instead of iterating linearly like I currently do.

## Team Preference Ranking
1. Platform Team
2. Policy Team
3. Data Team
