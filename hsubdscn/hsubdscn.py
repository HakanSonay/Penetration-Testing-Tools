import requests
import sys

sub_list = open("subdomains-1000.txt").read()
subs = sub_list.splitlines()

for sub in subs:
    url = f"http://{sub}.{sys.argv[1]}"
    try:
        requests.get(url)
    except requests.ConnectionError:
        pass
    else:
        print("Valid domain:", url)
