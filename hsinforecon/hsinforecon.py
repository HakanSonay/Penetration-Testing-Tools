import sys
import requests
import socket
import json

gethostby_ = socket.gethostbyname(sys.argv[1])
print("\nThe IP address of "+sys.argv[1] + "is :"+gethostby_+"\n")

# ipinfo.io

req_ipinfo = requests.get("https://ipinfo.io/"+gethostby_+"/json")
resp_ = json.loads(req_ipinfo.text)
print("City: "+resp_["city"])
print("Region: "+resp_["region"])
print("Country: "+resp_["country"])
print("Location: "+resp_["loc"])
print("ISP: "+resp_["org"])
print("Postal: "+resp_["postal"])
print("Time Zone: "+resp_["timezone"])
