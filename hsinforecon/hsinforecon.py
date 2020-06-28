import sys
import requests
import socket
import json

if len(sys.argv) < 2:
    print("Usage: " + sys.argv[0] + "<url>")
    sys.exit(1)

req = requests.get("https://" + sys.argv[1])
for head in req.headers:
    print(head+":", req.headers[head])


gethostby_ = socket.gethostbyname(sys.argv[1])
print("\nThe IP address of "+sys.argv[1] + "is :"+gethostby_+"\n")

# ipinfo.io

req_two = requests.get("https://ipinfo.io/"+gethostby_+"/json")
resp_ = json.loads(req_two.text)
print("City: "+resp_["city"])
print("Region: "+resp_["region"])
print("Country: "+resp_["country"])
print("Location: "+resp_["loc"])
print("ISP: "+resp_["org"])
print("Postal: "+resp_["postal"])
print("Time Zone: "+resp_["timezone"])
