import sys
import requests
import socket
import json
import whois

print("HEADER")
response = requests.get("https://" + sys.argv[1])
for head in response.headers:
    print(head+":", response.headers[head])

# whois
print("\nWHOIS")
response_whois = whois.query(sys.argv[1])
for res in response_whois.__dict__:
    print(res, response_whois.__dict__[res])

ip = socket.gethostbyname(sys.argv[1])
print("\nThe IP address of "+sys.argv[1] + "is :"+ip)

# ipinfo.io
print("\nIPINFO")
response_ipinfo = requests.get("https://ipinfo.io/"+ip+"/json")
result = json.loads(response_ipinfo.text)
print("City: "+result["city"])
print("Region: "+result["region"])
print("Country: "+result["country"])
print("Location: "+result["loc"])
print("ISP: "+result["org"])
print("Postal: "+result["postal"])
print("Time Zone: "+result["timezone"])
