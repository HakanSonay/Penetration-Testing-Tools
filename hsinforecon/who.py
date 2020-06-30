import whois

host = "google.com"

res = whois.query(host)

for resq in res.__dict__:
    print(resq, res.__dict__[resq])
