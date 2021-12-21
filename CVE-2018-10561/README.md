# RCE on GPON home routers (CVE-2018-10561)

## Press
[The Hacker News - 1](https://thehackernews.com/2018/05/protect-router-hacking.html) 

[The Hacker News - 2](https://thehackernews.com/2018/05/botnet-malware-hacking.html)

[KitPloit](https://www.kitploit.com/2018/05/gpon-python-exploit-for-remote-code.html)

[Security Affairs](https://securityaffairs.co/wordpress/71987/hacking/gpon-home-routers-hack.html)



## Vulnerability
Many routers today use GPON internet, and  a way to bypass all authentication on the devices (**CVE-2018-10561**) was found by [VPNMentor](https://www.vpnmentor.com/blog/critical-vulnerability-gpon-router/). With this authentication bypass, it's also possible to unveil another command injection vulnerability (**CVE-2018-10562**) and execute commands on the device.

At the time it was written almost ONE MILLION of these devices are exposed to the Internet, according to [Shodan](https://www.shodan.io/search?query=title%3A%22GPON+Home+Gateway%22).


## Dependencies required
`requests`

`urllib2`

## Tested on 
`Kali Linux`

`Ubuntu 17.10 Server`


## Usage

```
python gpon_rce.py TARGET_URL COMMAND

```
e.g.
```
python gpon_rce.py http://192.168.1.15 'id'

```

## Screenshots
<p align="center">
  <img width="460" src="https://cdn1.imggmi.com/uploads/2018/5/7/f1210b72c5a5349f8aa5cbf310c3c7d6-full.png">
</p>


<p align="center">
  <img width="460" src="https://cdn1.imggmi.com/uploads/2018/5/7/981fdc2cdce43511a89135f2fca7f474-full.png">
</p>
