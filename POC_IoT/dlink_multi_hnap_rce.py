#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register


class TestPOC(POCBase):
    name = "D-Link Multi HNAP RCE"
    vulID = ''
    author = ['sebao']
    vulType = 'Path Traversal'
    version = '1.0'  # default version: 1.0
    references = 'https://www.exploit-db.com/exploits/37171/,https://www.exploit-db.com/exploits/38722/'
    desc = 'Module exploits HNAP remote code execution vulnerability in multiple D-Link devices which allows executing commands on the device.'


    vulDate = ''
    createDate = '2017-10-17'
    updateDate = '2017-10-17'

    appName = 'D-Link'
    appVersion = 'D-Link DIR-645,AP-1522 revB,DAP-1650 revB,DIR-880L,DIR-865L，DIR-860L revA，DIR-860L revB，DIR-815 revB，DIR-300 revB，DIR-600 revB，DIR-645'
    dork = ''
    appPowerLink = 'http://www.dlink.com'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = self.url+ "/HNAP1/"
        headers = {"SOAPAction": '"http://purenetworks.com/HNAP1/GetDeviceSettings"'}

        resp = req.get(url,headers=headers)
        if resp.status_code == 200 and "D-Link" in resp.content and "SOAPActions" in resp.content:
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
