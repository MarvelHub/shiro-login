# shiro-login
基于springboot， 对shiro登录部分进行简单分装

在实际开发中可以直接打包成jar引入使用，该项目封装4个请求路径，均以“/auth”，项目自身也提供路径免验证配置，通过配置文件设置
接口说明：
    1./auth/login                              登录验证
    2./auth/nav/{username}                     获取用户导航菜单
    3./auth/logout                             退出系统
    4./auth/captcha.jpg?uuid={uuid}            验证码
开发者主要通过继承LoginProcessManager抽象类，重写其中方法
