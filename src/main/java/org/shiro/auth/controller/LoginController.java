package org.shiro.auth.controller;

import org.shiro.auth.common.entity.UserInfo;
import org.shiro.auth.common.handle.LoginProcessManager;
import org.shiro.auth.common.limit.Limit;
import org.shiro.auth.common.shiro.properties.LoginProperties;
import org.shiro.auth.common.utils.EncryptUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotBlank;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.*;

/**
 * 登录访问层，登录/验证码/导航栏菜单/退出
 * 基本路径: /auth/**
 */
@RestController
@RequestMapping("/auth")
public class LoginController{

    @Resource
    LoginProperties loginProperties;
    private LoginProcessManager loginProcessManager;
    @Autowired
    public void setLoginProcessHandle(LoginProcessManager loginProcessManager) {
        this.loginProcessManager = loginProcessManager;
    }

    @PostMapping("/login")
    @Limit(key = "login", period = 60, count = 20, name = "登录接口", prefix = "limit")
    public Map<String, Object> login(String username, String password, String uuid, String captcha,
                                     @RequestParam(defaultValue = "0") long timeOut, HttpServletRequest request) {

        Map<String, Object> result = new HashMap<>();
        result.put("code",HttpStatus.INTERNAL_SERVER_ERROR.value());

        username = StringUtils.lowerCase(username);
        password = EncryptUtils.MD5Encrypt(username, password); // 加密，与数据库加密相同方法

        if(!loginProcessManager.validateCaptch(uuid, captcha)){
            result.put("msg", "验证码不正确");
            return result;
        }

        UserInfo user = this.loginProcessManager.findUserDetailByUsername(username, UserInfo.class);
        if (user == null){
            result.put("msg", "用户名不存在");
            return result;
        }
        if (!StringUtils.equals(user.getPassword(), password)){
            result.put("msg", "用户名或密码错误");
            return result;
        }
        if (StringUtils.equals(UserInfo.STATUS_LOCK, user.getStatus())){
            result.put("msg", "账号已被锁定,请联系管理员");
            return result;
        }

        timeOut = (timeOut >0? timeOut : loginProperties.getDefaultTimeOut()) * 1000;

        return this.loginProcessManager.afterHandle(user, timeOut, request);
    }



    /**
     * 验证码
     */
    @GetMapping("/captcha.jpg")
    public void captcha(HttpServletResponse response, String uuid)throws IOException {
        response.setHeader("Cache-Control", "no-store, no-cache");
        response.setContentType("image/jpeg");

        //获取图片验证码
        BufferedImage image = this.loginProcessManager.getCaptcha(uuid);

        ServletOutputStream out = response.getOutputStream();
        ImageIO.write(image, "jpg", out);
        out.close();
    }

    /**
     * 导航菜单
     */
    @GetMapping("/nav/{username}")
    public Map<String, Object> nav(@NotBlank(message = "{required}") @PathVariable String username){
        Map<String, Object> result = new HashMap<>();
        try {
            Map<String, Object> data = this.loginProcessManager.routerView(username);
            UserInfo userInfo = this.loginProcessManager.getUserPermission(username, UserInfo.class);
            result.put("code",HttpStatus.OK.value());
            result.put("menuList", data.get("router"));
            result.put("buttons", data.get("buttons"));
            result.put("permissions", userInfo.getPermissionCollection());
        }catch (Exception e){
            e.printStackTrace();
            result.put("code",HttpStatus.INTERNAL_SERVER_ERROR.value());
            result.put("msg","查询菜单异常，请联系管理员");
        }
        return result;
    }

    @GetMapping("logout/{id}")
    public void logout(@NotBlank(message = "{required}") @PathVariable String id) throws Exception {
        this.loginProcessManager.logoutHandle(id);
    }
}
