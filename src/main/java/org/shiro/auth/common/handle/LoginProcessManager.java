package org.shiro.auth.common.handle;

import org.shiro.auth.common.entity.ActiveUser;
import org.shiro.auth.common.entity.UserInfo;
import org.shiro.auth.common.utils.IPUtils;
import org.springframework.context.annotation.ComponentScan;

import javax.servlet.http.HttpServletRequest;
import java.awt.image.BufferedImage;
import java.util.HashMap;
import java.util.Map;

/**
 * 配置登录回调函数
 * @author zf.zeng
 */
@ComponentScan(basePackages = "org.shiro.auth.*")
public abstract class LoginProcessManager implements OnlienUserAware, NavMenuResolver {

    private ActiveUser active;

    protected ActiveUser getActiveUser(){
        return this.active;
    }

    /**
     * 登录是通过指定用户名获取用户的基本信息以及权限角色等
     * @param username 用户名
     * @return 用户
     */
    public abstract <T>T findUserDetailByUsername(String username, Class<T> clazz);

    /**
     * 获取验证码流
     * @param uuid uuid
     * @return 流
     */
    public BufferedImage getCaptcha(String uuid){
        return null;
    }

    /**
     * 检验验证码是否正确
     * @param uuid uuid
     * @param captcha 验证码
     * @return true /false
     */
    public Boolean validateCaptch(String uuid, String captcha){
        return true;
    }

    /**
     * 登录验证成功之后的回调函数
     */
    public Map<String, Object> afterHandle(UserInfo user, Long timeOut, HttpServletRequest request){
        Map<String, Object> data = new HashMap<>();

        active = new ActiveUser(user, IPUtils.getIpAddr(request), timeOut);

        data.put("exipreTime", this.getActiveUser().getExipreAt());
        data.put("kickoutId", this.getActiveUser().getId());
        data.put("token", this.getActiveUser().getToken());

        user.setPassword("it's a secret");
        data.put("user", user);
        return data;
    }

    /**
     * 退出系统
     * @param kickoutId 在线用户ID
     */
    public void logoutHandle(String kickoutId){
        this.deleteByKickoutId(kickoutId);
    }

    /**
     * 从缓存中获取Token
     * @param key 键值
     * @return token
     */
    public abstract String getTokenCache(String key);
}
