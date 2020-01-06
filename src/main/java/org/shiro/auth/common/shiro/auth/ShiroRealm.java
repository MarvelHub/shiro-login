package org.shiro.auth.common.shiro.auth;

import org.shiro.auth.common.entity.UserInfo;
import org.shiro.auth.common.handle.LoginProcessManager;
import org.shiro.auth.common.shiro.jwt.JWTToken;
import org.shiro.auth.common.shiro.jwt.JWTTokenTimeoutException;
import com.auth0.jwt.JWT;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * 自定义实现 ShiroRealm，包含认证和授权两大模块
 *
 * @author MrBird
 */
@Slf4j
public class ShiroRealm extends AuthorizingRealm {

    @Autowired private LoginProcessManager loginProcessManager;

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JWTToken;
    }

    /**`
     * 授权模块，获取用户角色和权限
     *
     * @param token token
     * @return AuthorizationInfo 权限信息
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection token) {
        String username = JWT.decode(token.toString()).getClaim(JWTToken.CLAIM_USERNAME_KEY).asString();
        UserInfo user = loginProcessManager.getUserPermission(username, UserInfo.class);
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.addRoles(user.getRoleCollection());
        simpleAuthorizationInfo.addStringPermissions(user.getPermissionCollection());
        return simpleAuthorizationInfo;
    }

    /**
     * 用户认证
     * @param authenticationToken 身份认证 token
     * @return AuthenticationInfo 身份认证信息
     * @throws AuthenticationException 认证相关异常
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        // 这里的 token是从 JWTFilter 的 executeLogin 方法传递过来的，已经经过了解密
        JWTToken JWTToken = (JWTToken) authenticationToken;

        // 从 redis里获取这个 token
        String encryptTokenInRedis = loginProcessManager.getTokenCache(JWTToken.getIdentification());

        // 如果找不到，说明已经失效（JWTFilter类中进行特殊处理用户令牌过去事件）
        if (StringUtils.isBlank(encryptTokenInRedis))
            throw new JWTTokenTimeoutException("用户令牌已过期");

        return new SimpleAuthenticationInfo(JWTToken.getPrincipal(), JWTToken.getCredentials(), "shiro_realm");
    }
}
