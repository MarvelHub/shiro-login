package org.shiro.auth.common.shiro.jwt;

import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.http.HttpStatus;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/***
 * 代码的执行流程 preHandle->isAccessAllowed->isLoginAttempt->executeLogin
 */
@Slf4j
public class JWTFilter extends BasicHttpAuthenticationFilter {

    // token 对应的key
    public static final String TOKEN = "Authentication";

    /**
     * 这里我们详细说明下为什么最终返回的都是true，即允许访问
     * 例如我们提供一个地址 GET /article
     * 登入用户和游客看到的内容是不同的
     * 如果在这里返回了false，请求会被直接拦截，用户看不到任何东西
     * 所以我们在这里返回true，Controller中可以通过 subject.isAuthenticated() 来判断用户是否登入
     * 如果有些资源只有登入用户才能访问，我们只需要在方法上面加上 @RequiresAuthentication 注解即可
     * 但是这样做有一个缺点，就是不能够对GET,POST等请求进行分别过滤鉴权(因为我们重写了官方的方法)，但实际上对应用影响不大
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws UnauthorizedException {
        return isLoginAttempt(request, response) && executeLogin(request, response);
    }

    /**
     * 判断用户是否想要登入。
     * 检测header里面是否包含Authorization字段即可
     */
    @Override
    protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
        return WebUtils.toHttp(request).getHeader(TOKEN) != null;
    }

    @Override
    protected boolean executeLogin(ServletRequest request, ServletResponse response) {
        String token = WebUtils.toHttp(request).getHeader(TOKEN); // 获取的token是加密状态
        getSubject(request, response).login(new JWTToken(token, true)); // 提交给realm进行登入，如果错误他会抛出异常并被捕获
        return true; // 如果没有抛出异常则代表登入成功，返回true
    }

    /**
     * 对跨域提供支持
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) {
        try {
            return super.preHandle(request, response);
        } catch (Exception e) {
            //判断用户令牌是否超时，前端根据返回状态（408）进行对应的操作
            if (e instanceof JWTTokenTimeoutException) {
                WebUtils.toHttp(response).setStatus(HttpStatus.REQUEST_TIMEOUT.value());
            } else {
                WebUtils.toHttp(response).setStatus(HttpStatus.BAD_REQUEST.value());
            }
        }
        return false;
    }
}
