package org.shiro.auth.common.utils;

import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.Objects;

/***
 *  说  明：登录工具类
 *  作  者：zf.zeng
 *  日  期：2019-12-27 (星期五)
 ***/
public class IPUtils {

    private static final String UNKNOWN = "unknown";

    public static String getIpAddr(HttpServletRequest... requests) {
        HttpServletRequest request = requests.length==0? IPUtils.getHttpServletRequest():requests[0];
        String ip = request.getHeader("x-forwarded-for");
        if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return "0:0:0:0:0:0:0:1".equals(ip) ? "127.0.0.1" : ip;
    }

    /**
     * 获取当前用户请求地址
     * @return HttpServletRequest
     */
    private static HttpServletRequest getHttpServletRequest() {
        return ((ServletRequestAttributes) Objects.requireNonNull(RequestContextHolder.getRequestAttributes())).getRequest();
    }

}
