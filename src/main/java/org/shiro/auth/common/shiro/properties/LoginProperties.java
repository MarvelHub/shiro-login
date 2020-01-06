package org.shiro.auth.common.shiro.properties;


import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/***
 *  说  明：登录配置
 *  作  者：zf.zeng
 *  日  期：2019-12-27 (星期五)
 ***/
@Component
@ConfigurationProperties(prefix = "auth.login")
public class LoginProperties {

    private String anonUrl = "/**";

    private Long defaultTimeOut = 24 * 3600L; // 单位：秒

    public String getAnonUrl() {
        return anonUrl;
    }

    public void setAnonUrl(String anonUrl) {
        this.anonUrl = anonUrl;
    }

    public Long getDefaultTimeOut() {
        return defaultTimeOut;
    }

    public void setDefaultTimeOut(Long defaultTimeOut) {
        this.defaultTimeOut = defaultTimeOut;
    }
}
