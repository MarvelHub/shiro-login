package org.shiro.auth.common.shiro.auth;

import org.shiro.auth.common.shiro.jwt.JWTFilter;
import org.shiro.auth.common.shiro.properties.LoginProperties;
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import javax.annotation.Resource;

/**
 * Shiro 配置类
 */
@Configuration
public class ShiroConfig {

    @Resource private LoginProperties loginProperties;

    /***
     * 先走 filter ，然后 filter 如果检测到请求头存在 token，则用 token 去 login，走 Realm 去验证
     * @param securityManager securityManager
     * @param shiroFilterChainDefinition shiroFilterChainDefinition
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager, ShiroFilterChainDefinition shiroFilterChainDefinition) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager); // 设置 securityManager

        shiroFilterFactoryBean.getFilters().put("jwt", new JWTFilter());
        shiroFilterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition.getFilterChainMap());
        return shiroFilterFactoryBean;
    }

    @Bean
    protected ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        String[] urls = loginProperties.getAnonUrl().split(",");
        for (String url : urls) {
            chainDefinition.addPathDefinition(url, "anon");
        }
        chainDefinition.addPathDefinition("/**", "jwt"); //所有请求都要经过 jwt过滤器
        return chainDefinition;
    }

    @Bean
    public SecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        // 配置 SecurityManager，并注入 shiroRealm
        securityManager.setRealm(shiroRealm());

        // session统一有redis管理，故关闭自带session
        DefaultSubjectDAO subjectDAO = new DefaultSubjectDAO();
        subjectDAO.setSessionStorageEvaluator(new DefaultSessionStorageEvaluator() {
            @Override
            public boolean isSessionStorageEnabled() {
                return false;
            }
        });
        securityManager.setSubjectDAO(subjectDAO);

        return securityManager;
    }

    @Bean
    public ShiroRealm shiroRealm() {
        return new ShiroRealm();
    }

    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }
}
