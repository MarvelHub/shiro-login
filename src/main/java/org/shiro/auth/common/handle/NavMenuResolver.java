package org.shiro.auth.common.handle;


import java.util.Map;

/**
 * 路由菜单和权限接口
 */
public interface NavMenuResolver {

    /**
     * 路由菜单
     * @param user 用户
     * @return 菜单数据以树形数据返回
     */
    default Map<String, Object> routerView(String user) {
        return null;
    }

    /**
     * 用户权限，用于请求时的身份验证
     * @param username 用户名
     * @param clazz UserInfo
     * @return 用户所有权限&角色，多个权限（或角色）之间以逗号拼接
     */
    <T>T getUserPermission(String username, Class<T> clazz);
}
