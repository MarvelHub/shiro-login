package org.shiro.auth.common.handle;

import org.shiro.auth.common.entity.ActiveUser;

import java.util.List;

public interface OnlienUserAware {

    /**
     * 获取在线用户
     * @param username 指定用户名
     * @return 在线用户集合
     */
    default List<ActiveUser> findOnlienUser(String username) {
        return null;
    }

    /**
     * 退出系统
     * @param kickoutId 在线用户ID
     */
    default void deleteByKickoutId(String kickoutId) {}
}
