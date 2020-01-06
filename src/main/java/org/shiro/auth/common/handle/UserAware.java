package org.shiro.auth.common.handle;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import org.shiro.auth.common.shiro.jwt.JWTToken;
import org.apache.shiro.SecurityUtils;

import java.util.Objects;

/**
 * 获取当前操作用户ID
 */
public interface UserAware {

    /**
     * 获取当前用户ID
     * @return 用户ID
     */
    default Long getUserId(){
        return this.getUserId(Long.class, -1L);
    }


    /**
     * 获取当前用户ID
     * @param clazz 数据类型的对应类
     * @return 用户ID
     */
    default <T>T getUserId(Class<T> clazz){
        Object token = SecurityUtils.getSubject().getPrincipal();
        if(Objects.nonNull(token)){
            Claim claim = JWT.decode(String.valueOf(token)).getClaim(JWTToken.CLAIM_ID_KEY);
            return claim.as(clazz);
        }
        return null;
    }

    /**
     * 获取当前用户ID
     * @param clazz 数据类型的对应类
     * @param defaultValue 当值为空时，取默认值
     * @return 用户ID
     */
    default <T>T getUserId(Class<T> clazz, T defaultValue){
        T val = this.getUserId(clazz);
        return val == null ? defaultValue : val;
    }
}
