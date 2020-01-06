package org.shiro.auth.common.entity;


import cn.hutool.core.date.DatePattern;
import cn.hutool.core.date.DateUtil;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import org.shiro.auth.common.shiro.jwt.JWTToken;
import org.shiro.auth.common.utils.EncryptUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;

import java.io.Serializable;
import java.util.Date;

/**
 * 在线用户相关属性
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ActiveUser implements Serializable {
    private static final long serialVersionUID = 2055229953429884344L;

    // 唯一编号
    private String id = RandomStringUtils.randomAlphanumeric(20).toLowerCase();

    // 用户ID
    private Object userId;

    // 用户名
    private String username;
    // ip地址
    private String ip;
    // token
    private String token;
    // 登录时间
    private String loginTime = DateUtil.now();
    // 失效时间
    private String exipreAt;
    // 登录地点
    private String loginAddress;


    public ActiveUser(){}

    public ActiveUser(UserInfo user, String ip, Long timeOut) {
        this.userId = user.getUserId();
        this.username = user.getUsername();

        JWTCreator.Builder builder = JWT.create().withClaim(JWTToken.CLAIM_ID_KEY, String.valueOf(this.userId))
                .withClaim(JWTToken.CLAIM_USERNAME_KEY, this.username.toLowerCase()).withClaim(JWTToken.CLAIM_KICKOUT_ID_KEY, this.id);
        this.token = new EncryptUtils().encrypt(builder.sign(Algorithm.HMAC256(user.getPassword())));
        this.ip = ip;
        if(timeOut!=null && timeOut!=0L){
            Date date = DateUtil.date(System.currentTimeMillis() + timeOut);
            this.exipreAt = DateFormatUtils.format(date, DatePattern.PURE_DATETIME_PATTERN);
        }else{
            this.exipreAt = this.loginTime;
        }
    }

    /**
     * 每次登录的唯一标识
     */
    public String getIdentification(){
        return this.username.toLowerCase().concat("_").concat(this.id);
    }

}
