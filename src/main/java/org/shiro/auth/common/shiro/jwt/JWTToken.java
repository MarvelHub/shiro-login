package org.shiro.auth.common.shiro.jwt;



import com.auth0.jwt.interfaces.DecodedJWT;
import org.shiro.auth.common.utils.EncryptUtils;
import com.auth0.jwt.JWT;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.AuthenticationToken;
import java.io.Serializable;

/**
 * 用户令牌对象
 * 前端的token处于二次加密，传至后端的token在过滤器中通过token的构造器进行解密,因此在后端调用的方法中获取到token均为已解密
 * token 只保存用户名 & 用户ID & ActiveUser的id
 * 用户名对应键值 CLAIM_USERNAME_KEY
 * 用户ID对应键值 CLAIM_ID_KEY
 * ActiveUser对应键值 CLAIM_KICKOUT_ID_KEY
 */
@Slf4j
public class JWTToken implements AuthenticationToken {

    private static final long serialVersionUID = 1282057025599826155L;

    // token 存储的键值
    public static final String CLAIM_ID_KEY = "id";
    public static final String CLAIM_USERNAME_KEY = "username";
    public static final String CLAIM_KICKOUT_ID_KEY="kickoutid";
    private String token;

    /**
     * 创建/解析token
     * 如果token 在缓存前是经过 EncryptUtils 加密处理，需进行解析方可使用
     * @param decrypt 是否解析
     * @param token 基本参数
     */
    public JWTToken(String token, boolean decrypt) {
        this.token = decrypt? new EncryptUtils().decrypt(token): token;
    }

    @Override
    public Object getPrincipal() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    /**
     * 虎获取token中的用户ID
     * @return 用户ID
     */
    public Serializable getId() {
        return JWT.decode(this.token).getClaim(CLAIM_ID_KEY).asString();
    }

    public String getUsername(){
        return JWT.decode(this.token).getClaim(CLAIM_USERNAME_KEY).asString();
    }

    /**
     * 获取token中每次登录的唯一标识
     * @return 用户名
     */
    public String getIdentification(){
        if(StringUtils.isNotBlank(this.token)){
            DecodedJWT decodedJWT = JWT.decode(this.token);
            String username = decodedJWT.getClaim(CLAIM_USERNAME_KEY).asString();
            String activeid = decodedJWT.getClaim(CLAIM_KICKOUT_ID_KEY).asString();
            return username.concat("_").concat(activeid);
        }
        return "undefined";
    }

}
