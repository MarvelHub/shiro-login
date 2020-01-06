package org.shiro.auth.common.shiro.jwt;

import org.apache.shiro.authc.AuthenticationException;

/**
 * token过期抛出这个
 */
public class JWTTokenTimeoutException extends AuthenticationException {

    private static final long serialVersionUID = -8313101744886192005L;
    public JWTTokenTimeoutException(String message) {
        super(message);
    }
}
