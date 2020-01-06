package org.shiro.auth.common.entity;

import com.google.common.base.Strings;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.*;

/***
 *  说  明： 登录用户的基本信息
 *  作  者：zf.zeng
 *  日  期：2019-12-27 (星期五)
 ***/
@Data
@Slf4j
public class UserInfo implements Serializable {

    private static final long serialVersionUID = 8197619506429596389L;

    // 账户状态     1:有效  2:锁定
    public static final String STATUS_VALID = "1";
    public static final String STATUS_LOCK = "0";

    private Serializable userId;

    private String username;

    private String password;

    private String status = STATUS_VALID;

    private String roles;

    private String permissions;

    public UserInfo(){}

    public Collection<String> getRoleCollection(){
        return StringUtils.isBlank(this.roles)? new ArrayList<>() : Arrays.asList(this.roles.split(","));
    }

    public Collection<String> getPermissionCollection(){
        return StringUtils.isBlank(this.permissions)? new ArrayList<>() : Arrays.asList(this.permissions.split(","));
    }
}
