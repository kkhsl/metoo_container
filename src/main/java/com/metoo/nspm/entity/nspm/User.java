package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>
 *  Titlte: User.java
 * </p>
 *
 * <p>
 *  Description: 用户类，所有用户都由该类管理，包括普通用户，商家，管理员
 * </p>
 *
 * <p>
 *  author: hkk
 * </p>
 */

@ApiModel("用户实体类")
@Data//  注解在类上, 为类提供读写属性, 此外还提供了 equals()、hashCode()、toString() 方法
@Accessors(chain = true) // fluent、chain、prefix、注解用来配置lombok如何产生和显示getters和setters的方法
@AllArgsConstructor
@NoArgsConstructor
public class User extends IdEntity {
/*

    @ApiModelProperty("用户id")
    private Long id;
*/
/*
m
    @ApiModelProperty("用户注册时间")
    private Date addTime;
*/

    @ApiModelProperty("用户名")
    private String username;

    @ApiModelProperty("用户密码")
    private String password;

    @ApiModelProperty("用户邮箱")
    private String email;

    @ApiModelProperty("手机号码")
    private String mobile;

    @ApiModelProperty("性别 -1:无 0:女  1：男")
    private Integer sex;

    @ApiModelProperty("年龄")
    private Integer age;

    @ApiModelProperty("加密盐")
    private String salt;

    @ApiModelProperty("用户状态 0：启用 1：未启用")
    private Integer status;

    @ApiModelProperty("备注")
    private String note;

    @ApiModelProperty("用户角色 SUPPER:超级管理员 ADMIN:管理员 BUYER:普通用户 超级管理员拥有全部权限并且可以创建用户分配权限")
    private String userRole;

    @ApiModelProperty("角色集合")
    private List<Role> roles = new ArrayList<Role>();

    @ApiModelProperty("角色组")
    private List<RoleGroup> roleGroups = new ArrayList<RoleGroup>();

    @ApiModelProperty("组名称")
    private String groupName;

    @ApiModelProperty("组ID")
    private Long groupId;
    @ApiModelProperty("组等级")
    private String groupLevel;

    @ApiModelProperty("版本号：乐观锁")
    private Integer version;
    @ApiModelProperty("自定义锁，限制用户重试密码次数")
    private boolean locked;

    @ApiModelProperty("用户类型")
    private Integer type;

    public boolean isLocked() {
        return locked;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }
}
