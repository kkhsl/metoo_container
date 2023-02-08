package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.User;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import javax.validation.constraints.NotNull;
import java.util.Date;

@ApiModel("用户DTO")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class UserDto extends PageDto<User> {

    /**
     * AllArgsConstructor注解和NotNull注解配合使用，参数不为null
     */
    @NotNull(message = "Id不能为空")
    private Long id;

    private Date addTime;

    @NotNull(message = "用户名不能为空")
    private String username;

    //    @NotNull(message = "密码不能为空")
    private String password;

    private String verifyPassword;

    private String oldPassword;

    @ApiModelProperty("用户年龄")
    private Integer age;

    @ApiModelProperty("用户性别")
    private Integer sex;

    private String salt;

    @ApiModelProperty("角色ID字符串")
    private Integer[] role_id;

    @ApiModelProperty("默认0：普通用户 1：管理员 ")
    private String type;

    @ApiModelProperty("是否强制退出用户")
    private boolean flag;

    @ApiModelProperty("用户邮箱")
    private String email;

    @ApiModelProperty("手机号码")
    private String mobile;

    @ApiModelProperty("备注")
    private String note;

    @ApiModelProperty("组ID")
    private Long groupId;

    private Long[] userIds;

    private String groupLevel;
}