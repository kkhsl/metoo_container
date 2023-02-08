package com.metoo.nspm.vo;

import com.fasterxml.jackson.annotation.JsonFormat;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;
import org.springframework.format.annotation.DateTimeFormat;

import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class UserVo {

    /**
     * AllArgsConstructor注解和NotNull注解配合使用，参数不为null
     */
    @NotNull(message = "id is null")
    private Long id;

    @DateTimeFormat(pattern="yyyy-MM-dd HH:mm:ss")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss",timezone = "GMT+8")
    private Date addTime;

    @NotNull(message = "username is null")
    private String username;

    @NotNull(message = "password is null")
    private String password;

    @ApiModelProperty("用户年龄")
    private Integer age;

    @ApiModelProperty("用户性别")
    private Integer sex;

    @ApiModelProperty("用户性别")
    private String type;

    @ApiModelProperty("用户角色")
    private String userRole;

    @ApiModelProperty("角色ID集合")
    private List<Long> roleIds = new ArrayList<Long>();

    @ApiModelProperty("用户邮箱")
    private String email;

    @ApiModelProperty("手机号码")
    private String mobile;

    @ApiModelProperty("备注")
    private String note;

    @ApiModelProperty("组ID")
    private Long groupId;

    @ApiModelProperty("组名称")
    private String groupName;

}
