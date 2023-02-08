package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class Credential extends IdEntity {

    public static final String 通行认证是否开启 = "通行认证是否开启";
    private Integer currentPage = 1;// 当前页数
    private Integer pageSize = 15;// 每页条数

    @ApiModelProperty("凭据Uuid")
    private String uuid;
    @ApiModelProperty("凭据名")
    private String name;
    @ApiModelProperty("用户名")
    private String loginName;
    @ApiModelProperty("密码")
    private String loginPassword;
    @ApiModelProperty("通行用户名")
    private String enableUserName;
    @ApiModelProperty("通行密码")
    private String enablePassword;
    @ApiModelProperty("等级Id")
    private Long branchId;
    @ApiModelProperty("等级名称")
    private String branchName;
    @ApiModelProperty("等级")
    private String branchLevel;
    @ApiModelProperty("通行认证是否开启")
    private boolean trafficPermit;
    private Long userId;
    private String userName;
    private Long groupId;
    private String groupName;


    private String credentialId;
}
