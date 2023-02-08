package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.Credential;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.Set;

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class CredentialDTO extends PageDto<Credential> {

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

    private Long groupId;
    private String groupName;
    private Set<Long> groupIds;

    private String credentialId;

}
