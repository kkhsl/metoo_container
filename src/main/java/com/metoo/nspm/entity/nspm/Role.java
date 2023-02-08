package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

/**
 * <p>
 *     Title: Role.java
 * </p>
 *
 * <p>
 *     Description: 角色管理；
 * </p>
 *
 * <author>
 *     HKK
 * </author>
 */
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
@ApiModel("角色实体类")
public class Role extends IdEntity {

    @ApiModelProperty("角色名称")
    private String name;

    @JsonIgnore
    @ApiModelProperty("角色编码，根据改编码识别角色")
    private String roleCode;

    @JsonIgnore
    @ApiModelProperty("角色类型")
    private String type;

    @ApiModelProperty("角色说明")
    private String info;

    @ApiModelProperty("权限集合")
    private List<Long> res_ids;

    @JsonIgnore
    @ApiModelProperty("角色对应的组")
    private RoleGroup roleGroup;

    @JsonIgnore
    @ApiModelProperty("角色路由：前端")
    private String url;

    @JsonIgnore
    @ApiModelProperty("角色组件路由：前端")
    private String component;

    @ApiModelProperty("角色组下标")
    private Integer sequence;
}
