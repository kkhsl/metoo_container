package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.Role;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;


@ApiModel("角色管理DTO")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class RoleDto extends PageDto<Role> {

    @ApiModelProperty("角色ID")
    private Long id;

    @ApiModelProperty("角色名称")
    private String name;

    @ApiModelProperty("角色类型")
    private String type;

    @ApiModelProperty("角色下标")
    private Integer sequence;

    @ApiModelProperty("角色描述")
    private String info;

    @ApiModelProperty("角色Code")
    private String roleCode;

    @ApiModelProperty("角色组ID")
    private Long rg_id;

    @ApiModelProperty("角色所有权限集合")
    private Integer[] res_id;

    @ApiModelProperty("角色路由")
    private String url;

    @ApiModelProperty("角色组件路由")
    private String component;



}
