package com.metoo.nspm.vo;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@ApiModel("菜单管理")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class MenuVo {
  /*  @ApiModelProperty("角色组ID")
    private Long roleGroupId;

    @ApiModelProperty("角色组名称")
    private String roleGroupName;

    @ApiModelProperty("ICON")
    private String roleGroupIcon;

    @ApiModelProperty("角色组路由：前端")
    private String roleGroupUrl;

    @ApiModelProperty("角色信息")
    private List<RoleReq> role;
*/
    // ===

    @ApiModelProperty("资源Id")
    private String id;

    @ApiModelProperty("资源名称")
    private String name;

    private String value;

    @ApiModelProperty("路由")
    private String url;

    @ApiModelProperty("组件")
    private String component;

    @ApiModelProperty("组件名称")
    private String componentName;

    @ApiModelProperty("索引")
    private Integer sequence;

    @ApiModelProperty("等级")
    private Integer level;

    @ApiModelProperty("图标")
    private String icon;
    @ApiModelProperty("显示隐藏")
    private boolean hidden;

    @ApiModelProperty("权限子集")
    private List<MenuVo> childrenList;
}
