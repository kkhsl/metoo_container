package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.RoleGroup;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.ArrayList;
import java.util.List;

@ApiModel("角色组管理DTO")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class RoleGroupDto extends PageDto<RoleGroup> {

    @ApiModelProperty("角色ID")
    private Long id;

    @ApiModelProperty("角色组名称")
    private String name;

    @ApiModelProperty("角色组类型")
    private String type;

    @ApiModelProperty("角色ID字符串")
    private Integer[] role_id;

    @ApiModelProperty("角色ID集合")
    private List<Long> idList = new ArrayList<Long>();

    @ApiModelProperty("角色组下标")
    private Integer sequence;

   /* @ApiModelProperty("角色组图标")
    private Long iconId;*/

    @ApiModelProperty("角色组图标")
    private String icon;

    @ApiModelProperty("角色组路由：前端")
    private String url;

}
