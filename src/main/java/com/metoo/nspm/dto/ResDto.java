package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.Res;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@ApiModel("权限管理")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class ResDto extends PageDto<Res> {

    @ApiModelProperty("资源ID")
    private Long id;

    @ApiModelProperty("资源名称")
    private String name;

    private String value;

    @ApiModelProperty("角色ID")
    private Long role_id;

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

    @ApiModelProperty("权限子集")
    private List<ResDto> childrenList;

    @ApiModelProperty("权限父级")
    private List<ResDto> parentList;

    @ApiModelProperty("父级ID")
    private Long parentId;

    @ApiModelProperty("父级名称")
    private String parentName;

    @ApiModelProperty("组件图标")
    private String icon;

    @ApiModelProperty("显示隐藏")
    private boolean hidden;

}
