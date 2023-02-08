package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

/**
 * <p>
 *      Title: Res.java
 * </p>
 *
 * <p>
 *     Description: 系统权限资源管理类；用于记录系统权限信息，使用shiro进行对系统资源的访问控制
 * </p>
 *
 *  <author>
 *      HKK
 *  </author>
 */

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
@ApiModel("权限资源实体类")
public class  Res extends IdEntity {

    @ApiModelProperty("资源名称")
    private String name;

    @ApiModelProperty("资源值")
    private String value;

    @ApiModelProperty("资源类型")
    private String type;

    @ApiModelProperty("角色")
    private Role role;

    @ApiModelProperty("路由")
    private String url;

    @ApiModelProperty("组件")
    private String component;

    @ApiModelProperty("组件名称")
    private String componentName;

    @ApiModelProperty("组件图标")
    private String icon;

    @ApiModelProperty("索引")
    private Integer sequence;

    @ApiModelProperty("等级")
    private Integer level;

    @ApiModelProperty("childs")
    private List<Res> childrenList;

    @ApiModelProperty("父级ID")
    private Long parentId;

    @ApiModelProperty("父级名称")
    private String parentName;

    @ApiModelProperty("显示隐藏")
    private boolean hidden;
    /*@ApiModelProperty("角色集合")
    private List<Role> roles = new ArrayList<Role>();*/
}
