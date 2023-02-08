package com.metoo.nspm.entity.nspm;


import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.ArrayList;
import java.util.List;

@ApiModel("角色组实体类")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class RoleGroup extends IdEntity {

    @ApiModelProperty("角色组名称")
    private String name;

    @ApiModelProperty("角色索引")
    private Integer sequence;

    @ApiModelProperty("角色组类型 例：BUYER SELLER ADMIN")
    private String type;

    @ApiModelProperty("角色")
    private List<Role> roles = new ArrayList<Role>();

   /* @ApiModelProperty("角色组图标")
    private Accessory icon;
*/

    @ApiModelProperty("角色组图标")
    private String icon;

    @ApiModelProperty("角色组路由：前端")
    private String url;
}
