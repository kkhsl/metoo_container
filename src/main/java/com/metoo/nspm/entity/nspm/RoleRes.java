package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("角色权限实体类")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class RoleRes extends IdEntity {

    @ApiModelProperty("角色ID")
    private Long role_id;

    @ApiModelProperty("资源ID")
    private Long res_id;


}
