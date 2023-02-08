package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

/**
 * <p>
 *     Title: UserRole.java
 * </p>
 *
 * <p>
 *     Description: 用户角色管理类；
 * </p>
 *
 *
 */

@ApiModel("用户角色实体类")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class UserRole extends IdEntity {

    @ApiModelProperty("用户ID")
    private Long user_id;

    @ApiModelProperty("角色ID")
    private Long role_id;

}
