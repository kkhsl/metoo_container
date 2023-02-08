package com.metoo.nspm.req;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("角色组")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class RoleGroupReq {

    private Long id;
}
