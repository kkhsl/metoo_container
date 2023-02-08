package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@ApiModel("虚拟化类型")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class VirtualType extends IdEntity {

    private String name;
}
