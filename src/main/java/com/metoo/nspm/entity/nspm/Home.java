package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Home extends IdEntity {

    @ApiModelProperty("菜单名称")
    private String name;
    @ApiModelProperty("索引")
    private Integer sequence;
    @ApiModelProperty("是否开启")
    private boolean display;// 默认0：关闭 1：开启

}
