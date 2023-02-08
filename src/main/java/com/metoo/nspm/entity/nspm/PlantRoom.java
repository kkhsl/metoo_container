package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PlantRoom extends IdEntity {

    @ApiModelProperty("名称")
    private String name;
    @ApiModelProperty("描述")
    private String description;
    @ApiModelProperty("机柜")
    private List<Rack> rackList = new ArrayList<>();
    @ApiModelProperty("用户")
    private Long userId;
    @ApiModelProperty("机柜数量")
    private Integer rack_number;
    @ApiModelProperty("变更原因")
    private String change_reasons;
    private boolean isDefault;

}
