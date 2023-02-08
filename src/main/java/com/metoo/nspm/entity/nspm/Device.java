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

@ApiModel("设备")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class Device extends IdEntity {

    @ApiModelProperty("设备名称")
    private String name;
    @ApiModelProperty("设备索引")
    private Integer index;
    @ApiModelProperty("厂商")
    private List<Vendor> vendorList = new ArrayList<>();
}
