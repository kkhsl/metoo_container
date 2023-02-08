package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@ApiModel("设备类型")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class DeviceType extends IdEntity {

    private String name;
    private Integer type;
    private Integer count;
    private Integer online;
    private List<NetworkElement> networkElementList;
}
