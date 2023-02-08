package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@ApiModel("缺少设备Ip")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class LocalIpAddress extends IdEntity {

    private String deviceName;
    @ApiModelProperty("ip")
    private String ip;
    @ApiModelProperty("Ip地址")
    private String ipSegment;
    @ApiModelProperty("下标")
    private Integer sequence;

}
