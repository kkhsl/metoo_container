package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
@ApiModel("ip地址表")
public class IpDetail extends IdEntity {

    private String deviceName;
    @ApiModelProperty("Ip地址")
    private String ip;
    @ApiModelProperty("Ip地址")
    private String ipSegment;
    @ApiModelProperty("Mac地址")
    private String mac;
    @ApiModelProperty("接口序号")
    private Integer sequence;
    private boolean online;
    private int time;
    private String duration;
    private Integer usage;
    private String description;


}
