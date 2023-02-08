package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@ApiModel("路由表:Routing table")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Route extends IdEntity {

    @ApiModelProperty("掩码")
    private String mask;
    @ApiModelProperty("掩码位")
    private Integer maskBit;
    @ApiModelProperty("终点IP")
    private String destination;
    private String cost;
    private String flags;
    @ApiModelProperty("下一跳")
    private String nextHop;
    private String interfaceName;
    private String deviceIp;
    private String deviceName;
    @ApiModelProperty("设备Uuid")
    private String deviceUuid;
    @ApiModelProperty("协议类型")
    private String proto;
    private IpAddress ipAddress;
    private String cidr;
}
