package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@ApiModel("路由表:Routing table 临时表，记录并计算rout表")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class RouteTemp extends IdEntity {

    private String mask;
    private Integer maskBit;
    private String destination;
    private String cost;
    private String flags;
    private String nextHop;
    private String interfaceName;
    private String deviceName;
    private String deviceIp;
    @ApiModelProperty("设备Uuid")
    private String deviceUuid;
    private String proto;
    private IpAddress ipAddress;
    private String routeproto;
}
