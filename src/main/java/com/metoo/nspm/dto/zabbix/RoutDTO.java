package com.metoo.nspm.dto.zabbix;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.IpAddress;
import com.metoo.nspm.entity.nspm.Route;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.Date;

@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class RoutDTO extends  PageDto<Route> {
    private String mask;
    private String destination;
    private String cost;
    private String flags;
    private String nextHop;
    private String interfaceName;
    private String deviceName;
    @ApiModelProperty("设备Uuid")
    private String deviceUuid;
    private String proto;
    private IpAddress ipAddress;
    @ApiModelProperty("采集时间")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm",timezone = "GMT+8")
    private Date time;
    private String network;
    private String broadcast;
}
