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
@ApiModel("路由查询")
public class RouteTable extends IdEntity {

    @ApiModelProperty("设备Uuid")
    private String deviceUuid;
    @ApiModelProperty("设备名称")
    private String deviceName;
    @ApiModelProperty("接口名称")
    private String interfaceName;
    @ApiModelProperty("Ip地址")
    private String ip;
    @ApiModelProperty("Ip地址")
    private String ipAddress;
    @ApiModelProperty("Ip掩码")
    private String mask;
    @ApiModelProperty("Ip地址")
    private String ipSegment;
    @ApiModelProperty("Mac地址")
    private String mac;
    @ApiModelProperty("接口序号")
    private Integer index;
    @ApiModelProperty("接口序号")
    private String cidr;
    @ApiModelProperty("对端设备集合")
    private String remoteDevices;
    @ApiModelProperty("对端设备")
    private String remoteDevice;
    @ApiModelProperty("对端接口")
    private String remoteInterface;
    @ApiModelProperty("对端Uuid")
    private String remoteUuid;
    private int status;// 路由状态 0：正常 1：没有下一跳 2：路由环路
}
