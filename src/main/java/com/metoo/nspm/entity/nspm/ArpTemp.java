package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("临时数据")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class ArpTemp extends IdEntity {

    @ApiModelProperty("设备Ip")
    private String deviceIp;
    @ApiModelProperty("设备名称")
    private String deviceName;
    @ApiModelProperty("设备类型")
    private String deviceType;
    @ApiModelProperty("接口名称")
    private String interfaceName;
    @ApiModelProperty("接口序号")
    private String index;
    @ApiModelProperty("ip地址")
    private String ip;
    @ApiModelProperty("ip地址")
    private String ipAddress;
    @ApiModelProperty("MAC地址")
    private String mac;
    @ApiModelProperty("厂商")
    private String macVendor;
    @ApiModelProperty("标记")
    private String tag;
    @ApiModelProperty("对端设备名称")
    private String remoteDevice;
    @ApiModelProperty("对端接口名称")
    private String remoteInterface;
    @ApiModelProperty("对端设备类型")
    private String remoteDeviceType;
    @ApiModelProperty("对端Ip")
    private String remoteDeviceIp;
    @ApiModelProperty("对端Ip")
    private String remoteIp;
    @ApiModelProperty("对端Uuid")
    private String remoteUuid;
    private String segment;
    private String mask;
    private String uuid;


}
