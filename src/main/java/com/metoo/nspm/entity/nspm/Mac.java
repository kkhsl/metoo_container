package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;


@ApiModel("介质访问控制:Media Access Control")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class Mac extends IdEntity {

    @ApiModelProperty("设备名称")
    private String deviceIp;
    @ApiModelProperty("设备名称")
    private String deviceName;
    @ApiModelProperty("设备名称")
    private String deviceType;
    @ApiModelProperty("接口名称")
    private String interfaceName;
    @ApiModelProperty("Mac地址")
    private String mac;
    @ApiModelProperty("Mac标记")
    private String tag;
    @ApiModelProperty("Mac索引")
    private String index;
    @ApiModelProperty("索引")
    private String uuid;
    @ApiModelProperty("接口索引")
    private String interfaceIndex;
    @ApiModelProperty("接口ip")
    private String ip;
    @ApiModelProperty("接口ip")
    private String ipAddress;
    @ApiModelProperty("对端设备名称")
    private String remoteDevice;
    @ApiModelProperty("对端接口名称")
    private String remoteInterface;
    @ApiModelProperty("对端设备Ip")
    private String remoteDeviceIp;
    @ApiModelProperty("对端设备类型")
    private String remoteDeviceType;
    private String remoteUuid;
    private String vendor;
    private String vlan;
}
