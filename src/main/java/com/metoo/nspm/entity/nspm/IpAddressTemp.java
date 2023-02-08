package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
@ApiModel("Ip临时数据")
public class IpAddressTemp extends IdEntity {

    @ApiModelProperty("Ip地址")
    private String ip;
    @ApiModelProperty("设备名称")
    private String deviceName;
    @ApiModelProperty("Mac地址")
    private String mac;
    @ApiModelProperty("Mac地址")
    private String mask;

    @ApiModelProperty("设备Uuid")
    private String deviceUuid;
    @ApiModelProperty("接口名称")
    private String interfaceName;
    @ApiModelProperty("Ip地址")
    private String ipAddress;
    @ApiModelProperty("Ip地址")
    private String ipSegment;
    @ApiModelProperty("接口序号")
    private Integer index;
    @ApiModelProperty("接口序号")
    private String cidr;
    private List<Route> routs;
    private boolean isError;
    private int status;// 路由状态 0：正常 1：没有下一跳 2：路由环路
}
