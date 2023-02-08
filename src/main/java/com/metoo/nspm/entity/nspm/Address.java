package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("IP地址表")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class Address extends IdEntity {


    @ApiModelProperty("Ip地址")
    private String ip;
    @ApiModelProperty("Mac地址")
    private String mac;
    @ApiModelProperty("主机名称")
    private String hostName;
    @ApiModelProperty("子网Id")
    private Long subnetId;
    @ApiModelProperty("描述")
    private String description;
    private IpDetail ipDetail;


}
