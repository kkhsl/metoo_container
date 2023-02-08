package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("链路管理")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class Link extends IdEntity {

    @ApiModelProperty("名称")
    private String name;
    @ApiModelProperty("介质 0：光纤 1：网线")
    private Integer transmitter;
    @ApiModelProperty("类型 0：物理链路 1：逻辑链路")
    private Integer type;
//    @ApiModelProperty("带宽 单位（b：字节）")
//    private int bandwidth;
    private String bandwidth;
    @ApiModelProperty("状态 0：Actice 1:Not actice")
    private Integer status;
    @ApiModelProperty("起点设备")
    private String startDevice;
    @ApiModelProperty("起点端口")
    private String startInterface;
    @ApiModelProperty("起点Ip")
    private String startIp;
    @ApiModelProperty("终点设备")
    private String endDevice;
    @ApiModelProperty("终点端口")
    private String endInterface;
    @ApiModelProperty("终点Ip")
    private String endIp;
    @ApiModelProperty("描述")
    private String description;
    private Long groupId;
    private String groupName;

}
