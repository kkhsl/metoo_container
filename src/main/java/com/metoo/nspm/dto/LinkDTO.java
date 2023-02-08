package com.metoo.nspm.dto;

import com.metoo.nspm.core.domain.IdEntity;
import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.Link;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.Set;

@ApiModel("链路管理")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class LinkDTO extends PageDto<Link> {

    @ApiModelProperty("名称")
    private String name;
    @ApiModelProperty("介质 0：光纤 1：网线")
    private int transmitter;
    @ApiModelProperty("类型 0：物理链路 1：逻辑链路")
    private int type;
    @ApiModelProperty("带宽 单位（b：字节）")
//    private int bandwidth;
    private int bandwidth;
    @ApiModelProperty("状态 0：Actice 1:Not actice")
    private int status;
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
    private String desctiption;
    private Long groupId;
    private String groupName;
    private Set<Long> groupIds;

}
