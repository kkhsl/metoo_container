package com.metoo.nspm.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("磁盘告警模型")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class SysWarnMessageModelDto {
    @ApiModelProperty("每页的条数")
    private Integer limit;
    @ApiModelProperty("从哪开始分页")
    private Integer offset;
    @ApiModelProperty("根据什么字段排序")
    private String sort;
    @ApiModelProperty("排序方式:asc或者desc")
    private String order;
    private static final long serialVersionUID = -4132080872205033188L;
    @ApiModelProperty("类型(disk_warn:磁盘告警)")
    private String warnType;
    @ApiModelProperty("状态，（0:有效，1:无效）")
    private Integer status;
    @ApiModelProperty("告警值")
    private Integer warnValue;
    @ApiModelProperty("时间戳：秒")
    private Long warnTime;
    @ApiModelProperty("阀值")
    private Integer thresholdValue;
    @ApiModelProperty("告警信息")
    private String warnMessage;
    @ApiModelProperty("开始时间")
    private Long timeFrom;
    @ApiModelProperty("结束时间")
    private Long timeTo;
    @ApiModelProperty("子节点ip地址")
    private String ipAddress;

}
