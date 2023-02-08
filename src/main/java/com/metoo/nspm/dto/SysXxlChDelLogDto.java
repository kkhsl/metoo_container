package com.metoo.nspm.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("磁盘管理相关日志的模型")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class SysXxlChDelLogDto {

    private static final long serialVersionUID = -1870571841790468489L;
    @ApiModelProperty("主键id")
    private Integer logId;
    @ApiModelProperty("对象名称(分区，表)")
    private String objName;
    @ApiModelProperty("对象值(分区名,表名)")
    private String objValue;
    @ApiModelProperty("对象类型(syslog:原始日志,biz_data:业务数据，disk_warn:磁盘告警)")
    private String objType;
    @ApiModelProperty("状态，（0：有效，1，无效）")
    private Integer status;
    @ApiModelProperty("时间戳:秒")
    private Long delTime;
    @ApiModelProperty("开始时间")
    private Long timeFrom;
    @ApiModelProperty("结束时间")
    private Long timeTo;
    @ApiModelProperty("子节点ip地址")
    private String ipAddress;
    @ApiModelProperty("每页的条数")
    private Integer limit;
    @ApiModelProperty("从哪开始分页")
    private Integer offset;
    @ApiModelProperty("根据什么字段排序")
    private String sort;
    @ApiModelProperty("排序方式:asc或者desc")
    private String order;
}
