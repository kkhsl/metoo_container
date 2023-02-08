package com.metoo.nspm.dto;

import com.alibaba.fastjson.annotation.JSONField;
import com.alibaba.fastjson.serializer.DoubleSerializer;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.RsmsDevice;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.Set;

@Api("Rsms 设备")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class RsmsDeviceDTO extends PageDto<RsmsDevice> {

    private Long id;
    private String filter;
    @ApiModelProperty("名称")
    private String name;
    @ApiModelProperty("ip")
    private String ip;
    @ApiModelProperty("设备类型")
    private Long deviceTypeId;
    @ApiModelProperty("设备类型名称")
    private String deviceTypeName;
    @ApiModelProperty("厂商ID")
    private Long vendorId;
    @ApiModelProperty("厂商名称")
    private String vendorName;
    @ApiModelProperty("分组ID")
    private Long groupId;
    @ApiModelProperty("分组名称")
    private String groupName;
    @ApiModelProperty("机房")
    private Long plantRoomId;
    @ApiModelProperty("机房名称")
    private String plantRoomName;
    @ApiModelProperty("用户")
    private Long userId;
    @ApiModelProperty("机柜")
    private Long rackId;
    @ApiModelProperty("机柜名称")
    private String rackName;
    @ApiModelProperty("是否显示背面")
    private boolean rear;
    @ApiModelProperty("开始位置")
    private Integer start;
    @ApiModelProperty("大小")
    private Integer size;
    @ApiModelProperty("描述")
    private String description;
    @ApiModelProperty("资产编号")
    private String asset_number;
    @ApiModelProperty("主机名")
    private String host_name;
    @ApiModelProperty("状态 0：离线 1：在线")
    private Boolean status;
    @ApiModelProperty("型号")
    private String model;
    @ApiModelProperty("采购时间")
    @JsonFormat(pattern = "yyyy-MM-dd",timezone = "GMT+8")
    private Date purchase_time;
    @ApiModelProperty("过保时间")
    @JsonFormat(pattern = "yyyy-MM-dd",timezone = "GMT+8")
    private Date warranty_time;
    @JSONField(name="price",serializeUsing = DoubleSerializer.class)
    @ApiModelProperty("价格")
    private Double price;
    @ApiModelProperty("序列号")
    private String serial_number;
    @ApiModelProperty("责任人")
    private String duty;
    @ApiModelProperty("变更原因")
    private String changeReasons;
    private String uuid;
    @ApiModelProperty("项目Id")
    private Long projectId;
    @ApiModelProperty("项目名")
    private String projectName;
    private Set<Long> groupIds;

    @JsonFormat(pattern = "yyyy-MM-dd",timezone = "GMT+8")
    private Date start_purchase_time;
    @JsonFormat(pattern = "yyyy-MM-dd",timezone = "GMT+8")
    private Date end_purchase_time;
    @ApiModelProperty("过保时间")
    @JsonFormat(pattern = "yyyy-MM-dd",timezone = "GMT+8")
    private Date start_warranty_time;
    @JsonFormat(pattern = "yyyy-MM-dd",timezone = "GMT+8")
    private Date end_warranty_time;

}
