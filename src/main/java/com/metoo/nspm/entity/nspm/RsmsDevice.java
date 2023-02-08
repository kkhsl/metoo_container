package com.metoo.nspm.entity.nspm;

import com.alibaba.fastjson.annotation.JSONField;
import com.alibaba.fastjson.serializer.DoubleSerializer;
import com.metoo.nspm.core.config.annotation.excel.ExcelImport;
import com.metoo.nspm.core.domain.IdEntity;
import com.fasterxml.jackson.annotation.JsonFormat;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;

import java.util.Date;

@Api("Rsms 设备")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class RsmsDevice extends IdEntity {

    @ExcelImport(value = "设备名称", required = true, unique = true)
    @ApiModelProperty("名称")
    private String name;
    @ExcelImport("IP地址")
    @ApiModelProperty("ip")
    private String ip;
    @ApiModelProperty("设备类型")
    private Long deviceTypeId;
    @ExcelImport("设备类型")
    @ApiModelProperty("设备类型名称")
    private String deviceTypeName;
    @ApiModelProperty("厂商ID")
    private Long vendorId;
    @ExcelImport("品牌")
    @ApiModelProperty("厂商名称")
    private String vendorName;
    @ApiModelProperty("分组ID")
    private Long groupId;
    @ExcelImport("分组")
    @ApiModelProperty("分组名称")
    private String groupName;
    @ApiModelProperty("机房")
    private Long plantRoomId;
    @ExcelImport("机房")
    @ApiModelProperty("机房名称")
    private String plantRoomName;
    @ApiModelProperty("用户")
    private Long userId;
    @ApiModelProperty("机柜")
    private Long rackId;
    @ExcelImport("机柜")
    @ApiModelProperty("机柜名称")
    private String rackName;
    @ApiModelProperty("是否显示背面")
    private boolean rear;
    @ExcelImport("开始位置")
    @ApiModelProperty("开始位置")
    private Integer start;
    @ExcelImport("大小")
    @ApiModelProperty("大小")
    private Integer size;
    @ApiModelProperty("描述")
    private String description;
    @ExcelImport("资产编号")
    @ApiModelProperty("资产编号")
    private String asset_number;
    @ExcelImport("主机名")
    @ApiModelProperty("主机名")
    private String host_name;
    @ExcelImport("状态")
    @ApiModelProperty("状态 0：离线 1：在线")
    private Boolean status;
    @ExcelImport("型号")
    @ApiModelProperty("型号")
    private String model;
    @ExcelImport("采购时间")
    @ApiModelProperty("采购时间")
    @DateTimeFormat(pattern="yyyy-MM-dd")
    @JsonFormat(pattern = "yyyy-MM-dd",timezone = "GMT+8")
    private Date purchase_time;
    @ExcelImport("过保时间")
    @ApiModelProperty("过保时间")
    @DateTimeFormat(pattern="yyyy-MM-dd")
    @JsonFormat(pattern = "yyyy-MM-dd",timezone = "GMT+8")
    private Date warranty_time;
    @JSONField(name="price",serializeUsing = DoubleSerializer.class)
    @ApiModelProperty("价格")
    private Double price;
    @ApiModelProperty("序列号")
    private String serial_number;
    @ExcelImport("责任人")
    @ApiModelProperty("责任人")
    private String duty;
    @ApiModelProperty("变更原因")
    private String changeReasons;
    private String uuid;
    @ApiModelProperty("项目Id")
    private Long projectId;
    @ExcelImport("项目")
    @ApiModelProperty("项目名")
    private String projectName;


    private Integer rowNum;
    private String rowData;
    private String rowTips;

}
