package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@ApiModel("虚拟服务器DTO")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class VirtualServerDto extends PageDto<VirtualServerDto> {


    @ApiModelProperty("名称")
    private String name;
    @ApiModelProperty("主机名称")
    private String host_name;
    @ApiModelProperty("ip地址")
    private String ip;
    @ApiModelProperty("状态 0：在线 1：离线")
    private boolean status;
    @ApiModelProperty("虚拟化类型ID")
    private Long virtual_type_id;
    @ApiModelProperty("虚拟化类型名称")
    private String virtual_type_name;
    @ApiModelProperty("设备ID")
    private Long device_id;
    @ApiModelProperty("设备名称")
    private String deviceName;
    @ApiModelProperty("CPU 单位：核")
    private String cpu;
    @ApiModelProperty("内存 单位：GB")
    private String memmory;
    @ApiModelProperty("硬盘 单位：GB")
    private String hard_disk;
    @ApiModelProperty("操作系统ID")
    private Long operation_system_id;
    @ApiModelProperty("操作系统名称")
    private String operation_system_name;
    @ApiModelProperty("系统版本 ")
    private String version;
    @ApiModelProperty("备注")
    private String remark;
    private Long userId;
    private String userNam;
}
