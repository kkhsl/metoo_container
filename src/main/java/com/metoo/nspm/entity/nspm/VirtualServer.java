package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@ApiModel("虚拟服务器")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class VirtualServer extends IdEntity {

    @ApiModelProperty("服务器名")
    private String name;
    @ApiModelProperty("主机名")
    private String host_name;
    @ApiModelProperty("ip地址")
    private String ip;
    @ApiModelProperty("状态0：在线 1：离线")
    private Boolean status;
    @ApiModelProperty("虚拟化类型")
    private Long virtual_type_id;
    @ApiModelProperty("虚拟化类型名称")
    private String virtual_type_name;
    @ApiModelProperty("宿主机")
    private Long device_id;
    @ApiModelProperty("宿主机名称")
    private String device_name;
    @ApiModelProperty("CPU型号")
    private String cpuModel;
    @ApiModelProperty("CPU（单位：核）")
    private String cpu;
    @ApiModelProperty("内存（单位：GB）")
    private String memory;
    @ApiModelProperty("硬盘容量（单位：GB）")
    private String hard_disk;
    @ApiModelProperty("操作系统")
    private Long operation_system_id;
    @ApiModelProperty("操作系统名称")
    private String operation_system_name;
    @ApiModelProperty("系统版本")
    private String version;
    @ApiModelProperty("备注")
    private String remark;
    @ApiModelProperty("变更原因")
    private String changeReasons;
    private Long userId;
    private String userName;
}
