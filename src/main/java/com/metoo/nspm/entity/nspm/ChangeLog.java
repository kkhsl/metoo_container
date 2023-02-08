package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@ApiModel("变更记录")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ChangeLog extends IdEntity {

    @ApiModelProperty("名称")
    private String objectName;
    @ApiModelProperty("名称")
    private Long objectId;
    @ApiModelProperty("设备类型")
    private String deviceType;
    @ApiModelProperty("设备Id")
    private Long deviceId;
    @ApiModelProperty("设备名称")
    private String deviceName;
    @ApiModelProperty("操作账号")
    private String userName;
    @ApiModelProperty("操作账号Id")
    private Long userId;
    @ApiModelProperty("变更内容")
    private String content;
    @ApiModelProperty("变更原因")
    private String changeReasons;
}
