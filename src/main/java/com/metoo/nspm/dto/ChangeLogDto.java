package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class ChangeLogDto extends PageDto<ChangeLogDto> {

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
    private Long userId;
    @ApiModelProperty("变更内容")
    private String content;
    @ApiModelProperty("变更原因")
    private String changeReasons;
}
