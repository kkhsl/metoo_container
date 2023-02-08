package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RackDTO extends PageDto<RackDTO> {

    @ApiModelProperty("机柜名称")
    private String name;
    @ApiModelProperty("机柜大小")
    private Integer size;
    @ApiModelProperty("是否显示背面")
    private boolean rear;
    @ApiModelProperty("机房")
    private Long plantRoomId;
    @ApiModelProperty("用户")
    private Long userId;
    @ApiModelProperty("描述")
    private String description;
    @ApiModelProperty("/设备数量")
    private Integer number;

    @ApiModelProperty("资产编号")
    private String asset_number;
    @ApiModelProperty("变更原因")
    private String change_reasons;
}
