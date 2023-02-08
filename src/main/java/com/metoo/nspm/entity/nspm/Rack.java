package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.config.annotation.excel.ExcelImport;
import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@ApiModel("机柜")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Rack extends IdEntity {

    @ExcelImport(value = "名称")
    @ApiModelProperty("机柜名称")
    private String name;
    @ExcelImport(value = "大小")
    @ApiModelProperty("机柜大小")
    private Integer size;
    private int surplusSize;
    @ExcelImport(value = "背面")
    @ApiModelProperty("是否显示背面")
    private Boolean rear;
    @ApiModelProperty("机房")
    private Long plantRoomId;
    @ExcelImport(value = "机房")
    @ApiModelProperty("机房名称")
    private String plantRoomName;
    @ApiModelProperty("用户")
    private Long userId;
    @ExcelImport(value = "描述")
    @ApiModelProperty("描述")
    private String description;
    @ApiModelProperty("设备数量")
    private Integer number;
    @ExcelImport(value = "资产编号")
    @ApiModelProperty("资产编号")
    private String asset_number;
    @ApiModelProperty("变更原因")
    private String change_reasons;


    private Integer rowNum;
    private String rowData;
    private String rowTips;

}
