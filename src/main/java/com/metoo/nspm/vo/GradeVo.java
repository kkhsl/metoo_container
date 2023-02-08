package com.metoo.nspm.vo;

import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class GradeVo{

    @ApiModelProperty("年级ID")
    private Long id;

    @ApiModelProperty("年级名称")
    private String name;

    @ApiModelProperty("图片ID")
    private Long accessory_id;

    @ApiModelProperty("图片名称")
    private String accessory_name;

    @ApiModelProperty("图片路径")
    private String accessory_path;
}
