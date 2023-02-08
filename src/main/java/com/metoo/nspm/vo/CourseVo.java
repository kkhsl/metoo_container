package com.metoo.nspm.vo;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("科目")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class CourseVo {

    @ApiModelProperty("科目ID")
    private Long id;

    @ApiModelProperty("科目名称")
    private String name;
}
