package com.metoo.nspm.req;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("科目Req")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class CourseReq {

    @ApiModelProperty("科目ID")
    private Long id;

    @ApiModelProperty("是否显示")
    private Integer display;

}
