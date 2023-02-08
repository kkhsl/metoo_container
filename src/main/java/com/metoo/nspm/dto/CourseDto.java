package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.Course;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;
@ApiModel("年级DTO")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class CourseDto extends PageDto<Course> {

    @ApiModelProperty("科目ID")
    private Long id;

    @ApiModelProperty("科目名称")
    private String name;

    @ApiModelProperty("预留字段；科目等级，除普通科目外其他科目")
    private Integer level;

    @ApiModelProperty("科目索引")
    private Integer sequence;

    @ApiModelProperty("科目描述")
    private String message;

    @ApiModelProperty("是否显示")
    private int display;
}
