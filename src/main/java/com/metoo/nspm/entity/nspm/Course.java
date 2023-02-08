package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
@ApiModel("科目管理类")
public class Course extends IdEntity {

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
