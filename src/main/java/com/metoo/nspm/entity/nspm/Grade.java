package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

/**
 * 第一种方式: 年级、科目单独管理
 *
 * 第二种方式 年级，关联科目
 */

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
@ApiModel("年级科目管理")
public class Grade extends IdEntity {

    @ApiModelProperty("年级/科目名称")
    private String name;

    @ApiModelProperty("等级")
    private int level;

    @ApiModelProperty("排序")
    private int sequence;

    @ApiModelProperty("年级主任/科目老师 名称")
    private String username;

    @ApiModelProperty("年级/科目 老师ID")
    private Long user_id;

    @ApiModelProperty("预留字段，科目管理0：科目管理")
    private int type;

    @ApiModelProperty("上级ID")
    private Long parent_id;

    @ApiModelProperty("是否显示")
    private int display;

    @ApiModelProperty("年级/科目 描述/格言")
    private String message;

    @ApiModelProperty("关联附件")
    private Accessory accessory;

}
