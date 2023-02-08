package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

/**
 * <p>
 *     Title: Dept;
 * </p>
 *
 * <p>
 *     Description: 部门管理类；
 * </p>
 *
 * <author>
 *     HKK
 * </author>
 */

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
@ApiModel("部门实体类")
public class Dept extends IdEntity {

    @ApiModelProperty("部门名称")
    private String title;

    @ApiModelProperty("索引")
    private int sequence;

    @ApiModelProperty("级别")
    private int level;

    @ApiModelProperty("部门类型 平台 其他部门")
    private int type;

    @ApiModelProperty("部门联系人")
    private String contact;

    @ApiModelProperty("部门联系电话")
    private String telphone;

    @ApiModelProperty("部门简介")
    private String info;



}
