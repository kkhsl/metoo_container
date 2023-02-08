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
 *     Title: Accessory.java
 * </p>
 *
 * <p>
 *     Description: 系统附件管理类，图片附件; 测试Mysql字段和实体类属性名不同案例；后续可更改为一直属性
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
@ApiModel("系统附件实体类")
public class Accessory extends IdEntity {

    @ApiModelProperty("附件名称")
    private String a_name;
    @ApiModelProperty("附件存放路径")
    private String a_path;
    @ApiModelProperty("附件扩展名，不包含点")
    private String a_ext;
    @ApiModelProperty("宽度")
    private String a_width;
    @ApiModelProperty("高度")
    private String a_height;
    @ApiModelProperty("附件大小")
    private Integer a_size;
    @ApiModelProperty("附件对应的用户，精细化管理用户附件")
    private Long a_userId;
    @ApiModelProperty("附件类型0：图片 1：录播视频 2：回放视频 3：其他")
    private Integer type;

}
