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
 *     Title: Item.java
 * </p>
 *
 * <p>
 *     Description: 栏目管理类；语文、数学、java;
 * </p>
 */
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
@ApiModel("栏目实体类")
public class Item extends IdEntity {

    @ApiModelProperty("栏目标题")
    private String title;

    @ApiModelProperty("索引")
    private int sequence;

}
