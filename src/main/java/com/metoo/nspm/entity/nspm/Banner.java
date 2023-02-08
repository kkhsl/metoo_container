package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("Banner管理")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class Banner extends IdEntity {

    @ApiModelProperty("Banner标题")
    private String title;

    @ApiModelProperty("Banner索引 ASC")
    private Integer sequence;

    @ApiModelProperty("Banner 是否显示")
    private Integer display;

    @ApiModelProperty("轮播图路由")
    private String url;

    @JsonIgnore
    @ApiModelProperty("轮播图附件")
    private Accessory accessory;

    @ApiModelProperty("轮播图附件ID")
    private Long accessoryId;

    @ApiModelProperty("轮播图附件路径")
    private String accessoryPath;
}
