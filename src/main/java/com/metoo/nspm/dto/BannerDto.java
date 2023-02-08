package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.Banner;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("BannerDto")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class BannerDto extends PageDto<Banner> {

    @ApiModelProperty("Banner ID")
    private Long id;

    @ApiModelProperty("Banner标题")
    private String title;

    @ApiModelProperty("Banner索引 ASC")
    private Integer sequence;

    @ApiModelProperty("Banner 是否显示")
    private Integer display;

    @ApiModelProperty("轮播图路由")
    private String url;

    @ApiModelProperty("轮播图附件ID")
    private Long accessoryId;


}
