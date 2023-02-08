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
 *     Title: ProgramPlayback.java
 * </p>
 *
 * <p>
 *     Description: 视频回放管理类
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
@ApiModel("直播回放实体类：deprecated")
public class ProgramPlayback extends IdEntity {

    @ApiModelProperty("回放信息标题")
    private String title;

    @ApiModelProperty("直播间Id")
    private Long RoomId;

    @ApiModelProperty("直播节目Id")
    private Long programId;

    @ApiModelProperty("回放路径")
    private String path;

    @ApiModelProperty("创建回放 0: 创建成功 1：创建失败")
    private Integer create;

    @ApiModelProperty("")
    private String rtmp;

}
