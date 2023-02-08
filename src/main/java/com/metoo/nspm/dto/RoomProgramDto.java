package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.RoomProgram;
import com.fasterxml.jackson.annotation.JsonFormat;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;
import org.springframework.format.annotation.DateTimeFormat;

import java.util.Date;

@ApiModel("直播节目DTO")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class RoomProgramDto extends PageDto<RoomProgram> {

    private Long id;

    @ApiModelProperty("直播节目名称")
    private String title;

    @DateTimeFormat(pattern = "yyyy-MM-dd") //入参
    @JsonFormat(timezone = "GMT+8", pattern = "yyyy-MM-dd") //出参
    private Date beginTime;

    @DateTimeFormat(pattern = "yyyy-MM-dd") //入参
    @JsonFormat(timezone = "GMT+8", pattern = "yyyy-MM-dd") //出参
    private Date endTime;

    private Long userId;

    @ApiModelProperty("直播节目创建人")
    private String userName;

    @ApiModelProperty("直播节目状态 0: 关闭 1：开启")
    private Integer status;

    @ApiModelProperty("视频流默认0：停止 1：开启 deprecated")
    private Integer live;

    @ApiModelProperty("直播节目类型 0:查询普通用户直播")
    private Integer type;

    @ApiModelProperty("直播节目简介")
    private String info;

    @ApiModelProperty("节目海报/封面")
    private String poster;

    @ApiModelProperty("所属直播间ID")
    private Long RoomId;

    @ApiModelProperty("所属直播间名称")
    private String roomName;

    @ApiModelProperty("讲师")
    private String lecturer;

    @ApiModelProperty("年级")
    private Long grade_id;

    @ApiModelProperty("科目")
    private Long course_id;

    @ApiModelProperty("直播封面")
    private Long cover;

    @ApiModelProperty("是否需要生成回放视频0：不生成 1：生成")
    private Integer isPlayback;

}
