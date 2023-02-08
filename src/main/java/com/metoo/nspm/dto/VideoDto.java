package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.Accessory;
import com.metoo.nspm.entity.nspm.Video;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;


@ApiModel("视频DTO")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class VideoDto extends PageDto<Video> {

    private Long id;

    private String name;

    private Integer addTime;

    private String beginTime;

    private String endTime;

    private Integer sequence;

    private String path;

    private String rtmp;

    private Long liveRoomId;

    private Long roomProgramId;

    private Long userId;

    private String userName;

    private Long grade_id;

    private Long course_id;

    private String describe;

    private Integer display;

    private Integer status;

    private String message;

    private Accessory accessory;

    private Accessory video;

    private Integer currentPage;

    private Integer PageSize;

    @ApiModelProperty("视频类型 0：普通用户 1：管理员 Type属性被占用，使用genre")
    private Integer genre;

    private Integer type; // 视频类型 0：录播 1：回放

    private Integer isEnable;

    private String lecturer;

    @ApiModelProperty("封面附件ID")
    private Long photoId;

    @ApiModelProperty("视频附件ID")
    private Long videoId;


}
