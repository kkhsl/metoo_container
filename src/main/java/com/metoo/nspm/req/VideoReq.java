package com.metoo.nspm.req;

import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.Video;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("视频Req")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class VideoReq extends PageDto<Video> {

    private Long id;

    private String name;

    private Integer[] grade;

    private Integer[] course;

    private Integer display;

    private Integer status;

    private Integer sequence;

    private Integer addTime;

    private String startTime;

    private String endTime;

    private Integer type;

    private Long userId;

    private Long admin;

    private Long liveRoomId;

    private String lecturer;

    @ApiModelProperty("视频类型 0：普通用户 1：管理员 Type属性被占用，使用genre")
    private Integer genre;

    private Integer isEnable;
}
