package com.metoo.nspm.dto;


import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.LiveRoom;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("直播间DTO")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class LiveRoomDto extends PageDto<LiveRoom> {

    @ApiModelProperty("直播间ID")
    private Long id;

    @ApiModelProperty("软删除")
    private int deleteStatus = 0;

    @ApiModelProperty
    private String title;

    @ApiModelProperty("直播间管理人")
    private String manager;

    @ApiModelProperty("直播间密码：后期添加直播间密码重试次数，超过指定次数锁定直播间")
    private String password;

    @ApiModelProperty("直播间简介")
    private String info;

    @ApiModelProperty("直播间联系电话")
    private String telephone;

    @ApiModelProperty("是否禁用直播间 默认0：关闭 1：开启")
    private Integer isEnable;

    @ApiModelProperty("视频流默认0：停止 1：开启")
    private int live;

    @ApiModelProperty("直播间封面图片")
    private Long cover;

    @ApiModelProperty("是否开启回放")
    private Integer isPlayback;

    @ApiModelProperty("直播间创建人")
    private Long userId;

    @ApiModelProperty("直播间类型 0：默认查询个人直播间 1：查询普通用户直播间")
    private Integer type;

    @ApiModelProperty("直播间封面")
    private Long logoImg;

    @ApiModelProperty("年级IDS")
    private Integer[] grade;

    @ApiModelProperty("科目IDS")
    private Integer[] course;

    private Integer roomProgramStatus;
}
