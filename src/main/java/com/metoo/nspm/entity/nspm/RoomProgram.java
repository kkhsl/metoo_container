package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;
import org.springframework.format.annotation.DateTimeFormat;

import java.util.Date;

/**
 * <p>
 *     Title: RoomProgram.java
 * </p>
 *
 * <p>
 *     Description: 直播管理类；两种模式：一个直播对应一个直播间、多个直播对应一个直播间；
 *     @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8) 时间戳 : 后台到前台时间格式保持一致的问题
 *     @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
 * </p>
 *
 *  <author>
 *      HKK
 *  </author>
 */
@ApiModel("直播管理实体类")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class RoomProgram extends IdEntity {

    @ApiModelProperty("直播节目名称")
    private String title;

    @JsonIgnore
    private User user;

    @ApiModelProperty("直播节目创建人ID")
    private Long userId;

    @ApiModelProperty("直播节目创建人名称")
    private String userName;

    @ApiModelProperty("直播节目开始时间")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private Date beginTime;//

    @ApiModelProperty("直播节目结束时间")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private Date endTime;

    @ApiModelProperty("直播状态 0: 关闭 1：开启")
    private Integer status;

    @ApiModelProperty("是否显示  0:不显示 1：显示")
    private Integer display;

    @JsonIgnore
    @ApiModelProperty("视频流默认0：停止 1：开启 deprecated")
    private Integer live;

    @ApiModelProperty("直播类型 默认为0：普通用户 1：管理员")
    private Integer type;

    @ApiModelProperty("直播简介")
    private String info;

    @JsonIgnore
    @ApiModelProperty("直播海报/封面")
    private String poster;

    @JsonIgnore
    @ApiModelProperty("")
    private Integer remark;

    @ApiModelProperty("评论数")
    private Integer commmentNumber;

    @ApiModelProperty("观看人数")
    private Integer seeNumber;

    @ApiModelProperty("点赞人数")
    private Integer goodsNumber;

    @ApiModelProperty("所属直播间ID")
    private Long roomId;

    @ApiModelProperty("所属直播间名称")
    private String roomName;

    @ApiModelProperty("讲师")
    private String lecturer;

    @ApiModelProperty("签到人数")
    private Integer loginNumber;

    @ApiModelProperty("直播封面ID")
    private Long cover;

 /*   private String pushAddress;// 推流地址

    private String bindCode;// 推流码

    private String rtmp;//*/

    @ApiModelProperty("最近一次节目是否存在回放")
    private Integer playback;

    @ApiModelProperty("是否需要生成回放视频0：不生成 1：生成")
    private Integer isPlayback;

    @JsonIgnore
    @ApiModelProperty("所属年级")
    private Grade grade;

    @JsonIgnore
    @ApiModelProperty("所属科目")
    private Course course;

    /**
     * 偷个懒，这里不做联表查询
     */
    @ApiModelProperty("年级ID")
    private Long grade_id;

    @ApiModelProperty("年级名称")
    private String gradeName;

    @ApiModelProperty("科目ID")
    private Long course_id;

    @ApiModelProperty("科目名称")
    private String courseName;

    @ApiModelProperty("时间戳")
    private String timestamp;

//    @ApiModelProperty("数字签名、记录每次直播记录；直播间ID+直播ID+用户ID+学校number")
//    private String sign;
}
