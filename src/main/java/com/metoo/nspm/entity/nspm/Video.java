package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.Accessors;

/**
 * <p>
 *     Title: Video.java
 * </p>
 *
 * <p>
 *     Description: 视频管理类； 包含回放视频，录播视频
 * </p>
 *
 * <author>
 *      HKK
 * </author>
 */
@ApiModel("视频实体类")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class Video extends IdEntity {

    @ApiModelProperty("视频名称")
    private String name;

    @ApiModelProperty("直播视频播放时间")
   // @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private String beginTime;

    @ApiModelProperty("直播视频结束时间")
    // @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private String endTime;

    @ApiModelProperty("视频类型 0：录播 1：回放")
    private Integer type;

    @ApiModelProperty("索引：自定义视频顺序,统一使用DESC从大到小排列")
    private Integer sequence;

    @ApiModelProperty("文件存放地址")
    private String path;

    @ApiModelProperty("回放文件播放地址")
    private String rtmp;

    @ApiModelProperty("文件扩展名")
    private String extend;

    @ApiModelProperty("直播ID")
    private Long roomProgramId;


    @ApiModelProperty("所属直播节目")
    private RoomProgram roomProgram;

    @ApiModelProperty("所属直播间")
    private LiveRoom liveRoom;

    @ApiModelProperty("所属直播间ID")
    private Long liveRoomId;

    @ApiModelProperty("视频创建人 ID")
    private Long userId;

    @ApiModelProperty("上传人名稱名称")
    private String userName;

    @ApiModelProperty("讲师名称")
    private String lecturer;

    @ApiModelProperty("预留字段，视频关联年级")
    private Grade grade;

    @ApiModelProperty("视频关联班级")
    private Course course;

    @ApiModelProperty("描述")
    private String describe;

    @ApiModelProperty("是否显示 默认0：不显示 1：显示")
    private Integer display;

    @ApiModelProperty("审核状态 0：未审核 1：审核通过 -1：拒绝通过")
    private Integer status;

    @ApiModelProperty("审核未通过描述")
    private String message;

    @ApiModelProperty("视频封面")
    private Accessory accessory;

    @ApiModelProperty("视频文件")
    private Accessory video;

    @ApiModelProperty("视频类型 0：普通用户 1：管理员 Type属性被占用，使用genre")
    private Integer genre;
}
