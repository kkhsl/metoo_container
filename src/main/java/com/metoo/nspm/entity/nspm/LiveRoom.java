package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;


/**
 * <p>
 *     Title: LiveRoom.java
 * </p>
 *
 * <p>
 *     Description: 直播间管理类；
 * </p>
 */
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
@ApiModel("直播间实体类")
public class LiveRoom extends IdEntity {

    @ApiModelProperty("最后一次直播的时间：可根据此时间在前端排序")
    private Date lastTime;

    @ApiModelProperty("直播间名称")
    private String title;

    @ApiModelProperty("直播间管理人")
    private String manager;

    @ApiModelProperty("直播间密码：后期添加直播间密码重试次数，超过指定次数锁定直播间")
    private String password;

    @ApiModelProperty("直播间简介")
    private String info;

    @ApiModelProperty("直播间联系电话")
    private String telephone;

    @ApiModelProperty("是否禁用直播间 默认 -1：禁用  0：关闭 1：开启")
    private Integer isEnable;

    @ApiModelProperty("直播间是否有推流 0：停止 1：开启")
    private Integer live;

    @ApiModelProperty("OBS是否开启推流")
    private Integer obs;

    @ApiModelProperty("直播间封面图片")
    private Long cover;

    @ApiModelProperty("直播间封面图片")
    private String photo;

    private Accessory accessory;

    @ApiModelProperty("在线人数")
    private Integer onLine;

    @ApiModelProperty("直播间最大在线人数")
    private Integer maxOnline;

    @ApiModelProperty("直播间是否禁言  默认0：否 1：是")
    private Integer istalk;

    @ApiModelProperty("是否游客观看 默认0：否 1：是")
    private Integer isVip;

    @ApiModelProperty("推流地址")
    private String pushAddress;

    @ApiModelProperty("推流码")
    private String bindCode;

    @ApiModelProperty("推流码")
    private String rtmp;

    @ApiModelProperty("推流地址")
    private String obsRtmp;

    @ApiModelProperty("flv 地址")
    private String flv;

    @ApiModelProperty("websocket 地址")
    private String websocketFlv;

    @ApiModelProperty("栏目管理：java、php、python、语文、数学")
    private Long ItemId;

    @ApiModelProperty("部门ID 直播间所属部门")
    private Long deptId;

    @ApiModelProperty("是否开启回放")
    private Integer isPlayback;

    @ApiModelProperty("直播节目ID")
    private Long roomProgramId;

    @ApiModelProperty("直播节目")
    private RoomProgram roomProgram;

    @ApiModelProperty("所属直播节目")
    private List<RoomProgram> RoomProgramList = new ArrayList<>();

    @ApiModelProperty("直播间创建人")
    private User user;

    @ApiModelProperty("直播间所属用户id")
    private Long userId;

    @ApiModelProperty("直播间所属用户名")
    private String username;

    @ApiModelProperty("直播间类型0：普通用户 1：管理员")
    private Integer type;

    @ApiModelProperty("直播间索引：可根据该值默认排序，权重越大越在前")
    private Integer sequence;



}
