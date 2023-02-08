package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.Date;

/**
 * Description: 同一签名不能被重复开启关闭；控制客户端每次开启直播重新生成签名
 */
@ApiModel("学校实体类")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class Monitor extends IdEntity {

    @ApiModelProperty("应用唯一标识：暂时只使用AppId")
    private String appId;

    @ApiModelProperty("公钥")
    private String appKey;

    @ApiModelProperty("私钥")
    private String appSecret;

    @ApiModelProperty("数字签名、记录每次直播记录；直播间ID+直播ID+用户ID+学校number+startTime")
    private String sign;

    @ApiModelProperty("学校标题")
    private String title;

    @ApiModelProperty("直播间标题")
    private String liveRoomTitle;

    @ApiModelProperty("直播名称")
    private String roomProgramTitle;

    @ApiModelProperty("直播用户")
    private String username;

    @ApiModelProperty("直播开启时间")
    private Date startTime;

    @ApiModelProperty("直播结束时间")
    private Date endTime;

    @ApiModelProperty("直播状态 0: 关闭 1：开启 ")
    private Integer status;
}
