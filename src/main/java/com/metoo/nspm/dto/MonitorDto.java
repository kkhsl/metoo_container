package com.metoo.nspm.dto;


import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.Monitor;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class MonitorDto extends PageDto<Monitor> {

    @ApiModelProperty("学校标题")
    private String title;

    @ApiModelProperty("直播间标题")
    private String liveRoomTitle;

    @ApiModelProperty("直播名称")
    private String roomProgramTitle;

    @ApiModelProperty("直播用户名称")
    private String username;

    @ApiModelProperty("数字签名、记录每次直播记录；直播间ID+直播ID+用户ID+学校number")
    private String sign;

    @ApiModelProperty("应用唯一标识")
    private String appId;

    @ApiModelProperty("直播开启时间戳")
    private String startTime;

}
