package com.metoo.nspm.vo;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.Date;

@ApiModel("学校实体VO类")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class MonitorVo extends IdEntity {

    @ApiModelProperty("学校编号：唯一标识、由学校第一次调用接口生成，之后不在改变")
    private Integer number;

    @ApiModelProperty("学校标题")
    private String title;

    @ApiModelProperty("直播开启时间")
    private Date startTime;

    @ApiModelProperty("直播结束时间")
    private Date endTime;

    private Long userId;

    private Long liveRoomId;

    private String username;

    private String liveRoomTitle;

}
