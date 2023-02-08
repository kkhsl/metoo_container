package com.metoo.nspm.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.zabbix.Problem;
import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.Date;


@ApiModel("问题")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class NspmProblemDTO extends PageDto<Problem> {


    // 时间问题 采集时间、zabbix problem生成时间、问题解决时间。需要修改 后面两种记录时间戳。前端需同时修改
    private Integer objectid;
    private String name;
    private String deviceName;
    private String interfaceName;
    private String hostids;
    private Long clock;
    private String uuid;
    private String ip;
    private String severity; //问题当前严重性。 可用值： 0 - 未分类； 1 - 信息； 2 - 警告； 3 - 平均； 4 - 高； 5 - 灾难。
    private String event;
    private Integer suppressed;// 问题是否被抑制 0：问题处于正常状态 1：问题被抑制
    private Integer status;
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss",timezone = "GMT+8")
    private Date restoreTime;

}
