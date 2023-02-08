package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class Policy extends IdEntity {

    @ApiModelProperty("策略ID")
    private String policyId;
    @ApiModelProperty("策略名称")
    private String policyName;
    @ApiModelProperty("策略类型")
    private String type;
    @ApiModelProperty("策略类型 ")
    private String policyType;

    @ApiModelProperty("行号")
    private String lineNum;
    @ApiModelProperty("源域")
    private String srcDomain;
    @ApiModelProperty("源Ip")
    private String srcIp;
    @ApiModelProperty("目的域")
    private String dstDomain;
    @ApiModelProperty("目的Ip")
    private String dstIp;
    @ApiModelProperty("服务")
    private String service;
    @ApiModelProperty("时间")
    private String time;
    @ApiModelProperty("动作")
    private String action;
    @ApiModelProperty("描述")
    private String description;
    private String parentId;
    private String parentName;
    @ApiModelProperty("优化类型 策略优化：RuleCheck_1 对象优化：RC_EMPTY_OBJECT")
    private String optimizeType;
    @ApiModelProperty("设备UUID")
    private String deviceUuid;

    @ApiModelProperty("对象名称")
    private String name;
    @ApiModelProperty("对象类型")
    private String typeDesc;
    @ApiModelProperty("所在行号")
    private String lineNumbers;
    @ApiModelProperty("内容")
    private String content;
    @ApiModelProperty("序号")
    private String index;
    @ApiModelProperty("不可见字符")
    private String invisible;
    @ApiModelProperty("工单号")
    private String orderNo;
    private String deviceName;
    private String deviceType;


}
