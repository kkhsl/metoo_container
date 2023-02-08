package com.metoo.nspm.dto.zabbix;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@ApiModel("检索触发器")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class TriggerDTO extends ParamsDTO {

    private Integer triggerid;
    private List<Integer> triggerids;
    private List<Integer> groupids;
    private List<Integer> templateids;
    private List<Integer> hostids;
    private List<Integer> itemids;
    private List<Integer> applicationids;
    private List<String> functions;
    private String group;
    private String host;
    private String expandData;
    private Boolean expandDescription;
    private Boolean expandExpression;
    private String selectGroups;
    private String selectItems;
    private String selectHosts;
    private String selectFunctions;
    private String selectDependencies;
    private String selectDiscoveryRule;
    private String selectLastEvent;
    private String filter;
    private Integer limitSelects;

    private String params;
    private String interfaceName;

    private List<String> interfaceNames;
    private String ip;
    private Integer index;

    private Integer recovery_mode;// 事件恢复生成模式.
    private String recovery_expression;// 生成的触发恢复表达式.
    private String description;// 触发器的名称
    private String expression;// 简化的触发器表达式
    private Integer priority;// 触发器的严重性级别 0 - (默认) 未分类; 1 - 信息; 2 - 警告; 3 - 一般严重; 4 - 严重; 5 - 灾难.
    private String correlation_tag;
    private List tags;
    private Integer value;
}
