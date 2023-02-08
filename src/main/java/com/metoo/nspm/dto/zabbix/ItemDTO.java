package com.metoo.nspm.dto.zabbix;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@ApiModel("监控项")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class ItemDTO extends ParamsDTO {

    private List<Integer> itemids;
    private List<Integer> groupids;
    private List<Integer> templateids;
    private List<String> hostids;
    private List<Integer> proxyids;
    private List<Integer> interfaceids;
    private List<Integer> graphids;
    private List<Integer> triggerids;
    private List<Integer> applicationids;
    private Boolean webitems;
    private Boolean inherited;
    private Boolean templated;
    private Boolean monitored;
    private String group;
    private String host;
    private String application;
    private Boolean with_triggers;
    private Object filter;
    private List tags;
    private List output;
    private String selectTags;
}
