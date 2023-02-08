package com.metoo.nspm.dto.zabbix;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@ApiModel("模板")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class TemplateDTO extends ParamsDTO {


    private Object filter;
    private List<Integer> templateids;
    private List<Integer> groupids;
    private List<Integer> parentTemplateids;
    private List<Integer> hostids;
    private List<Integer> graphids;
    private List<Integer> itemids;
    private List<Integer> triggerids;
    private List<Object> tags;
    private Boolean with_items;
    private Boolean with_triggers;
    private Boolean with_graphs;
    private Boolean with_httptests;
    private String vendor;

}
