package com.metoo.nspm.dto.zabbix;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class HostDTO extends ParamsDTO{

    private String ip;
    private String hostid;
    private List<Integer> groupids;
    private List<Integer> applicationids;
    private List<Integer> dserviceids;
    private List<Integer> graphids;
    private List<Integer> hostids;
    private List<Integer> httptestids;
    private List<Integer> interfaceids;
    private List<Integer> itemids;
    private List<Integer> maintenanceids;
    private Boolean maintenance_status;
    private List<String> selectParentTemplates;
    private List<Object> interfaces;
    private List<Object> groups;
    private Integer params;
    private Boolean monitored_hosts;
    private Boolean proxy_hosts;
    private List<Integer> proxyids;
    private Boolean templated_hosts;
    private List<Integer> templateids;
    private List<Integer> triggerids;
    private String selectGroups;
    private String selectApplications;
    private String selectDiscoveries;
    private String selectDiscoveryRule;
    private String selectGraphs;
    private String selectHostDiscovery;
    private String selectHttpTests;
    private String selectInterfaces;
    private String selectInventory;
    private String selectItems;
    private String selectMacros;
    private String selectScreens;
    private String selectTriggers;
    private Object filter;
    private String templates;
    private Boolean monitored;
    private List tags;
    private List output;
}
