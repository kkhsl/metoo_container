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
public class HostCreateDTO extends ParamsDTO {

    private String deviceName;
    private String deviceIp;
    private String host;
    private String name;
    private String hostid;
    private List<Integer> groupids;
    private List<Integer> applicationids;
    private List<Integer> dserviceids;
    private List<Integer> graphids;
    private List<Integer> hostids;
    private List<Integer> httptestids;
    private List<Integer> interfaceids;
    private List<Object> templates;
    private List<Object> groups;
    private List<Integer> itemids;
    private List<Integer> maintenanceids;
    private List<String> selectParentTemplates;
    private List<Object> interfaces;
    private boolean monitored_hosts;
    private boolean proxy_hosts;
    private List<Integer> proxyids;
    private boolean templated_hosts;
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

    private String type;
    private String main;
    private String useip;
    private String ip;
    private String dns;
    private String port;
    private String version;
    private String bulk;
    private String community;
    private String securityname;
    private String contextname;
    private String securitylevel;


}
