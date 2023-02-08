package com.metoo.nspm.core.service.zabbix.impl;

import com.metoo.nspm.core.service.api.zabbix.ZabbixItemService;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.service.zabbix.IGatherService;
import com.metoo.nspm.core.service.zabbix.ItemService;
import com.metoo.nspm.entity.nspm.ArpTemp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

@Service
//@Transactional
public class GatherServiceImpl implements IGatherService {

    @Autowired
    private ItemService itemService;
    @Autowired
    private ZabbixItemService zabbixItemService;
    @Autowired
    private IArpService arpService;
    @Autowired
    private IArpHistoryService arpHistoryService;
    @Autowired
    private IMacService macService;
    @Autowired
    private IMacHistoryService macHistoryService;
    @Autowired
    private IRoutService routService;
    @Autowired
    private IRoutHistoryService routHistoryService;
    @Autowired
    private IArpTempService arpTempService;
    @Autowired
    private IIPAddressService ipAddressService;
    @Autowired
    private IIPAddressHistoryService ipAddressHistoryService;

    @Override
    public void gatherArpItem(Date time) {
        this.itemService.gatherArpItem(time);
        // 打标签
        this.zabbixItemService.arpTag();
        // 同步到arp
        this.arpService.truncateTable();
        this.arpService.copyArpTemp();
        // 记录历史Arp
        this.arpHistoryService.copyArpTemp();

    }

    @Override
    public void gatherMacItem(Date time) {
        this.itemService.gatherMacItem(time);
        // 同步到系统其他表
        this.zabbixItemService.macTag();
        this.macService.truncateTable();
        this.macService.copyMacTemp();
        // 记录历史
        this.macHistoryService.copyMacTemp();
    }

    @Override
    public void gatherRouteItem(Date time) {
        this.itemService.gatherRouteItem(time);
        this.routService.truncateTable();
        this.routService.copyRoutTemp();
        this.routHistoryService.copyRoutTemp();

    }

    @Override
    public void gatherIpaddressItem(Date time) {
        this.itemService.gatherIpaddressItem(time);
        this.ipAddressService.truncateTable();
        this.ipAddressService.copyIpAddressTemp();
        // 记录历史Ipaddress
        this.ipAddressHistoryService.copyIpAddressTemp();
    }

    @Override
    public void gatherProblemItem(Date time) {
        this.itemService.gatherProblemItem(time);
//        this.ipAddressService.truncateTable();
//        this.ipAddressService.copyIpAddressTemp();
//        // 记录历史Ipaddress
//        this.ipAddressHistoryService.copyIpAddressTemp();
    }

    @Override
    public void testTransactional() {
        ArpTemp arpTemp = new ArpTemp();
        arpTemp.setDeviceName("a");
        this.arpTempService.save(arpTemp);
        this.itemService.testTransactional();
    }
}
