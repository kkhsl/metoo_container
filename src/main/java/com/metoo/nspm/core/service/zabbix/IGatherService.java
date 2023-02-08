package com.metoo.nspm.core.service.zabbix;

import java.util.Date;

public interface IGatherService {

    /**
     * 采集Arp
     * @param time
     */
    void gatherArpItem(Date time);

    /**
     * 采集Mac
     * @param time
     */
    void gatherMacItem(Date time);

    /**
     * 采集路由
     * @param time
     */
    void gatherRouteItem(Date time);

    /**
     * 采集Ip地址
     * @param time
     */
    void gatherIpaddressItem(Date time);

    /**
     * 采集告警信息
     * @param time
     */
    void gatherProblemItem(Date time);

    /**
     * 采集主机接口（主机状态）
     */
//    void gatherInterfaceitem(Date time);

    void testTransactional();

    /**
     * 采集主机状态
     */
//    void gatherSnmpAvailable();
}
