package com.metoo.nspm.core.service.api.zabbix;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.entity.zabbix.History;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;

public interface ZabbixService {

    public Object getUsages(String ip, List itemName);

    /**
     * @param ip
     * @param itemName
     * @param limit
     * @param time_till
     * @param time_from
     * @return
     */
    Map getDevice(String ip, List itemName, Integer limit, Long time_till, Long time_from);

    Map getDeviceInfo(String ip, List itemName, Integer limit, Long time_till, Long time_from, boolean flag);

    Object getDeviceHistory(String ip, List itemName, Integer limit, Long time_till, Long time_from);

    Object refresh(String itemids, Integer limit);

    List getInterfaceInfo(String ip);

    Object flow(String ip, String name);

    Object getInterfaceHistory(String ip, Integer limit, Long time_till, Long time_from);

    // 获取服务器信息
    Object getServer(String ip);

    // ARP
    List getItemArp(String ip,  String deviceName, String uuid, String deviceType);
    // Mac
    Object getItemMac(String ip, String deviceName, String uuid, String deviceType);
    // Route
    List<Map<String, String>> getItemRoutByIp(String ip);

    void createRoutTable(String ip);

    // 采集arp表
    void gatherArp(Date time);

    // 采集Mac表
    void gatherMac(Date time);

    // 采集rout表
    void gatherRout(Date time);

    // 采集ip表
    void gatherIp(Date time);

    // 采集Problem
    void gatherProblem();

    void gatherThreadProblem();

    void updateProblemStatus();

    // 采集arp（多线程）
    void gatherArpThread();

    // 采集Mac（多线程）
    void gatherMacThread();

    // 采集路由表
    Object gatherRoutByIp(String ip, String deviceName, String uuid);

    // 采集路由表
    Object gatherIpaddress(String ip, String deviceName, String uuid);

    String getItemLastvalueByItemId(Integer id);

    List parseHistoryZeroize(JSONObject obj, Long time_till, Long time_from);

    List<History> parseHistoryZeroize(List<History> obj, Long time_till, Long time_from);
}
