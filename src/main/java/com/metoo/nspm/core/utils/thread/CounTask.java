//package com.metoo.nspm.core.utils.thread;
//
//import com.alibaba.fastjson.JSONArray;
//import com.alibaba.fastjson.JSONObject;
//import com.metoo.nspm.core.manager.admin.tools.DateTools;
//import com.metoo.nspm.core.manager.zabbix.utils.ItemUtil;
//import com.metoo.nspm.core.service.zabbix.IArpService;
//import com.metoo.nspm.core.service.zabbix.IArpTempService;
//import com.metoo.nspm.core.service.zabbix.IpDetailService;
//import com.metoo.nspm.core.utils.network.IpUtil;
//import com.metoo.nspm.entity.nspm.Arp;
//import com.metoo.nspm.entity.nspm.ArpTemp;
//import com.metoo.nspm.entity.nspm.IpDetail;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Component;
//
//import java.util.*;
//import java.util.concurrent.Executors;
//import java.util.concurrent.RecursiveTask;
//
//@Component
//public class CounTask extends RecursiveTask<List> {
//
//    @Autowired
//    private ItemUtil itemUtil;
//    @Autowired
//    private IpDetailService ipDetailService;
//    @Autowired
//    private IArpService arpService;
//    @Autowired
//    private IArpTempService arpTempService;
//
//    private JSONArray items;// item解析
//
//    private Integer taskNum;// 指定子任务拆分数量
//
//    private String ip;
//
//    private String deviceName;
//
//    private String deviceType;
//
//    private String uuid;
//
//    private Date time;
//
//    private static final int TASKNUM = 100;// 定义每次把大任务分解为100个小任务
//
//    public CounTask(JSONArray items, Integer taskNum, String ip, String deviceName,
//                    String deviceType, String uuid, Date time){
//        this.items = items;
//        this.taskNum = taskNum;
//        this.deviceName = deviceName;
//        this.deviceType = deviceType;
//        this.uuid = uuid;
//        this.time = time;
//    }
//
//    @Override
//    protected List compute() {
//        List ips = new ArrayList();// 记录采集信息
//        if(items != null && items.size() > 0){
//            for(Object obj : items){
//                JSONObject item = JSONObject.parseObject(obj.toString());
//                String lastClock = item.getString("lastclock");
//                if(lastClock != null && !lastClock.equals("")){
//                    Long currentSecond = DateTools.currentTimeSecond();
//                    Long interval = DateTools.secondInterval(currentSecond, Long.parseLong(lastClock));
//                    if(interval >= 300){
////                        continue;
//                    }
//                }
//                if(!item.get("error").equals("")){
//                    continue;
//                }
//
//                JSONArray tags = JSONArray.parseArray(item.getString("tags"));
//                if (tags != null && tags.size() > 0) {
//                    // 记录全网ip信息
//                    IpDetail ipDetail = new IpDetail();
//                    ArpTemp arp = new ArpTemp();
//                    arp.setDeviceName(deviceName);
//                    arp.setDeviceType(deviceType);
//                    arp.setDeviceIp(ip);
//                    arp.setUuid(uuid);
//                    for (Object t : tags) {
//                        JSONObject tag = JSONObject.parseObject(t.toString());
//                        if (tag.getString("tag").equals("ip")) {
//                            arp.setIp(IpUtil.ipConvertDec(tag.getString("value")));
//                            arp.setIpAddress(tag.getString("value"));
//                            ipDetail.setIp(IpUtil.ipConvertDec(tag.getString("value")));
//                            ips.add(IpUtil.ipConvertDec(tag.getString("value")));
//                        }
//                        if (tag.getString("tag").equals("mac")) {
//                            arp.setMac(tag.getString("value"));
//                            ipDetail.setMac(tag.getString("value"));
//                        }
//                        if (tag.getString("tag").equals("mask")) {
//                            arp.setMask(tag.getString("value"));
//                        }
//                        if (tag.getString("tag").equals("ifindex")) {
//                            if(com.metoo.nspm.core.utils.StringUtils.isInteger(tag.getString("value"))){
//                                arp.setIndex(Integer.parseInt(tag.getString("value")));
//                                String interfaceName = itemUtil.getInterfaceName(ip,
//                                        arp.getInterfaceName());
//                                arp.setInterfaceName(interfaceName);
//                            }
//                        }
//                    }
//                    arp.setTag("S");
////                          IP表：记录Ip使用率 (优化到IP表)
//                    ipDetail.setDeviceName(deviceName);
//                    IpDetail existingIp = ipDetailService.selectObjByIp(ipDetail.getIp());
//                    if(existingIp == null && ipDetail != null){
//                        ipDetailService.save(ipDetail);
//                    }
//                    // 查询arp
//                    Map<String, Object> params = new HashMap();
//                    params.clear();
//                    params.put("ip", arp.getIp());
//                    params.put("deviceName", arp.getDeviceName());
//                    params.put("interfaceName", arp.getInterfaceName());
//                    List<Arp> localArps = arpService.selectObjByMap(params);
//                    if(localArps.size() == 0){
//                        arp.setAddTime(time);
//                        arpTempService.save(arp);
//                    }
//                }
//            }
//        }
//        return null;
//    }
//}
