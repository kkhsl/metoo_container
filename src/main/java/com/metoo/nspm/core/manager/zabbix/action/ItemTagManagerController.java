package com.metoo.nspm.core.manager.zabbix.action;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.pagehelper.util.StringUtil;
import com.metoo.nspm.core.manager.admin.tools.DateTools;
import com.metoo.nspm.core.mapper.zabbix.HistoryMapper;
import com.metoo.nspm.core.mapper.zabbix.ItemMapper;
import com.metoo.nspm.core.service.api.zabbix.ZabbixItemService;
import com.metoo.nspm.core.service.api.zabbix.ZabbixService;
import com.metoo.nspm.core.service.topo.ITopoNodeService;
import com.metoo.nspm.core.service.zabbix.IGatherService;
import com.metoo.nspm.core.service.zabbix.IItemTagService;
import com.metoo.nspm.core.service.zabbix.ItemService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.entity.zabbix.History;
import com.metoo.nspm.entity.zabbix.Item;
import com.metoo.nspm.entity.zabbix.ItemTag;
import com.metoo.nspm.vo.ItemTagBoardVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@RequestMapping("/zabbix/itemtag")
@RestController
public class ItemTagManagerController {

    @Autowired
    private ItemMapper itemMapper;
    @Autowired
    private IItemTagService itemTagService;
    @Autowired
    private ItemService itemService;
    @Autowired
    private IGatherService gatherService;
    @Autowired
    private ZabbixService zabbixService;
    @Autowired
    private HistoryMapper historyMapper;
    @Autowired
    private DateTools dateTools;
    @Autowired
    private ZabbixItemService zabbixItemService;

    @GetMapping("/arpTable")
    public Object arpTable(@RequestParam(required = false) String ip){
        List<Item> itemTagList = this.itemMapper.arpTable(ip);
        return itemTagList;
    }

    /**
     * 获取端口信息
     * @param ip
     * @return
     */
    @GetMapping("/interfaceTable")
    public Object interfaceTable(@RequestParam(required = false) String ip){
        Map params = new HashMap();
        params.put("ip", ip);
        params.put("index", "ifindex");
        List<Item> itemTagList = this.itemMapper.interfaceTable(params);
        List list = new ArrayList();
        if(itemTagList != null && itemTagList.size() > 0){
            for (Item item : itemTagList){
                List<ItemTag> tags = item.getItemTags();
                Map map = new HashMap();
                map.put("description", "");
                map.put("name", "");
                map.put("ip", "");
                map.put("mask", "");
                map.put("status", "");
                if(tags != null && tags.size() > 0){
                    for(ItemTag tag : tags){
                        if(tag.getTag().equals("description")){
                            map.put("description", StringUtil.isEmpty(tag.getValue()) ? "" : tag.getValue());
                        }
                        if(tag.getTag().equals("ifname")){
                            map.put("name", StringUtil.isEmpty(tag.getValue()) ? "" : tag.getValue());
                        }
                        if(tag.getTag().equals("ifup")){
                            String status = "unknown";
                            if(tag.getValue() !=  null){
                                switch (tag.getValue()){
                                    case "1":
                                        status = "up";
                                        break;
                                    case "2":
                                        status = "down";
                                        break;
                                    default:
                                        status = "unknown";
                                }
                            }
                            map.put("status", status);
                        }
                        if (tag.getTag().equals("ifindex")) {
                            map.put("ip", StringUtil.isEmpty(tag.getIp()) ? "" : tag.getIp());
                            map.put("mask", StringUtil.isEmpty(tag.getMask()) ? "" : tag.getMask());
                        }
                    }
                }
                list.add(map);
            }
        }
        return ResponseUtil.ok(list);
    }

    /**
     * 查询设备流量
     * @param ip ip地址
     * @param name 端口名
     * @return
     */
    @GetMapping("/traffic")
    public Object getHistory(String ip, String name, Long time_from, Long time_till){
        List list = new ArrayList();
        Map params = new HashMap();
        params.put("ip", ip);
        // 采集ifbasic,然后查询端口对应的历史流量
        params.put("tag", "ifbasic");
        params.put("available", 1);
        params.put("filterValue", name);
        List<Item> items = this.itemService.selectTagByMap(params);
        for (Item item : items) {
            Map map = new HashMap();
            List<ItemTag> tags = item.getItemTags();
            if (tags != null && tags.size() > 0) {
                for (ItemTag tag : tags) {
                    String value = tag.getValue();
                    if (tag.getTag().equals("ifname")) {
                        map.put("name", value);
                        // 根据端口获取流量
                        params.clear();
                        params.put("ip", ip);
                        params.put("tag", "ifsent");
                        params.put("available", 1);
                        params.put("filterValue", value);
                        params.put("filterTag", "ifname");
                        List<Item> sentItem = this.itemService.selectTagByMap(params);
                        // sent
                        if(sentItem.size() > 0){
                            //
                            Long itemid = null;
                            for(Item sent : sentItem){
                                // 获取历史信息
                                itemid = sent.getItemid();
                                break;
                            }
                            // 获取历史信息
                            params.clear();
                            Integer from = time_from.intValue();
                            Integer till = time_till.intValue();
                            params.put("time_from", from);
                            params.put("time_till", till);
                            params.put("itemid", itemid);
                            List<History> sentHistory = this.historyMapper.selectObjByMap(params);
                            List<History>  newSentHistory = this.zabbixService.parseHistoryZeroize(sentHistory, time_from, time_till);
                            map.put("sentHistory", newSentHistory);
                        }else{
                            map.put("sentHistory", new ArrayList<>());
                        }
                        // ifreceived
                        params.clear();
                        params.put("ip", ip);
                        params.put("tag", "ifreceived");
                        params.put("available", 1);
                        params.put("filterValue", value);
                        params.put("filterTag", "ifindex");
                        List<Item> receivedItem = this.itemService.selectTagByMap(params);
                        // speed
                        if(receivedItem.size() > 0){
                            Long itemid = null;
                            for(Item received : receivedItem){
                                // 获取历史信息
                                itemid = received.getItemid();
                                break;
                            }
                            // 获取历史信息
                            params.clear();
                            params.put("time_from", time_from.intValue());
                            params.put("time_till", time_till.intValue());
                            params.put("itemid", itemid);
                            List<History> receivedHistory = this.historyMapper.selectObjByMap(params);
                            List<History>  newReceivedHistory = this.zabbixService.parseHistoryZeroize(receivedHistory, time_from, time_till);
                            map.put("receivedHistory", newReceivedHistory);
                        }else{
                            map.put("receivedHistory", new ArrayList<>());
                        }

                    }
                    if(tag.getTag().equals("ifindex")){
                        // speed
                        JSONArray speedItems = this.zabbixItemService.getItemSpeedTag(ip, Integer.parseInt(value));
                        if(speedItems.size() > 0){
                            JSONObject jsonObject = JSONObject.parseObject(speedItems.get(0).toString());
                            map.put("speed", jsonObject.getString("lastvalue"));
                        }
                    }
                }
                list.add(map);
            }
        }
        return list;
    }
//
//    /**
//     * item历史记录，图形，数据补零，便于前端画图
//     *
//     * @param histories
//     * @param time_till
//     * @param time_from
//     * @return
//     */
//    public List<History> parseHistoryZeroize(List<History> histories, Long time_till, Long time_from){
//        Long start = time_from;
//        Long end = null;
//        List list = new ArrayList();
//        for (int j = 0; j < histories.size(); j++){
//            History history = histories.get(j);
//            if(start != null){
//                end = history.getClock();
//                // 比较两个记录时间间隔，间隔为/分钟
//                long b = end / 60;
//                long d = start / 60;
//                double diff = (b - d);
//                if(diff > 1){
//                    long n = 1;// 中补（中间空缺 从1开：起始位置不用补，使用< 终点位置不用补）
//                    if(j == 0){
//                        n = 0;// 前补（最前面空缺，从0开始，起始位置需要补充）
//                    }
//                    for(long i = n; i < diff; i++){
//                        String startTime = this.dateTools.longToStr((start * 1000) + i * 60000 , "yyyy-MM-dd HH:mm");
//                        History newHistory = new History();
//                        newHistory.setTime(startTime);
//                        newHistory.setItemid(history.getItemid());
//                        newHistory.setValue(0);
//                        list.add(newHistory);
//                        n++;
//                    }
//                }
//                start = end;
//                String time = this.dateTools.longToStr(history.getClock() * 1000, "yyyy-MM-dd HH:mm");
//                history.setTime(time);
//                list.add(history);
//                // 后补（最后面空缺 使用<=：最后一个位置需要补）
//                if(j + 1 == histories.size()){
//                    long n = time_till / 60;
//                    long m = end / 60;
//                    long till_diff = (n - m);
//                    if(till_diff > 1){
//                        for(long i = 1; i <= till_diff; i++){
//                            String startTime = this.dateTools.longToStr((start * 1000) + i * 60000 , "yyyy-MM-dd HH:mm");
//                            History newHistory = new History();
//                            newHistory.setTime(startTime);
//                            newHistory.setItemid(history.getItemid());
//                            newHistory.setValue(0);
//                            list.add(newHistory);
//                        }
//                    }
//                }
//            }
//        }
//        return list;
//    }

//    @GetMapping("/board")
//    public Object getBoard(Long time_from, Long time_till){
//        List<ItemTagBoardVO> boards = this.itemTagService.selectBoardByTag(null);
//        if(boards.size() > 0){
//            for (ItemTagBoardVO board : boards) {
//                if(board.getItems().size() > 0){
//                    for (Item item : board.getItems()) {
//                        Long itemid = item.getItemid();
//                        // 获取历史信息
//                        Map params = new HashMap();
//                        params.clear();
//                        Integer from = time_from.intValue();
//                        Integer till = time_till.intValue();
//                        params.put("time_from", from);
//                        params.put("time_till", till);
//                        params.put("itemid", itemid);
//                        List<History> sentHistory = this.historyMapper.selectObjByMap(params);
//                        List<History>  replenishSentHistory = this.parseHistoryZeroize(sentHistory, time_from, time_till);
//                        if(item.getBoardType().equals("BOARDCPU")){
//                            board.setCpu(replenishSentHistory);
//                        }else if(item.getBoardType().equals("BOARDMEM")){
//                            board.setMem(replenishSentHistory);
//                        }else if(item.getBoardType().equals("BOARDTEMP")){
//                            board.setTemp(replenishSentHistory);
//                        }
//                    }
//                }
//            }
//        }
//        return ResponseUtil.ok(boards);
//    }

    @GetMapping
    public void testTransactional(){
//        this.itemService.testTransactional();
        this.gatherService.testTransactional();
    }
}
