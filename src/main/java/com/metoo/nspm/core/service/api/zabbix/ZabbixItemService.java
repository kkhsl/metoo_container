package com.metoo.nspm.core.service.api.zabbix;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.dto.zabbix.ItemDTO;
import com.metoo.nspm.entity.nspm.IpAddress;

import java.util.List;
import java.util.Map;

public interface ZabbixItemService {

    JSONObject getItem(ItemDTO dto);// 这里优化

    JSONArray getItemById(Integer id);

    // 获取items
    public JSONArray getItemByIpAndTag(String ip, List tags, List output);

    JSONArray getItemRout(String ip);

    // 梳理网段
    JSONArray getItemIpAddress(String ip);

    JSONArray getItemIpAddressTag(String ip);

    JSONArray getItemIpAddressTagByIndex(String ip, Integer index);

    JSONArray getItemsByIpAndTags(String ip, List<String> list);

    JSONArray getItemTags(String ip);

    JSONArray getItemSpeedTag(String ip, Integer index);

    JSONArray getItemMac(String ip);

    JSONArray getItemArpTag(String ip);

    JSONArray getItemInterfacesByIndex(String ip, Integer index);

    JSONArray getItemInterfacesTagByIndex(String ip, String index);

    JSONArray getItemIfIndexByIndexTag(String ip);

    JSONArray getItemInterfaces(String ip);

    Map<String, List<Object>> ipAddressCombing(JSONArray items);

    Map<String, List<Object>> ipAddressCombingByDB(List<IpAddress> ipList);

    JSONArray getItemOperationalTagByIndex(String ip, Integer index);

    JSONArray getItemMacTag(String ip);

    JSONArray getItemInterfacesTag(String ip);

    JSONArray getItemRoutTag(String ip);

    void arpTag();

    void macTag();
}
