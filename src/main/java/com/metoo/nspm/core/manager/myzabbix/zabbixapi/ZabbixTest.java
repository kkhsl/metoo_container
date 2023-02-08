package com.metoo.nspm.core.manager.myzabbix.zabbixapi;

import com.alibaba.fastjson.JSON;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class ZabbixTest {

    public static void main(String[] args) {

    }

    @Test
    public void test(){
        String cidr = "192.168.1.64/26";
        String ip = "192.168.1.127";
        String[] ips = ip.split("\\.");
        int ipAddr = (Integer.parseInt(ips[0]) << 24)
                | (Integer.parseInt(ips[1]) << 16)
                | (Integer.parseInt(ips[2]) << 8)
                | Integer.parseInt(ips[3]);
        int type = Integer.parseInt(cidr.replaceAll(".*/", ""));
        int mask = 0xFFFFFFFF << (32 - type);
        System.out.println(type);
        System.out.println(mask);
    }

    @Test
    public void test1(){
        Map map = new HashMap();
        map.put("test",1 );
        System.out.println(JSON.toJSON(map));
    }
}
