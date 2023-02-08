package com.metoo.nspm.core.mapper.nspm.zabbix;

import com.metoo.nspm.entity.nspm.IpAddress;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface IpAddressHistoryMapper {

    List<IpAddress> selectObjByMap(Map map);

    IpAddress selectObjByMac(String mac);

    IpAddress selectObjByIp(String ip);

    IpAddress querySrcDevice(Map params);

    int batchDelete(List<IpAddress> ipAddresses);

    void copyIpAddressTemp();
}
