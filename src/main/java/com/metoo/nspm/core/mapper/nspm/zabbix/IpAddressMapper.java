package com.metoo.nspm.core.mapper.nspm.zabbix;

import com.metoo.nspm.entity.nspm.IpAddress;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface IpAddressMapper {

    List<IpAddress> selectObjByMap(Map map);

    IpAddress selectObjByMac(String mac);

    IpAddress selectObjByIp(String ip);

    int save(IpAddress instance);

    int update(IpAddress instance);

    IpAddress querySrcDevice(Map params);

    void truncateTable();

    void copyIpAddressTemp();
}
