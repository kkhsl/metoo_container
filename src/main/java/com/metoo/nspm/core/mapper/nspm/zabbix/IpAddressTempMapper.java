package com.metoo.nspm.core.mapper.nspm.zabbix;

import com.metoo.nspm.entity.nspm.IpAddressTemp;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface IpAddressTempMapper {

    List<IpAddressTemp> selectObjByMap(Map map);

    IpAddressTemp selectObjByMac(String mac);

    IpAddressTemp selectObjByIp(String ip);

    int save(IpAddressTemp instance);

    int update(IpAddressTemp instance);

    void truncateTable();

    IpAddressTemp querySrcDevice(Map params);
}
