package com.metoo.nspm.core.mapper.nspm.zabbix;

import com.metoo.nspm.entity.nspm.RouteTable;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface RouteTableMapper {


    RouteTable selectObjByMac(String mac);

    RouteTable selectObjByIp(String ip);

    List<RouteTable> selectObjByMap(Map params);

    int save(RouteTable instance);

    int update(RouteTable instance);

    void truncateTable();

}
