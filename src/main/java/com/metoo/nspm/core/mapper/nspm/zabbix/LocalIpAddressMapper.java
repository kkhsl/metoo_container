package com.metoo.nspm.core.mapper.nspm.zabbix;

import com.metoo.nspm.entity.nspm.LocalIpAddress;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface LocalIpAddressMapper {


    List<LocalIpAddress> selectObjByMap(Map map);

    int save(LocalIpAddress instance);

    void truncateTable();
}
