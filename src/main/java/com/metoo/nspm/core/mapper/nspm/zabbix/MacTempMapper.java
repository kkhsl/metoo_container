package com.metoo.nspm.core.mapper.nspm.zabbix;

import com.metoo.nspm.entity.nspm.MacTemp;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface MacTempMapper {
    List<MacTemp> selectByMap(Map params);

    MacTemp getObjByInterfaceName(String interfaceName);

    List<MacTemp> groupByObjByMap(Map params);

    List<MacTemp> groupByObjByMap2(Map params);

    List<MacTemp> getMacUS(Map params);

    List<MacTemp> macJoinArp(Map params);

    MacTemp selectByMac(String mac);

    int save(MacTemp instance);

    int update(MacTemp instance);

    void truncateTable();
}
