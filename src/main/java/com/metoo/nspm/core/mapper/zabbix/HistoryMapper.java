package com.metoo.nspm.core.mapper.zabbix;

import com.metoo.nspm.entity.zabbix.History;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface HistoryMapper {

    List<History> selectObjByMap(Map params);
}
