package com.metoo.nspm.core.mapper.nspm.zabbix;

import com.metoo.nspm.entity.nspm.Mac;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface MacHistoryMapper {

    List<Mac> selectObjByMap(Map params);

    int batchDelete(List<Mac> macs);

    void copyMacTemp();
}
