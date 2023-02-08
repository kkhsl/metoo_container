package com.metoo.nspm.core.mapper.nspm.zabbix;

import com.metoo.nspm.entity.nspm.ProblemTemp;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface ProblemTempMapper {

    void truncateTable();

    int batchInsert(List<ProblemTemp> instance);

    ProblemTemp selectObjByObjectId(Integer objectid);

    List<ProblemTemp> selectObjByMap(Map params);

    int update(ProblemTemp instance);

}
