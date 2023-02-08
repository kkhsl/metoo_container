package com.metoo.nspm.core.service.zabbix;

import com.metoo.nspm.entity.nspm.ProblemTemp;

import java.util.List;
import java.util.Map;

public interface IProblemTempService {

    void truncateTable();

    int batchInsert(List<ProblemTemp> instance);

    ProblemTemp selectObjByObjectId(Integer objectid);

    List<ProblemTemp> selectObjByMap(Map params);

    int update(ProblemTemp instance);

}
