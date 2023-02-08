package com.metoo.nspm.core.mapper.nspm.zabbix;

import com.metoo.nspm.dto.NspmProblemDTO;
import com.metoo.nspm.entity.zabbix.Problem;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface NspmProblemMapper {


    List<Problem> selectObjConditionQuery(NspmProblemDTO dto);

    List<Problem> selectObjByMap(Map params);

    void truncateTable();

    void copyProblemTemp(Map params);

}
