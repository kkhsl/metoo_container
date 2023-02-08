package com.metoo.nspm.core.service.zabbix;

import com.github.pagehelper.Page;
import com.metoo.nspm.dto.NspmProblemDTO;
import com.metoo.nspm.dto.zabbix.ProblemDTO;
import com.metoo.nspm.entity.zabbix.Problem;

import java.util.List;
import java.util.Map;

public interface IProblemService {

    Page<Problem> selectConditionQuery(NspmProblemDTO dto);

    List<Problem> selectObjByMap(Map params);

    int selectCount(Map params);

    void truncateTable();

    void copyProblemTemp(Map params);
}
