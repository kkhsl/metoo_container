package com.metoo.nspm.core.mapper.zabbix;

import com.metoo.nspm.dto.NspmProblemDTO;
import com.metoo.nspm.dto.zabbix.ProblemDTO;
import com.metoo.nspm.entity.zabbix.Problem;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface ProblemMapper {



    int selectCount(Map params);

}
