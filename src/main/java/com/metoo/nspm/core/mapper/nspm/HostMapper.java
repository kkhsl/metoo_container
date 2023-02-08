package com.metoo.nspm.core.mapper.nspm;

import com.github.pagehelper.Page;
import com.metoo.nspm.dto.HostDTO;
import com.metoo.nspm.entity.nspm.Host;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface HostMapper {

    Host selectObjById(Long id);

    Page<Host> selectConditionQuery(HostDTO instance);

    List<Host> selectObjByMap(Map params);

    int save(Host instance);

    int update(Host instance);

    int delete(Long id);
}
