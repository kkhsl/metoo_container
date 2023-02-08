package com.metoo.nspm.core.service.nspm;

import com.github.pagehelper.Page;
import com.metoo.nspm.dto.HostDTO;
import com.metoo.nspm.entity.nspm.Host;

import java.util.List;
import java.util.Map;

public interface IHostService {

    Host selectObjById(Long id);

    Page<Host> selectConditionQuery(HostDTO dto);

    List<Host> selectObjByMap(Map params);

    int save(Host instance);

    int update(Host instance);

    int delete(Long id);
}
