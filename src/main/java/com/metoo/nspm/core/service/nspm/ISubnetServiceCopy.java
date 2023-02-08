package com.metoo.nspm.core.service.nspm;

import com.github.pagehelper.Page;
import com.metoo.nspm.dto.SubnetDTO;
import com.metoo.nspm.entity.nspm.Subnet;

import java.util.List;
import java.util.Map;

public interface ISubnetServiceCopy {

    Subnet selectObjById(Long id);

    Page<Subnet> selectObjConditionQuery(SubnetDTO dto);

    List<Subnet> selectObjByMap(Map params);

    int save(Subnet instance);

    int update(Subnet instance);

    int delete(Long id);
}
