package com.metoo.nspm.core.service.nspm;

import com.github.pagehelper.Page;
import com.metoo.nspm.dto.VlanDTO;
import com.metoo.nspm.entity.nspm.Vlan;

import java.util.List;
import java.util.Map;

public interface IVlanService {

    Vlan selectObjById(Long id);

    Page<Vlan> selectObjConditionQuery(VlanDTO dto);

    List<Vlan> selectObjByMap(Map params);

    int save(Vlan instance);

    int update(Vlan instance);

    int delete(Long id);
}
