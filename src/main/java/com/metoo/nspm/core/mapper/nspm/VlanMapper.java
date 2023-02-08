package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.dto.VlanDTO;
import com.metoo.nspm.entity.nspm.Vlan;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface VlanMapper {

    Vlan selectObjById(Long id);

    List<Vlan> selectObjConditionQuery(VlanDTO dto);

    List<Vlan> selectObjByMap(Map params);

    int save(Vlan instance);

    int update(Vlan instance);

    int delete(Long id);
}
