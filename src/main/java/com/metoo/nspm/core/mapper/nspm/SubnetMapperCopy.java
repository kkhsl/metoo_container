package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.dto.SubnetDTO;
import com.metoo.nspm.entity.nspm.Subnet;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface SubnetMapperCopy {

    Subnet selectObjById(Long id);

    List<Subnet> selectObjConditionQuery(SubnetDTO dto);

    List<Subnet> selectObjByMap(Map params);

    int save(Subnet instance);

    int update(Subnet instance);

    int delete(Long id);
}
