package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.Vendor;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface VendorMapper {

    Vendor selectObjById(Long id);

    Vendor selectObjByName(String name);


    List<Vendor> selectConditionQuery(Map params);

}
