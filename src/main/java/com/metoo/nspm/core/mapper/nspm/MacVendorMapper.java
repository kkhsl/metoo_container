package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.MacVendor;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface MacVendorMapper {

    List<MacVendor> selectObjByMap(Map params);
}
