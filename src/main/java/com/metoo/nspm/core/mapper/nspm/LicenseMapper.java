package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.License;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface LicenseMapper {

    List<License> query();

    int update(License instance);
}
