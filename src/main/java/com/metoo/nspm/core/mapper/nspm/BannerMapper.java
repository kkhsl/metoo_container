package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.dto.BannerDto;
import com.metoo.nspm.entity.nspm.Banner;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface BannerMapper {

    Banner findObjById(Long id);

    List<Banner> findObjByMap(Map params);


    List<Banner> query(BannerDto dto);

    boolean save(Banner dto);

    boolean update(Banner dto);

    boolean delete(Long id);
}
