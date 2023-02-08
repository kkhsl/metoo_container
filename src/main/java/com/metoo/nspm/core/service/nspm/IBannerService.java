package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.dto.BannerDto;
import com.metoo.nspm.entity.nspm.Banner;
import com.github.pagehelper.Page;

import java.util.List;
import java.util.Map;

public interface IBannerService {

    Banner findObjById(Long id);

    List<Banner> findObjByMap(Map params);

    Page<Banner> query(BannerDto dto);

    boolean save(BannerDto dto);

    boolean update(BannerDto dto);

    boolean delete(Long id);
}
