package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.dto.ChangeLogDto;
import com.metoo.nspm.entity.nspm.ChangeLog;
import com.github.pagehelper.Page;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface ChangeLogMapper {


    Page<ChangeLog> findBySelect(ChangeLogDto dto);

    int save(ChangeLog instance);
}
