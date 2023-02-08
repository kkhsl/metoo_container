package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.dto.GradeDto;
import com.metoo.nspm.entity.nspm.Grade;
import com.github.pagehelper.Page;

import java.util.List;
import java.util.Map;

public interface IGradeService {

    Grade getObjById(Long id);

    List<Grade> selectAll(Map params);

    Object save(GradeDto instance);

    Object update(Grade instance);

    boolean delete(Long id);

    Grade modify(Long id);

    Page<Grade> query(Map params);

    /**
     * 条件查询
     * @param params
     * @return
     */
    List<Grade> findBycondition(Map params);

    /**
     * web页面年级列表
     * @param params
     * @return
     */
    List<Grade> webGradeList(Map params);
}
