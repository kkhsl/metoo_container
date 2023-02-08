package com.metoo.nspm.core.service.nspm;

import com.github.pagehelper.Page;
import com.metoo.nspm.dto.LinkDTO;
import com.metoo.nspm.entity.nspm.Link;

import java.util.List;
import java.util.Map;

public interface ILinkService {

    Link selectObjById(Long id);

    Page<Link> selectObjConditionQuery(LinkDTO instance);

    List<Link> selectObjByMap(Map params);

    int save(Link instace);

    int update(Link instace);

    int delete(Long id);

    int batchesDel(Long[] ids);

    int batchesInsert(List<Link> instances);
}
