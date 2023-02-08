package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.dto.TopoNodeDto;
import com.metoo.nspm.entity.nspm.TopoNode;
import com.github.pagehelper.Page;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface NodeMapper {

    TopoNode getObjById(Long id);

    TopoNode getObjByHostAddress(String hostAddress);

    /**
     * 分页查询
     * @param nodeDto
     * @return
     */
    Page<TopoNode> query(TopoNodeDto nodeDto);

    int save(TopoNode instance);

    int update(TopoNode instance);

    int delete(Long id);
}
