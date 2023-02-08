package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.dto.PresetPathDTO;
import com.metoo.nspm.entity.nspm.PresetPath;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface PresetPathMapper {

    PresetPath selectObjById(Long id);

    List<PresetPath> selectConditionQuery(PresetPathDTO dto);

    List<PresetPath> selectObjByMap(Map params);

    int save(PresetPath instance);

    int update(PresetPath instance);

    int delete(Long id);
}
