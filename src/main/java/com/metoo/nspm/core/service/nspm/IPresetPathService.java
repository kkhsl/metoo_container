package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.dto.PresetPathDTO;
import com.metoo.nspm.entity.nspm.PresetPath;
import com.github.pagehelper.Page;

import java.util.List;
import java.util.Map;

public interface IPresetPathService {

    PresetPath selectObjById(Long id);

    Page<PresetPath> selectConditionQuery(PresetPathDTO dto);

    List<PresetPath> selectObjByMap(Map params);

    int save(PresetPath instance);

    int update(PresetPath instance);

    int delete(Long id);
}
