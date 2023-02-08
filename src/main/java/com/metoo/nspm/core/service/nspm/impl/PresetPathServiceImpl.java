package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.PresetPathMapper;
import com.metoo.nspm.core.service.nspm.IPresetPathService;
import com.metoo.nspm.dto.PresetPathDTO;
import com.metoo.nspm.entity.nspm.PresetPath;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class PresetPathServiceImpl implements IPresetPathService {

    @Autowired
    private PresetPathMapper presetPathMapper;

    @Override
    public PresetPath selectObjById(Long id) {
        return this.presetPathMapper.selectObjById(id);
    }

    @Override
    public Page<PresetPath> selectConditionQuery(PresetPathDTO dto) {
        if(dto == null){
            dto = new PresetPathDTO();
        }
        Page<PresetPath> page = PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());

        this.presetPathMapper.selectConditionQuery(dto);
        return page;
    }

    @Override
    public List<PresetPath> selectObjByMap(Map params) {
        return this.presetPathMapper.selectObjByMap(params);
    }

    @Override
    public int save(PresetPath instance) {
        if(instance.getId() == null || instance.getId().equals("")){
            instance.setAddTime(new Date());
        }
        if(instance.getId() == null || instance.getId().equals("")){
            try {
                return this.presetPathMapper.save(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }else{
            try {
                return this.presetPathMapper.update(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }

    }

    @Override
    public int update(PresetPath instance) {
        try {
            return this.presetPathMapper.update(instance);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int delete(Long id) {
        try {
            return this.presetPathMapper.delete(id);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }
}
