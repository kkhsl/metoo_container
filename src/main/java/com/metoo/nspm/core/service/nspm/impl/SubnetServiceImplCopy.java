package com.metoo.nspm.core.service.nspm.impl;

import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.metoo.nspm.core.mapper.nspm.SubnetMapperCopy;
import com.metoo.nspm.core.service.nspm.ISubnetServiceCopy;
import com.metoo.nspm.dto.SubnetDTO;
import com.metoo.nspm.entity.nspm.Subnet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
@Transactional
public class SubnetServiceImplCopy implements ISubnetServiceCopy {

    @Autowired
    private SubnetMapperCopy subnetMapper;

    @Override
    public Subnet selectObjById(Long id) {
        return this.subnetMapper.selectObjById(id);
    }

    @Override
    public Page<Subnet> selectObjConditionQuery(SubnetDTO dto) {
        Page<Subnet> page = PageHelper.startPage(dto.getCurrentPage(), dto.getCurrentPage());
        this.subnetMapper.selectObjConditionQuery(dto);
        return page;
    }

    @Override
    public List<Subnet> selectObjByMap(Map params) {
        return this.subnetMapper.selectObjByMap(params);
    }

    @Override
    public int save(Subnet instance) {
        try {
            return this.subnetMapper.save(instance);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int update(Subnet instance) {
        try {
            return this.subnetMapper.update(instance);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int delete(Long id) {
        try {
            return this.subnetMapper.delete(id);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }
}
