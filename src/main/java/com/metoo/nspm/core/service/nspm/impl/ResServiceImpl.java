package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.ResMapper;
import com.metoo.nspm.core.service.nspm.IResService;
import com.metoo.nspm.dto.ResDto;
import com.metoo.nspm.entity.nspm.Res;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Service("resService")
@Transactional
public class ResServiceImpl implements IResService {

    @Autowired
    private ResMapper resMapper;

    @Override
    public List<Res> findResByRoleId(Long id) {
        return this.resMapper.findResByRoleId(id);
    }

    @Override
    public Res findObjById(Long id) {
        return this.resMapper.selectPrimaryById(id);
    }

    @Override
    public Res findObjByName(String name) {
        return this.resMapper.findObjByName(name);
    }

    @Override
    public Res findObjByNameAndLevel(Map map) {
        return this.resMapper.findObjByNameAndLevel(map);
    }

    @Override
    public Res findResUnitRoleByResId(Long id) {
        return this.resMapper.findResUnitRoleByResId(id);
    }

    @Override
    public Page<Res> query(ResDto dto) {
            Page<Res> page= PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());
            this.resMapper.query();
            return page;
    }

    @Override
    public List<Res> findPermissionByJoin(Map map) {
        return this.resMapper.findPermissionByJoin(map);
    }

    @Override
    public List<Res> findPermissionByMap(Map map) {
        return this.resMapper.findPermissionByMap(map);
    }

    @Override
    public List<Res> findResByResIds(List<Integer> ids) {
        return this.resMapper.findResByResIds(ids);
    }

    @Override
    public Collection<String> findPermissionByUserId(Long id) {
        return this.resMapper.findPermissionByUserId(id);
    }

    @Override
    public boolean save(ResDto dto) {
        Res obj = null;
        if(dto.getId() == null){
            obj = new Res();
            obj.setAddTime(new Date());
        }else{
            obj = this.resMapper.selectPrimaryById(dto.getId());
        }
        if(obj != null){
            BeanUtils.copyProperties(dto, obj);
            Res res = this.resMapper.selectPrimaryById(dto.getParentId());
            if(res != null){
                obj.setParentId(res.getId());
                obj.setParentName(res.getName());
            }
            obj.setType("URL");
            if(obj.getId() == null ){
                try {
                    this.resMapper.save(obj);
                    return true;
                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }
            }else{
                try {
                    this.resMapper.update(obj);
                    return true;
                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }
            }
        }
        return false;
    }


    @Override
    public boolean delete(Long id) {
        try {
            this.resMapper.delete(id);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
