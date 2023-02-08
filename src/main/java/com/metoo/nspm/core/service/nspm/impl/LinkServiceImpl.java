package com.metoo.nspm.core.service.nspm.impl;

import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.mapper.nspm.LinkMapper;
import com.metoo.nspm.core.service.nspm.ILinkService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.LinkDTO;
import com.metoo.nspm.dto.MacDTO;
import com.metoo.nspm.entity.nspm.Link;
import com.metoo.nspm.entity.nspm.Mac;
import com.metoo.nspm.entity.nspm.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class LinkServiceImpl implements ILinkService {

    @Autowired
    private LinkMapper linkMapper;

    @Override
    public Link selectObjById(Long id) {
        return this.linkMapper.selectObjById(id);
    }

    @Override
    public Page<Link> selectObjConditionQuery(LinkDTO dto) {
        if(dto == null){
            dto = new LinkDTO();
        }
        Page<Link> page = PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());
        this.linkMapper.selectObjConditionQuery(dto);
        return page;
    }

    @Override
    public List<Link> selectObjByMap(Map params) {
        return this.linkMapper.selectObjByMap(params);
    }

    @Override
    public int save(Link instance) {
        User user = ShiroUserHolder.currentUser();
        if(instance.getGroupId() == null){
            instance.setGroupId(user.getGroupId());
        }
        if(instance.getId() == null || instance.getId().equals("")){
            instance.setAddTime(new Date());
        }
        if(instance.getId() == null  || instance.getId().equals("")){
            try {
                return this.linkMapper.save(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }else{
            try {
                return this.linkMapper.update(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }
    }

    @Override
    public int update(Link instace) {
        try {
            return this.linkMapper.update(instace);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int delete(Long id) {
        try {
            return this.linkMapper.delete(id);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int batchesDel(Long[] ids) {
        try {
            return this.linkMapper.batchesDel(ids);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int batchesInsert(List<Link> instances) {
        try {
           return this.linkMapper.batchesInsert(instances);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }
}
