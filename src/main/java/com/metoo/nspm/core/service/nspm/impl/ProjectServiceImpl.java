package com.metoo.nspm.core.service.nspm.impl;

import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.mapper.nspm.ProjectMapper;
import com.metoo.nspm.core.service.nspm.IProjectService;
import com.metoo.nspm.dto.ProjectDTO;
import com.metoo.nspm.entity.nspm.Project;
import com.metoo.nspm.entity.nspm.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class ProjectServiceImpl implements IProjectService {

    @Autowired
    private ProjectMapper projectMapper;

    @Override
    public Project selectObjById(Long id) {
        Project project = this.projectMapper.selectObjById(id);
        if(project != null){
            User user = ShiroUserHolder.currentUser();
            if(project.getUserId().equals(user.getId())){
               return project;
            }
        }
        return null;
    }

    @Override
    public Project selectObjByName(String name) {
        return this.projectMapper.selectObjByName(name);
    }

    @Override
    public Page<Project> selectObjConditionQuery(ProjectDTO dto) {
        if(dto == null){
            dto = new ProjectDTO();
        }
        User user = ShiroUserHolder.currentUser();
        dto.setUserId(user.getId());
        Page<Project> page = PageHelper.startPage(
                dto.getCurrentPage(), dto.getPageSize());
        this.projectMapper.selectConditionQuery(dto);
        return page;
    }

    @Override
    public List<Project> selectObjByMap(Map params) {
        User user = ShiroUserHolder.currentUser();
        params.put("userId", user.getId());
        return this.projectMapper.selectObjByMap(params);
    }

    @Override
    public int save(Project instance) {
        User user = ShiroUserHolder.currentUser();
        if(instance.getId() == null){
            instance.setAddTime(new Date());
            instance.setUserId(user.getId());
            instance.setUserName(user.getUsername());
        }
        if(instance.getId() == null){
            try {
                return this.projectMapper.save(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }else{
            try {
                return this.projectMapper.update(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }

    }

    @Override
    public int update(Project instance) {
        try {
            return this.projectMapper.update(instance);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int delete(Long id) {
        try {
            return this.projectMapper.delete(id);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }
}
