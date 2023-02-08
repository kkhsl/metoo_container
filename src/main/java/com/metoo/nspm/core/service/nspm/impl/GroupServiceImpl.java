package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.GroupMapper;
import com.metoo.nspm.core.service.nspm.IGroupService;
import com.metoo.nspm.dto.GroupDto;
import com.metoo.nspm.entity.nspm.Group;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class GroupServiceImpl implements IGroupService {


    public static void main(String[] args) {
        System.out.println(String.format("%0" + 4
                + "d", 01));
    }
    @Resource
    private GroupMapper groupMapper;

    @Override
    public List<Group> query(Map map) {
        return this.groupMapper.query(map);
    }

    @Override
    public Group selectObjById(Long id) {
        return this.groupMapper.selectObjById(id);
    }

    @Override
    public Group selectObjByName(String name) {
        return this.groupMapper.selectObjByName(name);
    }

    @Override
    public Group getObjByLevel(String level) {
        return this.groupMapper.getObjByLevel(level);
    }

    @Override
    public List<Group> selectObjByMap(Map map) {
        return this.groupMapper.selectObjByMap(map);
    }

    @Override
    public List<Group> queryChild(Long id) {
        return this.groupMapper.queryChild(id);
    }

    @Override
    public boolean save(GroupDto instance) {
        Group group = null;
        if(instance.getId() == null){
            instance.setAddTime(new Date());
            group = new Group();
        }else{
            instance.setUpdateTime(new Date());
            group = this.groupMapper.selectObjById(instance.getId());
        }
        BeanUtils.copyProperties(instance, group);

        if(instance.getId() == null){
            if(instance.getParentId() != null){
                Group parent = this.selectObjById(instance.getParentId());
                if(parent != null){
                    // 获取maxBranchLevel
                    Group maxGroup = this.groupMapper.getMaxBranch(parent.getLevel());
                    if(maxGroup != null){
                        System.out.println("%0" + maxGroup.getLevel().length() + "d");
                        System.out.println(String.format("%0" + maxGroup.getLevel().length() + "d", Integer.parseInt(maxGroup.getLevel()) + 1));
                        group.setLevel(String.format("%0" + maxGroup.getLevel().length() + "d", Integer.parseInt(maxGroup.getLevel()) + 1));
                        group.setParentLevel(parent.getLevel());
                        group.setParentId(parent.getId());
                    }else{
                        group.setLevel(parent.getLevel() + "01");
                        group.setParentLevel(parent.getLevel());
                        group.setParentId(parent.getId());
                    }

                }
            }else{
                group.setParentLevel("0");
                List<Group> parents = this.queryChild(null);
                int level = parents.size() + 1;
                group.setLevel(String.format("%02d", level));
            }
            try {
                this.groupMapper.save(group);
                return true;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }else{
            try {
                this.groupMapper.update(group);
                return true;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
    }

    @Override
    public boolean del(Long id) {
        try {
            this.groupMapper.del(id);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
