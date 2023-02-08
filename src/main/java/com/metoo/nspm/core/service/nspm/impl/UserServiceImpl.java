package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.mapper.nspm.LiveRoomMapper;
import com.metoo.nspm.core.mapper.nspm.UserMapper;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.dto.UserDto;
import com.metoo.nspm.entity.nspm.*;
import com.metoo.nspm.vo.UserVo;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import org.apache.shiro.SecurityUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@Transactional
public class UserServiceImpl implements IUserService {

    @Autowired
    private UserMapper userMapper;
    @Autowired
    private IUserRoleService userRoleService;
    @Autowired
    private IRoleService roleService;
    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private ILiveRoomService liveRoomService;
    @Autowired
    private LiveRoomMapper liveRoomMapper;
    @Autowired
    private IGroupService groupService;
    @Autowired
    private IPlantRoomService plantRoomService;

    @Override
    public User findByUserName(String username) {
        return this.userMapper.findByUserName(username);
    }

    @Override
    public User findRolesByUserName(String username) {
        return null;
    }

    @Override
    public UserVo findUserUpdate(Long id) {
        return this.userMapper.findUserUpdate(id);
    }

    @Override
    public User findObjById(Long id) {
        return this.userMapper.selectPrimaryKey(id);
    }

    @Override
    public Page<UserVo> getObjsByLevel(UserDto dto) {
        if(dto.getGroupLevel() == null || dto.getGroupLevel().equals("")){
            User currentUser = ShiroUserHolder.currentUser();
            User user = this.findByUserName(currentUser.getUsername());
            dto.setGroupLevel(user.getGroupLevel());
        }
        Page<UserVo> page = PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());
        this.userMapper.getObjsByLevel(dto.getGroupLevel());
        return page;
    }

    @Override
    public List<String> getObjByLevel(String level) {
        Group group = this.groupService.getObjByLevel(level);
        if(group == null){
            User currentUser = ShiroUserHolder.currentUser();
            User user = this.findByUserName(currentUser.getUsername());
            group = this.groupService.getObjByLevel(user.getGroupLevel());
        }
        if(group != null) {
            List<Group> groups = this.groupService.queryChild(group.getId());
            groups.add(group);
            List<String> users = this.userMapper.getObjByLevel(groups);
            return users;
        }

        return null;
    }

    @Override
    public Page<UserVo> query(UserDto dto) {
        Page<UserVo> page = PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());
        this.userMapper.query(dto);
        return page;
    }


    @Override
    public boolean save(UserDto dto) {
        User user = null;
        if(dto.getId() == null){
            user = new User();
            dto.setAddTime(new Date());
        }else{
            user = this.userMapper.selectPrimaryKey(dto.getId());
        }
        BeanUtils.copyProperties(dto, user);
        // 查询组信息
        Group group = this.groupService.selectObjById(dto.getGroupId());
        if(group != null){
            user.setGroupName(group.getBranchName());
            user.setGroupLevel(group.getLevel());
        }else{// 未设置组时，默认为所属组与当前用户相同
            User currentUser = ShiroUserHolder.currentUser();
            currentUser = this.userMapper.findByUserName(currentUser.getUsername());
            System.out.println(currentUser.getGroupLevel());
            user.setGroupLevel(currentUser.getGroupLevel());
            user.setGroupName(currentUser.getGroupName());
            user.setGroupId(currentUser.getGroupId());
        }
        if(dto.getId() == null){
            try {
                this.userMapper.insert(user);
                // 创建默认机房
                PlantRoom plantRoom = new PlantRoom();
                plantRoom.setName("默认机房");
                plantRoom.setDeleteStatus(1);
                plantRoom.setAddTime(new Date());
                plantRoom.setUserId(user.getId());
                plantRoom.setDefault(true);
                this.plantRoomService.save(plantRoom);
//                // 创建直播间
//                Map params = new HashMap();
//                params.put("currentPage", 0);
//                params.put("pageSize", 1);
//                params.put("userId", user.getId());
//                List<LiveRoom> liveRoomList = this.liveRoomService.findObjByMap(params);
//               if(liveRoomList.size() < 1){
//                   LiveRoom instance = new LiveRoom();
//                   instance.setDeleteStatus(0);
//                   instance.setAddTime(new Date());
//                   instance.setTitle(user.getUsername() + "的直播间");
//                   Date date = new Date();
//                   SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
//                   String df = sdf.format(date);
//                   String bindCode = df + CommUtils.randomString(6);// 推流码
//                   instance.setBindCode(bindCode);
//                   instance.setUser(user);
//                   instance.setUserId(user.getId());
//                   instance.setUsername(user.getUsername());
//                   instance.setIsEnable(1);
//                   if(instance.getManager() == null || instance.getManager().equals("")){
//                       instance.setManager(user.getUsername());
//                   }
//                   //rtmp://lk.soarmall.com:1935/hls
//                   SysConfig SysConfig = this.sysConfigService.findSysConfigList();
//                   String rtmp = CommUtils.getRtmp(SysConfig.getIp(), bindCode);
//                   String obsRtmp = CommUtils.getObsRtmp(SysConfig.getIp());
//                   String path =  SysConfig.getPath() + File.separator + bindCode;
//                   instance.setRtmp(rtmp);
//                   instance.setObsRtmp(obsRtmp);
//                   try {
//                       FileUtil.storeFile(path);
//                       FileUtil.possessor(path);
//                   } catch (IOException e) {
//                       e.printStackTrace();
//                   }
//                   this.liveRoomMapper.save(instance);
//               }
                String roleName = "";
                // 批量添加用户角色信息
                if(dto.getRole_id() != null && dto.getRole_id().length > 0){
                    List<Integer> idList = Arrays.asList(dto.getRole_id());
                    List<Role> roleList = this.roleService.findRoleByIdList(idList);
                    List<UserRole> userRoles = new ArrayList<UserRole>();
                    for(Role role : roleList){
                        UserRole userRole = new UserRole();
                        userRole.setUser_id(user.getId());
                        userRole.setRole_id(role.getId());
                        userRoles.add(userRole);
                        roleName += role.getName() + ",";
                    }
                    roleName = roleName.substring(0,roleName.lastIndexOf(","));
                    this.userRoleService.batchAddUserRole(userRoles);
                }
                    try {
                        user.setUserRole(roleName);
                        this.userMapper.update(user);
                        return true;
                    } catch (Exception e) {
                        e.printStackTrace();
                        return false;
                    }
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }else{
            try {
                String roleName = "";

                // 批量添加用户角色信息
                if(dto.getRole_id() != null && dto.getRole_id().length > 0){
                    // 清除用户角色信息
                    this.userRoleService.deleteUserByRoleId(user.getId());
                    List<Integer> idList = Arrays.asList(dto.getRole_id());
                    List<Role> roleList = this.roleService.findRoleByIdList(idList);
                    List<UserRole> userRoles = new ArrayList<UserRole>();
                    for(Role role : roleList){
                        UserRole userRole = new UserRole();
                        userRole.setUser_id(user.getId());
                        userRole.setRole_id(role.getId());
                        userRoles.add(userRole);
                        roleName += role.getName() + ",";
                    }
                    roleName = roleName.substring(0, roleName.lastIndexOf(","));
                    this.userRoleService.batchAddUserRole(userRoles);
                }
                user.setUserRole(roleName);
                this.userMapper.update(user);
                User currentUser = ShiroUserHolder.currentUser();


                // 第一种方式 强制退出当前帐号
                // 如果修改的是当前已登录用户信息则退出当前帐号
                if(dto.isFlag() && currentUser.getId().equals(user.getId())){
                     SecurityUtils.getSubject().logout();
                    // 修改身份信息后，动态更改Subject的用户属性
                   /* Subject subject = SecurityUtils.getSubject();
                    String username = (String) subject.getPrincipal();
                    User userInfo = this.userMapper.findByUserName(username);// 查询指定属性，封装到Subject内
                    PrincipalCollection newPrincipalCollection =
                            new SimplePrincipalCollection(userInfo, userInfo.getUsername());
                    subject.runAs(newPrincipalCollection);*/
                }

                //第二种防止 强制退出被修改用户

                return true;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
    }

    @Override
    public boolean update(User user) {
        try {
            this.userMapper.update(user);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean delete(User user) {
        // 清除用户角色
        try {
            this.userRoleService.deleteUserByRoleId(user.getId());
            this.userMapper.delete(user.getId());
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean deleteByLevel(String level) {
        return this.userMapper.deleteByLevel(level);
    }

    @Override
    public boolean allocation(List<User> list){
        try {
            this.userMapper.allocation(list);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public List<User> findObjByIds(Long[] ids) {
        return this.userMapper.findObjByIds(ids);
    }


}
