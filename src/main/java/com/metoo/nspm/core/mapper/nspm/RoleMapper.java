package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.dto.RoleDto;
import com.metoo.nspm.entity.nspm.Role;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface RoleMapper {

    /**
     * 根据角色id查询指定角色
     * @param id
     * @return
     */
    Role findRoleById(Long id);

    Role findRoleByName(String name);

    Role selectByPrimaryUpdae(Long id);

    /**
     * 根据角色类型，查询所有角色
     * @return
     */
    default List<Role> findRoleByType() {
        return findRoleByType();
    }

    /**
     * 根据角色类型，查询所有角色
     * @param type
     * @return
     */
    List<Role> findRoleByType(String type);

    /**
     *根据用户id查询用所有角色信息
     * @param user_id
     * @return
     */
    List<Role> findRoleByUserId(Long user_id);


    List<Role> findRoleByRoleGroupByUserId(Long user_id);

    List<Role> findRoleByRoleGroupId(Long role_group_id);

    /**
     * 根据权限ID查询角色集合
     * @param id
     * @return
     */
    List<Role> findRoleByResId(Long id);

    /**
     * 方式一：
     * 根据角色Id集合查询角色
     * @param list
     * @return
     */
    List<Role> findRoleByIdList(List<Integer> list);

    List<Role> findRoleByIds(String ids);

    /**
     * 根据角色类型查询角色， 目前只有一种角色，默认使用“ADMIN”
     * @return
     */
    List<Role> query(RoleDto dto);

    List<Role> findObjByMap(Map params);

    int insert(Role instance);

    int update(Role instance);

    int delete(Long id);

    /**
     * 批量修改
     * @param map
     * @return
     */
    int batchUpdateRoleGroupId(Map map);
}
