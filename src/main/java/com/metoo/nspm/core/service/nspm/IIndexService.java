package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.vo.MenuVo;

import java.util.List;

public interface IIndexService {

    /**
     * 根据用户id查询角色及角色组
     * @param id
     * @return
     */
    List<MenuVo> findMenu(Long id);

}
