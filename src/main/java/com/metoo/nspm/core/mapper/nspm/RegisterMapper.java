package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface RegisterMapper {

    /**
     * 保存一个User对象
     * @param user
     */
    int save(User user);


}
