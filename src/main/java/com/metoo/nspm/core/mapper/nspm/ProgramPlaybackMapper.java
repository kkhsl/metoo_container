package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.ProgramPlayback;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface ProgramPlaybackMapper {

    /**
     * 保存一个ProgramPlayback对象
     * @param instance
     * @return
     */
    int insert(ProgramPlayback instance);


}
