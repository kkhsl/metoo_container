package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.dto.VideoDto;
import com.metoo.nspm.entity.nspm.Video;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface VideoMapper {

    /**
     * 根据Video Id 查找Video对象
     * @param id Video Id
     * @return
     */
    Video get(Long id);

    int insert(Video instance);

    int update(Video instance);

    int delete(Long id);

    List<Video> selectAll();

    List<Video> query(VideoDto dto);

    List<Video> findObjByMap(Map map);

    List<Video> findObjBuLiveRoomId(Long id);


    Video videoUnit(Long id);

    /**
     * 根据直播间Id查询回放/and上传视频列表
     * @param id
     * @return
     */
    List<Video> selectByLiveRoomId(Long id);
}
