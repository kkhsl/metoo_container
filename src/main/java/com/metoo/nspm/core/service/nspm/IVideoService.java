package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.dto.VideoDto;
import com.metoo.nspm.entity.nspm.Video;
import com.github.pagehelper.Page;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

public interface IVideoService {

    Video getObjById(Long id);

    Video selectPrimaryById(Long id);

    List<Video> findObjByMap(Map params);

//    Page<Video> findObjByReq(VideoDto dto);

    Page<Video> query(VideoDto dto);

    List<Video> findObjBuLiveRoomId(Long id);

    Object save(VideoDto instance);

    boolean save(Video instance);

    boolean update(VideoDto instance);

    boolean update(Video instance);

    boolean delete(Long id);

    boolean batchDelete(List<Serializable> ids);

    List<Video> queryAll(Integer currentPage, Integer pageSize);

}
