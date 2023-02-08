package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.dto.LiveRoomDto;
import com.metoo.nspm.entity.nspm.LiveRoom;
import com.metoo.nspm.vo.WebLiveRoomVo;
import com.github.pagehelper.Page;

import java.util.List;
import java.util.Map;

public interface ILiveRoomService {
    /**
     * 根据LiveRoom id 获取一个LiveRoom 对象
     * @param id
     * @return
     */
    LiveRoom getObjById(Long id);


    /**
     *分页查询
     * @param dto
     * @return
     */
    Page<LiveRoom> query(LiveRoomDto dto);

    /**
     * 条件查询
     * @param params
     * @return
     */
    List<LiveRoom> findObjByMap(Map<String, Object> params);


    /**
     * 查询所有的LiveRoom对象
     * @return
     */
    List<LiveRoom> findAllLiveRoom();


    /**
     * 保存一个LiveRoom 对象
     * @param instance
     * @return
     */
    boolean save(LiveRoom instance);

    /**
     * 更新一个LiveRoom 对象
     * @param instance
     * @return
     */
    public int update(LiveRoom instance);

    /**
     *删除直播间
     * @param id
     * @return
     */
    int delete(Long id);


    /**
     * 查询总数
     * @return
     */
    int findAccountByTotal();

    int modify(String property);

    /**
     * 分页查询
     * @return
     */
   List<LiveRoom> queryLiveRooms(Integer currentPage, Integer pageSize);

   Page<WebLiveRoomVo> webLiveRoom(Map<String, Object> params);

}
