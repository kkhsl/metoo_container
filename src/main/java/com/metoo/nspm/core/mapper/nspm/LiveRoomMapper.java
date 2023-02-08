package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.dto.LiveRoomDto;
import com.metoo.nspm.entity.nspm.LiveRoom;
import com.metoo.nspm.vo.WebLiveRoomVo;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface LiveRoomMapper {

    /**
     * 根据LiveRoom id 获取一个LiveRoom 对象
     * @param id
     * @return
     */
    LiveRoom getObjById(Long id);

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
    int save(LiveRoom instance);

    /**
     * 更新一个LiveRoom 对象
     * @param instance
     * @return
     */
    int update(LiveRoom instance);

    /**
     *删除直播间
     * @param id
     * @return
     */
    int delete(Long id);

    /**
     *分页查询
     * @param dto
     * @return
     */
    List<LiveRoom> query(LiveRoomDto dto);

    /**
     * 查询总数
     * @return
     */
    int getAccountByTotal();

    int change(String isEnable);


    /**
     * pageHelper 分页插件；查询所有
     * @return
     */
    List<LiveRoom> selectAll();

    /**
     *
     * @param params
     * @return
     */
    List<LiveRoom> findObjByMap(Map<String, Object> params);


    /**
     * 联合查询，直播间-直播节目-年级-科目表（根据年级序列排序）
     * @param params
     * @return
     */
    List<WebLiveRoomVo> webLiveRoom(Map<String, Object> params);



}
