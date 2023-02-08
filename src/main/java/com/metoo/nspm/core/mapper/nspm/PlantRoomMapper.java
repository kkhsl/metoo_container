package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.dto.PlantRoomDTO;
import com.metoo.nspm.entity.nspm.PlantRoom;
import com.metoo.nspm.vo.PlantRoomVO;
import com.github.pagehelper.Page;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface PlantRoomMapper {

    PlantRoom getObjById(Long id);

    PlantRoom selectObjByName(String name);

    List<PlantRoomVO> query(PlantRoom instance);

    List<PlantRoom> selectConditionQuery(PlantRoomDTO instance);

    List<PlantRoom> findBySelectAndRack(PlantRoomDTO instance);

    List<PlantRoom> selectObjByCard(Map params);

    List<PlantRoom> selectObjByMap(Map params);

    List<PlantRoomVO> selectVoByMap(Map params);

    int save(PlantRoom instance);

    int update(PlantRoom instance);

    int delete(Long id);

    int batchDel(String ids);
}
