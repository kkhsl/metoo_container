package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.dto.PlantRoomDTO;
import com.metoo.nspm.entity.nspm.PlantRoom;
import com.metoo.nspm.vo.PlantRoomVO;
import com.github.pagehelper.Page;

import java.util.List;
import java.util.Map;

public interface IPlantRoomService {

    PlantRoom getObjById(Long id);

    PlantRoom selectObjByName(String name);

    // 查询所有机房
    List<PlantRoomVO> query(PlantRoom instance);

    Page<PlantRoom> selectConditionQuery(PlantRoomDTO instance);

    Page<PlantRoom> findBySelectAndRack(PlantRoomDTO instance);

    List<PlantRoom> selectObjByCard();

    List<PlantRoom> selectObjByMap(Map params);

    List<PlantRoomVO> selectVoByMap(Map params);

    int save(PlantRoom instance);

    int delete(Long id);

    int batchDel(String ids);
}
