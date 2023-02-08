package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.dto.MonitorDto;
import com.metoo.nspm.entity.nspm.Monitor;
import com.metoo.nspm.vo.MonitorVo;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface MonitorMapper {

    /**
     * 根据监控ID查询该记录是否存在
     * @param id
     * @return
     */
    Monitor getObjById(Long id);

    /**
     * 根据签名信息查询记录是否存在
     * @param sign
     * @return
     */
    Monitor getObjBySign(String sign);

    /**
     * 条件查询
     * @param dto
     * @return
     */
    List<MonitorVo> query(MonitorDto dto);

    /**
     * 保存监控信息
     * @param instance
     * @return
     */
    int save(Monitor instance);

    /**
     * 更新监控信息
     * @param instance
     * @return
     */
    int update(Monitor instance);

    /**
     * 根据监控id删除监控记录
     * @param id
     * @return
     */
    int delete(Long id);

}
