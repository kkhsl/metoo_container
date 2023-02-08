package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.Accessory;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface AccessoryMapper {

    /**
     * 根据ID查询一个Accessory对象
     * @param id
     * @return
     */
    Accessory getObjById(Long id);

    /**
     * 保存一个Accessory附件对象
     * @param instance
     * @return
     */
    int save(Accessory instance);

    /**
     * 更新
     * @param instance
     * @return
     */
    int update(Accessory instance);

    /**
     * 删除
     * @param id
     * @return
     */
    int delete(Long id);

    /**
     * 根据条件查询一组附件
     * @param params
     * @return
     */
    List<Accessory> query(Map params);
}
