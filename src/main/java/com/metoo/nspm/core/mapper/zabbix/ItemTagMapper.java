package com.metoo.nspm.core.mapper.zabbix;

import com.metoo.nspm.entity.zabbix.ItemTag;
import com.metoo.nspm.vo.ItemTagBoardVO;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface ItemTagMapper {

    // 获取最小ifbasic-ifindex
    ItemTag selectItemTagMinIfIndex(String ip);

    ItemTag selectItemTagIfNameByIndex(Map params);

    List<ItemTagBoardVO> selectBoardByTag(Map params);

    List<ItemTag> queryBoard(String ip);
}
