package com.metoo.nspm.core.service.zabbix;

import com.metoo.nspm.entity.zabbix.ItemTag;
import com.metoo.nspm.vo.ItemTagBoardVO;

import java.util.List;
import java.util.Map;

public interface IItemTagService {

    // 获取最小ifbasic-ifindex
    ItemTag selectItemTagMinIfIndex(String ip);

    ItemTag selectItemTagIfNameByIndex(Map params);

    List<ItemTagBoardVO> selectBoardByTag(Map params);

    List<ItemTagBoardVO> selectBoard(String ip, Long time_from, Long time_till);

    List<ItemTag> queryBoard(String ip);
}
