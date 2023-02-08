package com.metoo.nspm.core.service.zabbix.impl;

import com.metoo.nspm.core.mapper.zabbix.HistoryMapper;
import com.metoo.nspm.core.mapper.zabbix.ItemTagMapper;
import com.metoo.nspm.core.service.api.zabbix.ZabbixService;
import com.metoo.nspm.core.service.zabbix.IItemTagService;
import com.metoo.nspm.entity.zabbix.History;
import com.metoo.nspm.entity.zabbix.Item;
import com.metoo.nspm.entity.zabbix.ItemTag;
import com.metoo.nspm.vo.ItemTagBoardVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class ItemTagSeviceImpl implements IItemTagService {

    @Autowired
    private ItemTagMapper itemTagMapper;
    @Autowired
    private HistoryMapper historyMapper;
    @Autowired
    private ZabbixService zabbixService;

    @Override
    public ItemTag selectItemTagMinIfIndex(String ip) {
        return itemTagMapper.selectItemTagMinIfIndex(ip);
    }

    @Override
    public ItemTag selectItemTagIfNameByIndex(Map params) {
        return this.itemTagMapper.selectItemTagIfNameByIndex(params);
    }

    @Override
    public List<ItemTagBoardVO> selectBoardByTag(Map params) {
        return this.itemTagMapper.selectBoardByTag(params);
    }

    @Override
    public List<ItemTagBoardVO> selectBoard(String ip, Long time_from, Long time_till) {
        Map params = new HashMap();
        params.put("ip", ip);
        List<ItemTagBoardVO> boards = this.selectBoardByTag(params);
        if(boards.size() > 0){
            for (ItemTagBoardVO board : boards) {
                if(board.getItems().size() > 0){
                    for (Item item : board.getItems()) {
                        Long itemid = item.getItemid();
                        // 获取历史信息
                        params.clear();
                        Integer from = time_from.intValue();
                        Integer till = time_till.intValue();
                        params.put("time_from", from);
                        params.put("time_till", till);
                        params.put("itemid", itemid);
                        List<History> sentHistory = this.historyMapper.selectObjByMap(params);
                        List<History>  replenishSentHistory = this.zabbixService.parseHistoryZeroize(sentHistory, time_from, time_till);
                        if(item.getBoardType().equals("BOARDCPU")){
                            board.setCpu(replenishSentHistory);
                        }else if(item.getBoardType().equals("BOARDMEM")){
                            board.setMem(replenishSentHistory);
                        }else if(item.getBoardType().equals("BOARDTEMP")){
                            board.setTemp(replenishSentHistory);
                        }
                    }
                }
            }
            return boards;
        }
        return new ArrayList<>();
    }

    @Override
    public List<ItemTag> queryBoard(String ip) {
        return this.itemTagMapper.queryBoard(ip);
    }


}
