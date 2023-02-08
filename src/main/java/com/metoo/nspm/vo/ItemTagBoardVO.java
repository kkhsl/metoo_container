package com.metoo.nspm.vo;

import com.metoo.nspm.entity.zabbix.History;
import com.metoo.nspm.entity.zabbix.Item;
import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@ApiModel("item tag board")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ItemTagBoardVO {

    private Long itemtagid;

    private String value;

    private List<Item> items = new ArrayList<>();

    private List<History> cpu = new ArrayList<>();;

    private List<History> mem = new ArrayList<>();;

    private List<History> temp = new ArrayList<>();;



}
