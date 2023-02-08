package com.metoo.nspm.core.utils.collections;

import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class CollectionsUtil {

    /**
     * 根据值进行排序
     * @param param 入参集合
     * @param isdesc 指定升序 降序
     * @author HKK
     * @date 2022/08/22
     * @return java.util.Map<java.lang.String, java.lang.Integer>
     */
    public static Map<String, Integer> mapSortByVaslue(Map<String, Integer> param, boolean isdesc){
        Preconditions.checkNotNull(param);
        Set<Map.Entry<String, Integer>> sortedSet = param.entrySet();
        Preconditions.checkNotNull(sortedSet);
        Map<String, Integer> resMap = new LinkedHashMap<>(param.size());
        List<Map.Entry<String, Integer>> sortedList = Lists.newArrayList(sortedSet);
        //实现比较器
        Comparator<Map.Entry<String, Integer>> comparator = new Comparator<Map.Entry<String, Integer>>() {
            @Override
            public int compare(Map.Entry<String, Integer> entry1, Map.Entry<String, Integer> entry2) {
                //也可采用entry2比较entry1进行降序排序
                return entry1.getKey().compareTo(entry2.getKey());
            }
        };

        //降序  output:{dbc=9, cba=5, bca=16, abc=15}
        if (isdesc) {
            Collections.sort(sortedList, Collections.reverseOrder(comparator));
        } else {
            //升序   output:{abc=15, bca=16, cba=5, dbc=9}
            Collections.sort(sortedList, comparator);
        }
        for (Map.Entry<String, Integer> entry : sortedList) {
            String key = entry.getKey();
            Integer value = entry.getValue();
            if (StringUtils.isAnyBlank(key, String.valueOf(value))) {
                continue;
            }
            resMap.put(key, value);
        }
        return resMap;
    }

}
