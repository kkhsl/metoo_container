package com.metoo.nspm.core.POJO;

import com.alibaba.fastjson.JSONObject;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

/**
 * <p>
 *     Title: QueryFilter.java
 * </p>
 *
 * <p>
 *     Description: 查询条件管理类；前端：Vue 封装的查询格式
 *     {
 *     "op": {
 *         "order_id": "like",
 *         "user_name": "like",
 *         "goods_name": "like",
 *         "addTime": "range"
 *     },
 *     "filter": {
 *         "addTime": [
 *             "2021-05-16 00:00:00",
 *             "2021-05-20 00:00:00"
 *         ],
 *         "order_id": "3",
 *         "user_name": "3",
 *         "order_cat": 5,
 *         "goods_name": "3"
 *     },
 *     "limit": 10,
 *     "offset": 1
 * }
 * </p>
 *
 * <author>
 *     HKK
 * </author>
 */
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class QueryFilter {

    private JSONObject wildcard;// 通配符 如上：op

    private JSONObject filtrate;// 过滤条件 如上：filter

    private Integer currentPage;// 当前页面 如上：limit

    private Integer pageSize;// 每页展示多少条 如上：offset


}
