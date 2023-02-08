package com.metoo.nspm.dto.page;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@ApiModel("分页DTO")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class PageDto<T> {


    private Integer currentPage = 1;// 当前页数

    private Integer pageSize = 15;// 每页条数

    private Integer startRow;// 起始行

    private Integer total;// 总条数

    private Integer count;// 总页数

    private T object;// 查询对象

    private List<T> result;// 查询结果

    private String orderBy = "addTime";

    private String orderType = "DESC";


    public PageDto(Integer currentPage, Integer pageSize) {
       this.currentPage = currentPage;
       this.pageSize = pageSize;
    }

}
