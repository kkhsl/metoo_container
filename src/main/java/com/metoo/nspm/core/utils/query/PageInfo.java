package com.metoo.nspm.core.utils.query;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.github.pagehelper.Page;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("封装分页数据")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class PageInfo<T> {

    @JsonIgnore
    @ApiModelProperty("Mybatis分页对象")
    private Page<T> page;

    @ApiModelProperty("起始条数")
    private Integer startRow;

    @ApiModelProperty("每页条数")
    private Integer pageSize;

    @ApiModelProperty("总页数")
    private Integer pages;

    @ApiModelProperty("当前页码")
    private Integer pageNum;

    @ApiModelProperty("总条数")
    private long total;

    @ApiModelProperty("由第几条结束")
    private Integer endRow;

    @ApiModelProperty("排序")
    private String orderBy;

    @ApiModelProperty("结果集")
    private Object obj;

    @ApiModelProperty("其他结果集")
    private Object other;

    public PageInfo(Page page) {
        this.obj = page.getResult();
        this.startRow = page.getStartRow() + 1;
        this.pageSize = page.getPageSize();
        this.pageNum = page.getPageNum();
        this.total = page.getTotal();
        this.endRow = page.getEndRow();
        this.orderBy = page.getOrderBy();
        this.pages = page.getPages();
    }

    public PageInfo(Page page, Object other) {
        this.obj = page.getResult();
        this.startRow = page.getStartRow() + 1;
        this.pageSize = page.getPageSize();
        this.pageNum = page.getPageNum();
        this.total = page.getTotal();
        this.endRow = page.getEndRow();
        this.orderBy = page.getOrderBy();
        this.pages = page.getPages();
        this.other = other;
    }
}
