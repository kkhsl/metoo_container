package com.metoo.nspm.dto.page;

import lombok.Data;

import java.util.List;

@Data
public class PageResponseDto<T> {


    private Integer size;
    private Integer page;
    private Long total;
    private List<T> result;
}
