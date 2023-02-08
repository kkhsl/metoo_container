package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.Order;

public interface IOrderService {

    Order getObjByOrderId(Long orderId);

    Order getObjByOrderNo(String orderNo);

    int save(Order instance);
}
