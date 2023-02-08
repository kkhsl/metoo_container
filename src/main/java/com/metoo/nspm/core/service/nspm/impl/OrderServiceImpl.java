package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.OrderMapper;
import com.metoo.nspm.core.service.nspm.IOrderService;
import com.metoo.nspm.entity.nspm.Order;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class OrderServiceImpl implements IOrderService {

    @Autowired
    private OrderMapper orderMapper;

    @Override
    public Order getObjByOrderId(Long orderId) {
        return this.orderMapper.getObjByOrderId(orderId);
    }

    @Override
    public Order getObjByOrderNo(String orderNo) {
        return this.orderMapper.getObjByOrderNo(orderNo);
    }

    @Override
    public int save(Order instance) {
        return this.orderMapper.save(instance);
    }
}
