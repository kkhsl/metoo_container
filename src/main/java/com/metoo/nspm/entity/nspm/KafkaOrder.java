package com.metoo.nspm.entity.nspm;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

public class KafkaOrder {

    private Long orderId;
    private int count;

    public KafkaOrder(){};

    public Long getOrderId(){
        return this.orderId;
    };

    public int getCount(){
        return this.count;
    }

    public void setOrderId(Long orderId){
        this.orderId = orderId;
    }

    public void setCount(int count){
        this.count = count;
    }


}

