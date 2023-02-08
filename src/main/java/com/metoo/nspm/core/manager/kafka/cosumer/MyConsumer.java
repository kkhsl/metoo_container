package com.metoo.nspm.core.manager.kafka.cosumer;
/*
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.data.redis.connection.ReactiveStreamCommands;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.annotation.PartitionOffset;
import org.springframework.kafka.annotation.TopicPartition;
import org.springframework.kafka.support.Acknowledgment;*/
import org.springframework.stereotype.Component;

@Component
public class MyConsumer {

    /**
     * 设置为手动提交时 ack才生效
     * @param record
     * @param ack
     */
//    @KafkaListener(topics = "my-replicated-topic", groupId = "MyGroup1")
//    public void listenerGroup(ConsumerRecord<String, String> record, Acknowledgment ack){
//        String value = record.value();
//        System.out.println(value);
//        System.out.println(record);
//        // 手动提交offset
//        ack.acknowledge();// 设置了手动提交，但不执行该方法执行提交，以上方法会被重复消费
//    }

//    @KafkaListener(groupId = "testGroup", topicPartitions = {
//            @TopicPartition(topic = "topic1", partitions = {"0","1"}),
//            @TopicPartition(topic = "topic2", partitions = "0",
//            partitionOffsets = @PartitionOffset(partition = "1", initialOffset = "100"))
//    })
//    public void  listenGroupPro(ConsumerRecord<String, String> record, Acknowledgment ack){
//        String value = record.value();
//        System.out.println(value);
//        System.out.println(record);
//        // 手动提交offset
//        ack.acknowledge();// 设置了手动提交，但不执行该方法执行提交，以上方法会被重复消费
//    }

}
